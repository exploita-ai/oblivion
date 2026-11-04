import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { createServer, type Socket } from "node:net"
import os from "node:os"
import path from "node:path"
import { Client } from "@modelcontextprotocol/client"
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio"
import { discoverSafeTools, jobInfo } from "../src/safe-tools"

function frame(value: unknown) {
  const body = Buffer.from(JSON.stringify(value))
  const output = Buffer.alloc(4 + body.length)
  output.writeUInt32BE(body.length)
  body.copy(output, 4)
  return output
}

test("real Unix capability discovery gates tools and a lost creation reply is never retried", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-safe-tools-"))
  const socket = path.join(directory, "bridge.sock")
  const calls: { version: number; request_id: string; call: { operation: string; offset?: number; agent?: string; task?: string; request_id?: string; job_id?: string } }[] = []
  const jobs = new Map<string, ReturnType<typeof jobInfo.parse>>()
  const connections = new Set<Socket>()
  const parent = "a".repeat(32)
  const child = "b".repeat(32)
  const relay = createServer((peer) => {
    connections.add(peer)
    peer.on("error", () => {})
    peer.on("close", () => connections.delete(peer))
    peer.write(frame({ version: 1, kind: "capabilities", operations: ["safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"], limit: 24576 }))
    let buffer = Buffer.alloc(0)
    peer.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length < 4 || buffer.length < buffer.readUInt32BE() + 4) return
      const request = JSON.parse(buffer.subarray(4).toString()) as typeof calls[number]
      calls.push(request)
      if (request.call.operation.startsWith("chat-")) {
        const known = request.call.request_id ? jobs.get(request.call.request_id) : Array.from(jobs.values()).find((job) => job.job_id === request.call.job_id)
        const job = request.call.operation === "chat-create" ? jobInfo.parse({ job_id: "c".repeat(31) + jobs.size.toString(16), request_id: request.call.request_id, agent: request.call.agent, state: "queued", native_chat_id: null, reason: null }) : known!
        jobs.set(job.request_id, job)
        if (request.call.task === "chat unknown outcome") { peer.end(frame({ version: 1, request_id: request.request_id, ok: false, error: "safe_tool_outcome_unknown" })); return }
        if (request.call.operation === "chat-cancel") job.state = "cancelled"
        peer.end(frame({ version: 1, request_id: request.request_id, ok: true, result: job }))
        return
      }
      if (request.call.task === "drop reply") { peer.destroy(); return }
      if (request.call.task === "unknown outcome") { peer.end(frame({ version: 1, request_id: request.request_id, ok: false, error: "safe_tool_outcome_unknown" })); return }
      const info = { id: child, parent, created_by_agent: true, agent: "claude", creator_chat_id: null, request_id: request.request_id, ephemeral: false, mib: 2048, state: "awaiting-start" }
      peer.end(frame({ version: 1, request_id: request.request_id, ok: true, result: request.call.operation === "safe-status"
        ? { safe_id: parent, mode: "agent", children: [], next_offset: null, limits: { direct_children: 8, descendants: 32, depth: 4, records: 128 }, closing: false }
        : info }))
    })
  })
  await new Promise<void>((resolve) => relay.listen(socket, resolve))
  await Bun.write(path.join(directory, "entry.ts"), `
    import { StdioServerTransport } from ${JSON.stringify(Bun.resolveSync("@modelcontextprotocol/server/stdio", import.meta.dir))}
    import { createServer } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/server"))}
    import { discoverSafeTools } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/safe-tools"))}
    const server = createServer(await discoverSafeTools(process.argv[2]))
    await server.connect(new StdioServerTransport(process.stdin, process.stdout))
  `)
  const built = await Bun.build({ entrypoints: [path.join(directory, "entry.ts")], packages: "bundle", target: "node", format: "esm", minify: true, outdir: directory, naming: "entry.mjs" })
  expect(built.success).toBe(true)
  const client = new Client({ name: "safe-tools-contract", version: "1.0.0" })
  const transport = new StdioClientTransport({ command: "node", args: [path.join(directory, "entry.mjs"), socket], stderr: "pipe" })
  const errors: Buffer[] = []
  transport.stderr?.on("data", (chunk: Buffer) => errors.push(chunk))
  try {
    await client.connect(transport)
    const catalog = await client.listTools()
    expect(catalog.tools.map((tool) => tool.name)).toEqual(["tor_rotate", "safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"])
    expect(catalog.tools.find((tool) => tool.name === "chat_status")?.inputSchema.oneOf).toEqual([{ required: ["job_id"] }, { required: ["request_id"] }])
    expect(catalog.tools.find((tool) => tool.name === "safe_create")?.description).toContain("DOES NOT start an agent")
    expect(catalog.tools.find((tool) => tool.name === "safe_status")?.annotations?.readOnlyHint).toBe(true)
    const status = await client.callTool({ name: "safe_status", arguments: {} })
    expect(status.structuredContent).toMatchObject({ safe_id: parent, children: [], closing: false })
    expect(calls[0]?.call).toEqual({ operation: "safe-status", offset: 0 })
    const created = await client.callTool({ name: "safe_create", arguments: { agent: "claude", task: "Review imported source" } })
    expect(created.structuredContent).toMatchObject({ id: child, parent, state: "awaiting-start", agent: "claude" })
    expect(calls[1]?.request_id).toMatch(/^[a-f0-9]{32}$/)
    expect(calls[1]?.call).toEqual({ operation: "safe-create", agent: "claude", task: "Review imported source" })
    const invalid = await client.callTool({ name: "safe_create", arguments: { agent: "claude", task: "Review", parent: child } })
    expect(invalid.isError).toBe(true)
    const oversized = await client.callTool({ name: "safe_create", arguments: { agent: "codex", task: "è".repeat(8193) } })
    expect(oversized.isError).toBe(true)
    const escaped = await client.callTool({ name: "safe_create", arguments: { agent: "codex", task: "Review" + "\n".repeat(15000) } })
    expect(escaped.isError).toBe(true)
    expect(calls).toHaveLength(2)
    const deadline = await client.callTool({ name: "safe_create", arguments: { agent: "codex", task: "unknown outcome" } })
    expect(deadline.isError).toBe(true)
    expect(JSON.stringify(deadline.content)).toContain(calls[2]!.request_id)
    expect(JSON.stringify(deadline.content)).toContain("Do not retry creation automatically")
    const uncertain = await client.callTool({ name: "safe_create", arguments: { agent: "claude", task: "drop reply" } })
    expect(uncertain.isError).toBe(true)
    expect(JSON.stringify(uncertain.content)).toContain(calls[3]!.request_id)
    expect(JSON.stringify(uncertain.content)).toContain("Do not retry creation automatically")
    expect(calls).toHaveLength(4)
    expect(new Set(calls.map((call) => call.request_id)).size).toBe(4)
    const conversation = await client.callTool({ name: "chat_create", arguments: { agent: "opencode2", task: "Inspect the workspace" } })
    const job = jobInfo.parse(conversation.structuredContent)
    expect(job.state).toBe("queued")
    expect(job.agent).toBe("opencode2")
    expect(job.request_id).toMatch(/^[a-f0-9]{32}$/)
    expect(calls[4]?.call).toEqual({ operation: "chat-create", agent: "opencode2", task: "Inspect the workspace", request_id: job.request_id })
    expect(calls[4]?.request_id).not.toBe(job.request_id)
    expect(JSON.stringify(conversation.content)).not.toContain("Inspect the workspace")
    const found = await client.callTool({ name: "chat_status", arguments: { job_id: job.job_id } })
    expect(found.structuredContent).toMatchObject({ job_id: job.job_id, request_id: job.request_id, state: "queued" })
    const both = await client.callTool({ name: "chat_status", arguments: { job_id: job.job_id, request_id: job.request_id } })
    expect(both.isError).toBe(true)
    const neither = await client.callTool({ name: "chat_status", arguments: {} })
    expect(neither.isError).toBe(true)
    expect(calls).toHaveLength(6)
    const request_id = "d".repeat(32)
    const unknown = await client.callTool({ name: "chat_create", arguments: { agent: "codex", task: "chat unknown outcome", request_id } })
    expect(unknown.isError).toBe(true)
    expect(JSON.stringify(unknown.content)).toContain(request_id)
    expect(JSON.stringify(unknown.content)).toContain("Query chat_status with this request_id")
    expect(JSON.stringify(unknown.content)).toContain("Do not retry creation automatically")
    const reconciled = await client.callTool({ name: "chat_status", arguments: { request_id } })
    expect(reconciled.structuredContent).toMatchObject({ request_id, state: "queued" })
    expect(calls.filter((call) => call.call.operation === "chat-create")).toHaveLength(2)
    expect(calls.at(-1)?.call).toEqual({ operation: "chat-status", request_id })
    const cancelled = await client.callTool({ name: "chat_cancel", arguments: { job_id: job.job_id } })
    expect(cancelled.structuredContent).toMatchObject({ job_id: job.job_id, state: "cancelled" })
  } finally {
    await client.close()
    connections.forEach((peer) => peer.destroy())
    await new Promise<void>((resolve) => relay.close(() => resolve()))
    await rm(directory, { recursive: true, force: true })
  }
  expect(Buffer.concat(errors).toString()).toBe("")
})

test.each(["unsupported-version", "oversized-frame", "truncated-frame"])("invalid %s handshake advertises no Safe capabilities", async (kind) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-safe-handshake-"))
  const socket = path.join(directory, "bridge.sock")
  const relay = createServer((peer) => {
    peer.on("error", () => {})
    const data = kind === "unsupported-version" ? frame({ version: 2, kind: "capabilities", operations: ["safe_create"], limit: 24576 }) : Buffer.from([0, 1, 0, 0])
    peer.end(kind === "truncated-frame" ? data.subarray(0, 2) : data)
  })
  await new Promise<void>((resolve) => relay.listen(socket, resolve))
  try { expect(await discoverSafeTools(socket)).toBeUndefined() }
  finally {
    await new Promise<void>((resolve) => relay.close(() => resolve()))
    await rm(directory, { recursive: true, force: true })
  }
})
