import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Client } from "@modelcontextprotocol/client"
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio"

test("the Node bundle advertises only tor_rotate and rejects arguments before execution", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-tools-"))
  const result = await Bun.build({
    entrypoints: [path.resolve(import.meta.dir, "../src/index.ts")],
    target: "node", format: "esm", minify: true,
    outdir: directory, naming: "server.mjs",
  })
  expect(result.success).toBe(true)
  const client = new Client({ name: "oblivion-contract-test", version: "1.0.0" })
  const transport = new StdioClientTransport({
    command: "node", args: [path.join(directory, "server.mjs")], stderr: "pipe",
  })
  const errors: Buffer[] = []
  transport.stderr?.on("data", (chunk: Buffer) => errors.push(chunk))
  try {
    await client.connect(transport)
    const tools = await client.listTools()
    expect(tools.tools.map((tool) => tool.name)).toEqual(["tor_rotate"])
    expect(tools.tools[0]?.inputSchema).toMatchObject({ type: "object", additionalProperties: false })
    expect(tools.tools[0]?.annotations).toMatchObject({ destructiveHint: true, readOnlyHint: false })
    const refused = await client.callTool({ name: "tor_rotate", arguments: { url: "https://example.invalid" } })
    expect(refused.isError).toBe(true)
  } finally {
    await client.close()
    await rm(directory, { recursive: true, force: true })
  }
  expect(Buffer.concat(errors).toString()).toBe("")
})
