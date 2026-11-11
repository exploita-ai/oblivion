import { randomUUID } from "node:crypto"
import { once } from "node:events"
import { createConnection, type Socket } from "node:net"
import { z } from "zod"

const frameLimit = 24 * 1024
const capabilities = z.object({
  version: z.literal(1), kind: z.literal("capabilities"),
  operations: z.array(z.enum(["safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"])).max(5),
  limit: z.literal(frameLimit),
}).strict()
const response = z.discriminatedUnion("ok", [
  z.object({ version: z.literal(1), request_id: z.string().regex(/^[a-f0-9]{32}$/), ok: z.literal(true), result: z.unknown() }).strict(),
  z.object({ version: z.literal(1), request_id: z.string().regex(/^[a-f0-9]{32}$/), ok: z.literal(false), error: z.string().regex(/^[a-z][a-z0-9_]{0,95}$/) }).strict(),
])
const identifier = z.string().regex(/^[a-f0-9]{32}$/)
const nativeAgent = z.enum(["codex", "claude", "opencode2"])
const task = z.string().refine((value) => value.trim().length > 0 && Buffer.byteLength(value) <= 16384 && !value.includes("\0"), "Enter a nonempty task of at most 16384 UTF-8 bytes without NUL.")
const chatID = z.string().min(1).refine((value) => Buffer.byteLength(value) <= 256 && !/[\x00-\x1f\x7f-\x9f]/u.test(value), "Use a native chat ID of at most 256 bytes without control characters.")
export const childDelivery = z.object({
  phase: z.enum(["queued", "preparing", "needs-auth", "submitted", "finished", "unavailable"]),
  job: z.lazy(() => jobInfo).nullable(),
  reason: z.enum(["needs-auth", "startup-unavailable", "cleanup-required"]).nullable(),
}).strict().refine((value) => {
  if (value.phase === "submitted") return value.job !== null && value.reason === null
  if (value.phase === "finished") return value.job !== null && ["completed", "failed", "cancelled"].includes(value.job.state) && value.reason === null
  if (value.phase === "needs-auth") return value.job === null && value.reason === "needs-auth"
  if (value.phase === "unavailable") return value.job === null && value.reason !== null
  return value.job === null && value.reason === null
}, "Use observed delivery facts; queued/preparing never mean the task completed.")
export const childInfo = z.object({
  id: identifier, parent: identifier, created_by_agent: z.literal(true),
  agent: nativeAgent, creator_chat_id: chatID.nullable(),
  request_id: identifier, ephemeral: z.boolean(), mib: z.number().int().positive(),
  state: z.enum(["awaiting-start", "failed", "recovery-required"]),
  delivery: childDelivery.nullable(),
}).strict()
export const safeStatus = z.object({
  safe_id: identifier, mode: z.string().min(1).max(32), children: z.array(childInfo).max(16),
  next_offset: z.number().int().min(0).max(32).nullable(),
  limits: z.object({ direct_children: z.literal(8), descendants: z.literal(32), depth: z.literal(4), records: z.literal(128) }).strict(),
  closing: z.boolean(),
}).strict()
export const createInput = z.object({
  agent: nativeAgent.describe("Official agent requested for the separate child Safe. Only this agent's supported credential can be delegated."),
  task: task.describe("Task sealed into the child. The controller schedules one background start after creation; observe delivery and safe_status."),
  creator_chat_id: chatID.optional().describe("Current native agent chat ID, when known. Caller-reported metadata, not an authenticated identity. Do not invent an ID."),
}).strict().refine((value) => requestBody("0".repeat(32), { operation: "safe-create", ...value }).length <= frameLimit, "The encoded task exceeds the local bridge's 24 KiB frame limit. Shorten the task.")
export const jobInfo = z.object({
  job_id: identifier, request_id: identifier, agent: nativeAgent,
  state: z.enum(["queued", "running", "completed", "failed", "cancelled"]),
  native_chat_id: chatID.nullable(),
  reason: z.enum(["needs-auth", "needs-input", "timeout", "output-limit", "interrupted", "agent-exit", "startup-failed", "cleanup-required"]).nullable(),
}).strict()
export const chatCreateInput = z.object({
  agent: nativeAgent.describe("Official agent to run in this Safe using its existing login and permissions."),
  task: task.describe("Task for a new managed conversation. Files and output remain inside the current Safe."),
  request_id: identifier.optional().describe("Idempotency key from an earlier explicit request, or omit to generate one. An uncertain result must be looked up with chat_status before any retry."),
}).strict().refine((value) => requestBody("0".repeat(32), { operation: "chat-create", ...value, request_id: value.request_id ?? "0".repeat(32) }).length <= frameLimit, "The encoded task exceeds the local bridge's 24 KiB frame limit. Shorten the task.")
export const chatStatusInput = z.object({
  job_id: identifier.optional().describe("Known job ID. Supply this OR request_id, never both."),
  request_id: identifier.optional().describe("Known creation request ID, including an unconfirmed creation. Supply this OR job_id, never both."),
}).strict().refine((value) => (value.job_id !== undefined) !== (value.request_id !== undefined), "Supply exactly one of job_id or request_id.")
  .meta({ oneOf: [{ required: ["job_id"] }, { required: ["request_id"] }] })
export const chatCancelInput = z.object({ job_id: identifier.describe("Known job ID in this Safe. Find it with chat_status first if creation was unconfirmed.") }).strict()
type Call = { operation: "safe-status"; offset: number } | ({ operation: "safe-create" } & z.infer<typeof createInput>)
  | { operation: "chat-create"; agent: z.infer<typeof nativeAgent>; task: string; request_id: string }
  | ({ operation: "chat-status" } & z.infer<typeof chatStatusInput>)
  | ({ operation: "chat-cancel" } & z.infer<typeof chatCancelInput>)
type Reply = { request_id: string; result: unknown } | { request_id: string; error: string }

export type SafeTools = {
  operations: z.infer<typeof capabilities>["operations"]
  call: (input: Call, signal: AbortSignal) => Promise<Reply>
}

export async function discoverSafeTools(socket = "/run/oblivion-safe-tools.sock"): Promise<SafeTools | undefined> {
  const signal = AbortSignal.timeout(1500)
  let channel: Socket | undefined
  try {
    channel = await connect(socket, signal)
    const available = capabilities.parse(await readFrame(channel, signal))
    return { operations: available.operations, call: (input, signal) => call(socket, input, signal) }
  } catch {
    return undefined
  } finally { channel?.destroy() }
}

async function call(socket: string, input: Call, signal: AbortSignal): Promise<Reply> {
  const request_id = randomUUID().replaceAll("-", "")
  let channel: Socket | undefined
  try {
    channel = await connect(socket, signal)
    const available = capabilities.parse(await readFrame(channel, signal))
    if (!available.operations.some((operation) => operation === input.operation.replaceAll("-", "_"))) throw new Error("capability_unavailable")
    const body = requestBody(request_id, input)
    if (body.length > frameLimit) throw new Error("request_too_large")
    const frame = Buffer.allocUnsafe(4 + body.length)
    frame.writeUInt32BE(body.length)
    body.copy(frame, 4)
    // Subscribe before writing: a local peer can reply in the same event loop.
    const pending = readFrame(channel, signal)
    channel.write(frame)
    const reply = response.parse(await pending)
    if (reply.request_id !== request_id) throw new Error("request_mismatch")
    if (!reply.ok) return { request_id, error: reply.error === "safe_tool_outcome_unknown" && (input.operation === "safe-create" || input.operation === "chat-create")
      ? uncertain(input, request_id)
      : `The Safe controller rejected the request (${reply.error}).` }
    return { request_id, result: reply.result }
  } catch {
    return { request_id, error: uncertain(input, request_id) }
  } finally { channel?.destroy() }
}

function requestBody(request_id: string, call: unknown) {
  return Buffer.from(JSON.stringify({ version: 1, request_id, call }))
}

function uncertain(input: Call, request_id: string) {
  if (input.operation === "safe-create") return `Safe creation could not be confirmed (request ${request_id}). Check safe_status for this request ID before taking any further action. Do not retry creation automatically.`
  if (input.operation === "chat-create") return `Chat creation could not be confirmed (request ${input.request_id}). Query chat_status with this request_id before taking any further action. Do not retry creation automatically.`
  if (input.operation === "chat-cancel") return `Cancellation could not be confirmed for job ${input.job_id}. Query chat_status with this job_id before continuing.`
  return "Local tool status is unavailable. Check that this Safe is still open before continuing."
}

async function connect(path: string, signal: AbortSignal) {
  const channel = createConnection({ path })
  // A bounded call owns socket failures; no raw error reaches stderr or MCP.
  channel.on("error", () => {})
  try { await once(channel, "connect", { signal }); return channel }
  catch (error) { channel.destroy(); throw error }
}

function readFrame(channel: Socket, signal: AbortSignal): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0)
    const cleanup = () => {
      channel.off("data", data); channel.off("error", failed); channel.off("close", failed)
      signal.removeEventListener("abort", failed)
    }
    const failed = () => { cleanup(); reject(new Error("safe_tools_unavailable")) }
    const data = (chunk: Buffer) => {
      if (buffer.length + chunk.length > frameLimit + 4) { failed(); return }
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length < 4) return
      const size = buffer.readUInt32BE()
      if (!size || size > frameLimit || buffer.length > size + 4) { failed(); return }
      if (buffer.length < size + 4) return
      cleanup()
      try { resolve(JSON.parse(buffer.subarray(4).toString("utf8")) as unknown) }
      catch { reject(new Error("invalid_safe_tools_response")) }
    }
    if (signal.aborted || channel.destroyed) { failed(); return }
    channel.on("data", data); channel.once("error", failed); channel.once("close", failed)
    signal.addEventListener("abort", failed, { once: true })
  })
}
