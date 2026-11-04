import { McpServer } from "@modelcontextprotocol/server"
import { randomUUID } from "node:crypto"
import { z } from "zod"
import { rotate } from "./rotation"
import { chatCancelInput, chatCreateInput, chatStatusInput, childInfo, createInput, jobInfo, safeStatus, type SafeTools } from "./safe-tools"

export function createServer(safes?: SafeTools) {
  const server = new McpServer({ name: "oblivion-mcp-server", version: "0.1.0" })
  server.registerTool("tor_rotate", {
    title: "Rotate this Safe's Tor exit",
    description: "Rotate Tor circuits for this Safe. Interrupts every active model request, download and TCP connection in its agents and terminals. The gateway blocks application traffic before rotation and keeps it blocked if rotation fails. Use when the user requests rotation or a site refuses a Tor exit. No arguments or direct fallback. Requires Tor. Never retry automatically or rotate repeatedly to retry a rate limit. A different exit does not guarantee access to a site.",
    inputSchema: z.object({}).strict(),
    outputSchema: z.object({ status: z.enum(["rotated", "renewed"]) }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async (_input, context) => {
    const result = await rotate(AbortSignal.any([context.mcpReq.signal, AbortSignal.timeout(160_000)]))
    if ("error" in result) return { isError: true, content: [{ type: "text", text: result.error }] }
    return {
      structuredContent: { status: result.status },
      content: [{ type: "text", text: result.status === "rotated"
        ? "Tor circuits rebuilt and previous exit relays excluded. Isolation was verified and this Safe's traffic reopened. Previous connections were closed."
        : "Fresh Tor circuits were verified and this Safe's traffic reopened. No previous exit was available for comparison." }],
    }
  })
  if (safes?.operations.includes("safe_status")) server.registerTool("safe_status", {
    title: "Inspect this Safe and its children",
    description: "Read this Safe's identity, closing state, child Safe creation records, limits and bounded observed delivery metadata. Only this Safe's controller-scoped children are visible. Results are paginated; pass next_offset to read the next page. Creation state awaiting-start is separate from delivery: queued/preparing do not confirm execution; submitted is admission; inspect the job state for completion. Null delivery means no observation in this controller opening. needs-auth requires native login/user action; do not invent credentials or start anonymously. Use this to reconcile unconfirmed safe_create without replaying creation.",
    inputSchema: z.object({ offset: z.number().int().min(0).max(32).default(0).describe("Page offset from next_offset; omit for the first page.") }).strict(),
    outputSchema: safeStatus,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input, context) => {
    const reply = await safes.call({ operation: "safe-status", offset: input.offset }, AbortSignal.any([context.mcpReq.signal, AbortSignal.timeout(10_000)]))
    if ("error" in reply) return { isError: true, content: [{ type: "text", text: reply.error }] }
    const parsed = safeStatus.safeParse(reply.result)
    if (!parsed.success) return { isError: true, content: [{ type: "text", text: "Safe status could not be validated. Check this Safe in the Oblivion manager." }] }
    return { structuredContent: parsed.data, content: [{ type: "text", text: JSON.stringify(parsed.data) }] }
  })
  if (safes?.operations.includes("safe_create")) server.registerTool("safe_create", {
    title: "Create a closed child Safe",
    description: "Create one separate encrypted child Safe and schedule its requested official agent/task once in the background. A persistent child shares its family's unlock password and has an independent volume. An ephemeral parent creates a RAM-only child discarded on branch or host lock. Only the requested agent's explicitly supported credential is handed over through a sealed private channel; no other provider profiles or files are copied. Missing/unsupported authentication leaves delivery needs-auth and does not start anonymously. created_by_agent is controller-attested; creator_chat_id is caller-reported metadata. queued/preparing are startup observations, submitted is admission, and only the returned job state can confirm completion. Parent closure/idle lock fences the child. The caller cannot choose a parent, password or authority. Respect safe_status limits. Never retry an unconfirmed creation automatically.",
    inputSchema: createInput,
    outputSchema: childInfo,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async (input, context) => {
    const reply = await safes.call({ operation: "safe-create", ...input }, AbortSignal.any([context.mcpReq.signal, AbortSignal.timeout(165_000)]))
    if ("error" in reply) return { isError: true, content: [{ type: "text", text: reply.error }] }
    const parsed = childInfo.safeParse(reply.result)
    if (!parsed.success || parsed.data.request_id !== reply.request_id || parsed.data.state !== "awaiting-start") return {
      isError: true, content: [{ type: "text", text: `Safe creation could not be confirmed (request ${reply.request_id}). Check safe_status before continuing. Do not retry creation automatically.` }],
    }
    return { structuredContent: parsed.data, content: [{ type: "text", text: JSON.stringify(parsed.data) }] }
  })
  if (safes?.operations.includes("chat_create")) server.registerTool("chat_create", {
    title: "Start a managed agent conversation in this Safe",
    description: "Create a new headless conversation using Codex, Claude Code or OpenCode 2 in the current Safe. It shares this Safe's files and existing agent login. It does not create a Safe, copy credentials or bypass authentication and permission prompts. queued means admitted, not running or completed. Check chat_status for progress and a native chat ID when available. Prompts and output remain in files inside this Safe; replies contain metadata only. If creation is unconfirmed, look it up by request_id without rerunning the task. Agent output does not reset automatic-lock timers.",
    inputSchema: chatCreateInput, outputSchema: jobInfo,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, async (input, context) => {
    const request_id = input.request_id ?? randomUUID().replaceAll("-", "")
    const reply = await safes.call({ operation: "chat-create", ...input, request_id }, AbortSignal.any([context.mcpReq.signal, AbortSignal.timeout(165_000)]))
    if ("error" in reply) return { isError: true, content: [{ type: "text", text: reply.error }] }
    const parsed = jobInfo.safeParse(reply.result)
    if (!parsed.success || parsed.data.request_id !== request_id || parsed.data.agent !== input.agent) return {
      isError: true, content: [{ type: "text", text: `Chat creation could not be confirmed (request ${request_id}). Query chat_status with this request_id. Do not retry creation automatically.` }],
    }
    return { structuredContent: parsed.data, content: [{ type: "text", text: JSON.stringify(parsed.data) }] }
  })
  if (safes?.operations.includes("chat_status")) server.registerTool("chat_status", {
    title: "Inspect a managed conversation without starting it",
    description: "Read this Safe's managed job metadata by exactly one known job_id or creation request_id. A request_id lookup reconciles an unconfirmed chat_create without replaying its task. This operation never starts or resumes an agent. It returns no prompts or conversation output. Use the native_chat_id in the agent's own resume interface when available. failed reasons such as needs-auth or needs-input require user action; do not bypass permissions.",
    inputSchema: chatStatusInput, outputSchema: jobInfo,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input, context) => {
    const reply = await safes.call({ operation: "chat-status", ...input }, AbortSignal.any([context.mcpReq.signal, AbortSignal.timeout(10_000)]))
    if ("error" in reply) return { isError: true, content: [{ type: "text", text: reply.error }] }
    const parsed = jobInfo.safeParse(reply.result)
    if (!parsed.success || input.job_id && parsed.data.job_id !== input.job_id || input.request_id && parsed.data.request_id !== input.request_id) return {
      isError: true, content: [{ type: "text", text: "Chat status could not be validated. Check this Safe's managed jobs before continuing." }],
    }
    return { structuredContent: parsed.data, content: [{ type: "text", text: JSON.stringify(parsed.data) }] }
  })
  if (safes?.operations.includes("chat_cancel")) server.registerTool("chat_cancel", {
    title: "Cancel a managed conversation in this Safe",
    description: "Request cancellation of one known managed job in this Safe. It does not close the Safe or other conversations. Cancellation may interrupt writes and tool work. Report cancellation as confirmed only when the returned state is cancelled. running, queued or cleanup-required do not confirm that the process stopped; inspect chat_status before continuing. No task or output content is returned.",
    inputSchema: chatCancelInput, outputSchema: jobInfo,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  }, async (input, context) => {
    const reply = await safes.call({ operation: "chat-cancel", ...input }, AbortSignal.any([context.mcpReq.signal, AbortSignal.timeout(20_000)]))
    if ("error" in reply) return { isError: true, content: [{ type: "text", text: reply.error }] }
    const parsed = jobInfo.safeParse(reply.result)
    if (!parsed.success || parsed.data.job_id !== input.job_id) return {
      isError: true, content: [{ type: "text", text: `Cancellation could not be confirmed for job ${input.job_id}. Query chat_status before continuing.` }],
    }
    return { structuredContent: parsed.data, content: [{ type: "text", text: JSON.stringify(parsed.data) }] }
  })
  return server
}
