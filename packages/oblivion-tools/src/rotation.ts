import { open } from "node:fs/promises"
import { constants } from "node:fs"
import { Agent, request } from "node:http"
import { z } from "zod"

const reply = z.object({
  status: z.enum(["rotated", "renewed", "blocked", "tor_required", "cooldown", "rotation_in_progress", "controller_unavailable", "unauthorized", "rotation_not_allowed"]),
  phase: z.enum(["preparing", "draining", "circuit_build", "previous_exit", "deadline", "isolation", "circuit_status", "tor_information", "tor_reply", "listener_in_use", "verification"]).optional(),
}).strict()

export const unconfirmed = "Tor rotation could not be confirmed. Check this Safe's network status before continuing. Do not retry automatically."
type RotationResult = { status: "rotated" | "renewed" } | { error: string }

export function rotationResult(status: number, body: string): RotationResult {
  const parsed = z.string().transform((text, context) => {
    try { return JSON.parse(text) as unknown }
    catch { context.addIssue({ code: "custom", message: "invalid_rotation_reply" }); return z.NEVER }
  }).pipe(reply).safeParse(body)
  if (!parsed.success) return { error: unconfirmed }
  const result = parsed.data.status
  if (result === "rotated" || result === "renewed") return status === 200 ? { status: result } : { error: unconfirmed }
  const messages = {
    blocked: "Tor rotation failed. This Safe's external traffic remains blocked. Check its network settings or close and reopen the Safe.",
    tor_required: "Tor rotation requires an online Tor route for this Safe. SOCKS5 and Offline mode do not support rotation.",
    cooldown: "Tor rotation is rate limited. Wait at least 30 seconds between attempts. Do not retry in a loop.",
    rotation_in_progress: "A Tor rotation is already in progress for this Safe. Wait for its result.",
    controller_unavailable: unconfirmed,
    unauthorized: "The opening's rotation capability was rejected. Reopen the Safe. Provider API keys cannot authorize this operation.",
    rotation_not_allowed: "Tor rotation is unavailable during this Safe's current operation. Close an active OnionShare transfer before trying again.",
  }
  return { error: messages[result] }
}

export async function rotate(signal: AbortSignal) {
  const token = Buffer.alloc(65)
  try {
    const file = await open("/run/oblivion-network/token", constants.O_RDONLY | constants.O_NOFOLLOW)
    const size = await file.read(token).then((result) => result.bytesRead).finally(() => file.close())
    if (size !== 64 || !/^[a-f0-9]{64}$/.test(token.subarray(0, 64).toString("ascii"))) return { error: "The rotation capability is unavailable for this opening. Open this Safe with Tor first." }
    // The fixed private gateway is reached directly. User proxy variables must
    // never send this local capability to an external proxy or destination.
    const agent = new Agent({ keepAlive: false, proxyEnv: {} })
    try {
      return await new Promise<ReturnType<typeof rotationResult>>((resolve) => {
        const call = request({
          hostname: "10.88.0.1", port: 8114, path: "/tor/rotate", method: "POST", agent,
          headers: { Authorization: `Bearer ${token.subarray(0, 64).toString("ascii")}`, "Content-Length": "0" },
          signal,
        }, (response) => {
          const chunks: Buffer[] = []
          let bytes = 0
          response.on("data", (chunk: Buffer) => {
            bytes += chunk.length
            if (bytes > 1024) { call.destroy(); resolve({ error: unconfirmed }); return }
            chunks.push(chunk)
          })
          response.once("error", () => resolve({ error: unconfirmed }))
          response.once("end", () => resolve(rotationResult(response.statusCode ?? 0, Buffer.concat(chunks).toString("utf8"))))
        })
        call.once("error", () => resolve({ error: unconfirmed }))
        call.end()
      })
    } finally { agent.destroy() }
  } catch {
    return { error: unconfirmed }
  } finally { token.fill(0) }
}
