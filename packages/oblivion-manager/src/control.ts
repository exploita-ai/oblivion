import { createConnection } from "node:net"
import { z } from "zod"

const response = z.object({
  ok: z.boolean(),
  output: z.string(),
  error: z.string().regex(/^[a-z_]{1,80}$/).nullable(),
})

export type Operation =
  | "status"
  | "debug"
  | "claim-intro"
  | "settings-catalog"
  | "open-documents"
  | "open-documents-ephemeral"
  | "start-chat"
  | "browse"
  | "prepare-usb"
  | "unlock"
  | "unlock-ephemeral"
  | "create"
  | "rename-session"
  | "open"
  | "open-ephemeral"
  | "close"
  | "force-close"
  | "lock"
  | "api-keys"
  | "egress"
  | "network-policy"
  | "save-network"
  | "settings"
  | "network-menu"
  | "connections"
  | "discard-general-pending"
  | "discard-session-pending"
  | "transfers"

export type Request = {
  operation: Operation
  session?: string
  payload?: Uint8Array
}

export class ControlError extends Error {
  constructor(readonly code: string) {
    super(code)
  }
}

// The UI can only reach the existing authenticated Unix socket. Credentials
// travel in the framed body, never in arguments, environment or diagnostics.
export function request(input: Request, path = "/run/oblivion-control.sock"): Promise<string> {
  const limit = ["api-keys", "egress", "network-policy", "transfers", "prepare-usb", "settings", "browse", "connections"].includes(
    input.operation,
  )
    ? 4096
    : 1024
  if ((input.payload?.byteLength ?? 0) > limit) return Promise.reject(new ControlError("request_too_large"))
  const header = Buffer.from(
    JSON.stringify({ operation: input.operation, session: input.session ?? null, secret_len: input.payload?.byteLength ?? 0 }),
  )
  const frame = Buffer.alloc(4 + header.length + (input.payload?.byteLength ?? 0))
  frame.writeUInt32BE(header.length)
  frame.set(header, 4)
  if (input.payload) frame.set(input.payload, 4 + header.length)
  return new Promise((resolve, reject) => {
    const socket = createConnection({ path })
    const chunks: Buffer[] = []
    let size = 0
    socket.setTimeout(120_000)
    socket.once("connect", () => socket.end(frame, () => frame.fill(0)))
    socket.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size > 1024 * 1024) {
        socket.destroy(new ControlError("response_too_large"))
        return
      }
      chunks.push(chunk)
    })
    socket.once("timeout", () => socket.destroy(new ControlError("controller_timeout")))
    socket.once("error", (error) => reject(error instanceof ControlError ? error : new ControlError("controller_unavailable")))
    socket.once("close", () => frame.fill(0))
    socket.once("end", () => {
      const decoded = z.string().transform((value, context) => {
        try {
          return JSON.parse(value) as unknown
        } catch {
          context.addIssue({ code: "custom", message: "invalid_controller_response" })
          return z.NEVER
        }
      }).pipe(response).safeParse(Buffer.concat(chunks).toString("utf8"))
      chunks.forEach((chunk) => chunk.fill(0))
      if (!decoded.success) {
        reject(new ControlError("invalid_controller_response"))
        return
      }
      if (!decoded.data.ok) {
        reject(new ControlError(decoded.data.error ?? "operation_failed"))
        return
      }
      resolve(decoded.data.output)
    })
  })
}
