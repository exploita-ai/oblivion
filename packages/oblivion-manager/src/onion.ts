import { generateKeyPairSync } from "node:crypto"
import { z } from "zod"
import { ControlError, type Request } from "./control"
import { receiptSchema } from "./transfer"

export const onionCopySocket = "/run/oblivion-onion-host/copy.sock"
export const onionStatusSchema = z.object({
  configured: z.boolean(), active: z.boolean(), id: z.string().regex(/^[a-f0-9]{32}$/).nullable(),
  tor_progress: z.number().int().min(0).max(100).nullable(), tor_ready: z.boolean(),
  age_ms: z.number().int().nonnegative().safe(),
  phase: z.enum(["closed", "connecting", "ready", "starting", "receiving", "freezing", "review", "preparing-import", "copying", "imported", "preparing-share", "staging", "staged", "sharing"]),
  progress: z.object({ files: z.number().int().min(0).max(1024), bytes: z.number().int().min(0).max(1024 ** 4), transferred_bytes: z.number().int().min(0).max(1024 ** 4), rejected: z.number().int().nonnegative().safe() }).nullable(),
  receipt: receiptSchema.nullable(),
}).strict().transform((value) => ({ ...value,
  tor_ready: onionVerified(value),
  tor_progress: value.age_ms <= 10_000 ? value.tor_progress : null,
}))
export type OnionStatus = z.infer<typeof onionStatusSchema>
type StatusCommand = { action: "prepare-backup"; id: string; password: string; ttl_seconds: number } | { action: "prepare"; ttl_seconds: number } | { action: "receive" | "share"; client_auth: string } | { action: "status" | "freeze" | "import" | "stage" | "cancel" }

export function onionVerified(value: { tor_ready: boolean; tor_progress: number | null; age_ms: number }, elapsed = 0) {
  return value.tor_ready && value.tor_progress === 100 && value.age_ms + elapsed <= 10_000
}

export async function onionStatus(request: (value: Request) => Promise<string>, command: StatusCommand) {
  const payload = new TextEncoder().encode(JSON.stringify(command))
  try { return onionStatusSchema.parse(JSON.parse(await request({ operation: "onion", payload, timeoutMs: command.action === "prepare-backup" ? 360_000 : undefined }))) }
  finally { payload.fill(0) }
}

export async function onionAccess(request: (value: Request) => Promise<string>) {
  return z.object({ url: z.string().regex(/^http:\/\/[a-z2-7]{56}\.onion\/$/) }).strict().parse(JSON.parse(await request({ operation: "onion", payload: new TextEncoder().encode('{"action":"access"}') }))).url
}

// Node/Bun owns X25519 key generation. Only raw key encoding is done here;
// no private key goes to the controller, guest, argv, environment or a file.
export function createOnionRecipient() {
  const pair = generateKeyPairSync("x25519")
  const publicBytes = Buffer.from(pair.publicKey.export({ format: "jwk" }).x ?? "", "base64url")
  const privateBytes = Buffer.from(pair.privateKey.export({ format: "jwk" }).d ?? "", "base64url")
  if (publicBytes.length !== 32 || privateBytes.length !== 32) throw new ControlError("onion_key_generation_failed")
  let disposed = false
  return {
    publicKey: base32(publicBytes),
    reveal() { if (disposed) throw new ControlError("onion_closed"); return base32(privateBytes) },
    dispose() { disposed = true; privateBytes.fill(0) },
  }
}

export function base32(bytes: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let value = 0
  let bits = 0
  let result = ""
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8
    while (bits >= 5) { bits -= 5; result += alphabet[(value >>> bits) & 31] }
    value &= (1 << bits) - 1
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31]
  return result
}
