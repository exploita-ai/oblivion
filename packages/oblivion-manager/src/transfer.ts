import { createConnection, type Socket } from "node:net"
import { once } from "node:events"
import { z } from "zod"
import { ControlError } from "./control"

const name = z.string().min(1).max(255).refine((value) => !/[\/\\\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(value) && value !== "." && value !== "..")
export const relative = z.string().max(4096).refine((value) => value.split("/").length <= 32 && value.split("/").every((part) => name.safeParse(part).success))
export const pageSchema = z.object({
  path: z.union([z.literal(""), relative]),
  entries: z.array(z.object({ name, directory: z.boolean(), bytes: z.number().int().nonnegative().safe() })).max(100),
  next: name.nullable(), skipped: z.number().int().nonnegative(),
})
export type Page = z.infer<typeof pageSchema>
export const devicesSchema = z.object({
  configured: z.boolean(), export_configured: z.boolean(), active: z.boolean(),
  sources: z.array(z.object({ id: z.string().regex(/^\d+:\d+$/), name: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/), bytes: z.number().int().positive().safe(), kind: z.enum(["usb", "virtual"]).default("usb"), read_only: z.boolean().default(false) })),
})
const id = z.string().regex(/^[a-f0-9]{32}$/)
export const startedSchema = z.object({ id })
const digest = z.string().regex(/^[a-f0-9]{64}$/)
const entry = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("directory"), path: relative }),
  z.object({ kind: z.literal("file"), path: relative, size: z.number().int().nonnegative().safe(), sha256: digest }),
])
export const receiptSchema = z.object({ id, manifest_sha256: digest, entries: z.number().int().positive().max(1024), bytes: z.number().int().nonnegative().max(268435456) })
export const recoverySchema = z.discriminatedUnion("result", [
  z.object({ result: z.literal("inventory"), records: z.array(z.object({ id, state: z.enum(["private", "available", "published", "missing"]), receipt: receiptSchema.nullable() })).max(64), next: id.nullable() }),
  z.object({ result: z.literal("discarded"), id }),
])
export type Recovery = z.infer<typeof recoverySchema>
export type Offer = { entries: z.infer<typeof entry>[]; bytes: number; sha256: string }
export type Transfer = {
  browse: (path: string, after?: string) => Promise<Page>
  offer: (paths: string[]) => Promise<Offer>
  approve: (offer: Offer) => Promise<z.infer<typeof receiptSchema>>
  recover: (request: { operation: "list"; after: string | null } | { operation: "discard"; id: string }) => Promise<Recovery>
  close: () => void
}

const authoritySchema = z.object({
  entries: z.number().int().positive().max(1024),
  bytes: z.number().int().positive().max(1024 ** 4),
  budgetMs: z.number().int().positive().max(3_600_000),
})

// The existing Rust relay owns authorization, manifest validation, hashing and
// publication. This client sees metadata and receipts, never document bytes.
export async function connectTransfer(id: string, path = "/run/oblivion-transfer-host/control.sock", limits = { entries: 1024, bytes: 268435456, budgetMs: 300_000 }): Promise<Transfer> {
  const authority = authoritySchema.parse(limits)
  const receipt = receiptSchema.extend({ entries: z.number().int().positive().max(authority.entries), bytes: z.number().int().nonnegative().max(authority.bytes) })
  const socket = createConnection({ path })
  await once(socket, "connect")
  socket.setTimeout(authority.budgetMs, () => socket.destroy(new ControlError("transfer_expired")))
  const reader = new Reader(socket)
  const send = (value: object) => {
    const body = Buffer.from(JSON.stringify(value))
    if (body.length > 65536) throw new ControlError("transfer_request_too_large")
    const frame = Buffer.alloc(4 + body.length)
    frame.writeUInt32BE(body.length); frame.set(body, 4)
    socket.write(frame)
  }
  return {
    close: () => socket.destroy(),
    async browse(path, after) {
      send({ browse: { path, after: after ?? null, limit: 100 } })
      const page = pageSchema.parse(await reader.json(65536))
      if (page.path !== path || (page.next && after && page.next <= after)) throw new ControlError("invalid_directory_page")
      return page
    },
    async offer(paths) {
      send({ id, paths: paths.map((path) => relative.parse(path)), limits: { entries: authority.entries, bytes: authority.bytes } })
      if ((await reader.read(8)).toString("ascii") !== "OBLVCP01") throw new ControlError("invalid_manifest")
      const size = (await reader.read(4)).readUInt32BE()
      if (!size || size > 1048576) throw new ControlError("invalid_manifest")
      const encoded = await reader.read(size)
      const entries = z.array(entry).min(1).max(authority.entries).parse(JSON.parse(encoded.toString("utf8")))
      const bytes = entries.reduce((sum, entry) => sum + (entry.kind === "file" ? entry.size : 0), 0)
      if (bytes > authority.bytes) throw new ControlError("invalid_manifest")
      return { entries, bytes, sha256: new Bun.CryptoHasher("sha256").update(encoded).digest("hex") }
    },
    async approve(offer) {
      send({ id, manifest_sha256: offer.sha256 })
      const result = receipt.parse(await reader.json(1024))
      if (result.id !== id || result.manifest_sha256 !== offer.sha256 || result.entries !== offer.entries.length || result.bytes !== offer.bytes) throw new ControlError("invalid_receipt")
      return result
    },
    async recover(request) { send(request); return recoverySchema.parse(await reader.json(65536)) },
  }
}

class Reader {
  private buffered = Buffer.alloc(0)
  private chunks: AsyncIterableIterator<Buffer>
  constructor(socket: Socket) { this.chunks = socket[Symbol.asyncIterator]() }
  async read(size: number) {
    while (this.buffered.length < size) {
      const chunk = await this.chunks.next()
      if (chunk.done) throw new ControlError("transfer_disconnected")
      this.buffered = Buffer.concat([this.buffered, chunk.value])
    }
    const result = this.buffered.subarray(0, size)
    this.buffered = this.buffered.subarray(size)
    return result
  }
  async json(limit: number): Promise<unknown> {
    const size = (await this.read(4)).readUInt32BE()
    if (!size || size > limit) throw new ControlError("invalid_transfer_response")
    return JSON.parse((await this.read(size)).toString("utf8"))
  }
}
