import { expect, test } from "bun:test"
import { once } from "node:events"
import { mkdtemp, rm } from "node:fs/promises"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { connectTransfer } from "../src/transfer"

test.each([false, true])("only an explicit backup authority accepts a 512 MiB manifest: backup=%s", async (backup) => {
  const directory = await mkdtemp(join(tmpdir(), "oblivion-backup-client-"))
  const path = join(directory, "control.sock")
  const id = "a".repeat(32)
  const bytes = 512 * 1024 ** 2
  const encoded = Buffer.from(JSON.stringify([{ kind: "file", path: "session.oblivion", size: bytes, sha256: "b".repeat(64) }]))
  const digest = new Bun.CryptoHasher("sha256").update(encoded).digest("hex")
  const observed = Promise.withResolvers<void>()
  observed.promise.catch(() => {})
  const frame = (value: object) => {
    const body = Buffer.from(JSON.stringify(value))
    const size = Buffer.alloc(4); size.writeUInt32BE(body.length)
    return Buffer.concat([size, body])
  }
  const server = createServer((socket) => {
    void (async () => {
      let buffered = Buffer.alloc(0)
      let offered = false
      for await (const chunk of socket) {
        buffered = Buffer.concat([buffered, chunk])
        while (buffered.length >= 4 && buffered.length >= 4 + buffered.readUInt32BE()) {
          const size = buffered.readUInt32BE()
          const request = JSON.parse(buffered.subarray(4, 4 + size).toString()) as { id: string; limits: { entries: number; bytes: number }; manifest_sha256: string }
          buffered = buffered.subarray(4 + size)
          if (!offered) {
            expect(request.id).toBe(id)
            expect(request.limits).toEqual(backup ? { entries: 1, bytes } : { entries: 1024, bytes: 268435456 })
            const size = Buffer.alloc(4); size.writeUInt32BE(encoded.length)
            socket.write(Buffer.concat([Buffer.from("OBLVCP01"), size, encoded]))
            offered = true
            if (!backup) observed.resolve()
            continue
          }
          expect(request.manifest_sha256).toBe(digest)
          socket.end(frame({ id, entries: 1, bytes, manifest_sha256: digest }))
          observed.resolve()
        }
      }
    })().catch((error) => { observed.reject(error); socket.destroy() })
  })
  server.listen(path); await once(server, "listening")
  const transfer = await connectTransfer(id, path, backup ? { entries: 1, bytes, budgetMs: 3_600_000 } : undefined)
  try {
    if (!backup) {
      await expect(transfer.offer(["session.oblivion"])).rejects.toThrow("invalid_manifest")
      await observed.promise
      return
    }
    const offer = await transfer.offer(["session.oblivion"])
    expect(offer.bytes).toBe(bytes)
    expect(await transfer.approve(offer)).toMatchObject({ id, bytes, entries: 1, manifest_sha256: digest })
    await observed.promise
  } finally {
    transfer.close()
    server.close(); await once(server, "close")
    await rm(directory, { recursive: true, force: true })
  }
})
