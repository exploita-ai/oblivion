import { createSignal } from "solid-js"
import { z } from "zod"

const id = z.string().regex(/^[a-f0-9]{32}$/)
export const fileReceipt = z.object({ id, manifest_sha256: z.string().regex(/^[a-f0-9]{64}$/), entries: z.number().int().min(1).max(16384), bytes: z.number().int().nonnegative().max(16 * 1024 ** 3) }).strict()
export const fileOutcome = z.object({
  operation_id: id, safe_id: id, opening: id, source_opening: id.nullable(),
  state: z.enum(["unknown", "incomplete", "ready", "published", "discarded"]),
  receipt: fileReceipt.nullable(),
  can_recover: z.boolean(), can_discard: z.boolean(),
}).strict().refine((value) => {
  if (value.receipt && value.receipt.id !== value.operation_id) return false
  if (value.state === "unknown") return !value.source_opening && !value.receipt && !value.can_recover && !value.can_discard
  if (value.state === "incomplete") return !!value.source_opening && !value.receipt && !value.can_recover
  if (value.state === "ready") return !!value.source_opening && !!value.receipt && value.can_recover
  if (value.state === "published") return !!value.source_opening && !!value.receipt && !value.can_recover && !value.can_discard
  return !!value.source_opening && !value.receipt && !value.can_recover && !value.can_discard
})

export const fileInventory = z.object({
  safe_id: id, opening: id, direction: z.enum(["import", "export"]),
  entries: z.array(z.object({ operation_id: id, source_opening: id,
    name: z.string().refine((value) => !!value && Buffer.byteLength(value) <= 255 && !/[\p{Cc}\p{Bidi_Control}\p{Zl}\p{Zp}/\\\uD800-\uDFFF]/u.test(value) && value !== "." && value !== ".."),
  }).strict()).max(8),
  next_cursor: id.nullable(), skipped: z.number().int().nonnegative().max(16384),
}).strict().refine((value) => value.entries.every((entry, index) => index === 0 || value.entries[index - 1]!.operation_id < entry.operation_id)
  && (!value.next_cursor || (!value.entries.length || value.next_cursor >= value.entries.at(-1)!.operation_id)
    && (value.skipped > 0 || value.next_cursor === value.entries.at(-1)?.operation_id)))

// Paths stay only in this manager's memory, never in a desktop profile or log.
export type FileReference = { id: string; safe: string; opening: string; kind: "import" | "export"; name: string; destination: string; usbExport?: { receipt?: z.infer<typeof fileReceipt> } }
export type FileTransfer = FileReference & { sources: string[] }
export type FileOutcome = z.infer<typeof fileOutcome>
export type FileInventory = z.infer<typeof fileInventory>

export function createFileTransfers() {
  const [entries, setEntries] = createSignal<FileTransfer[]>([])
  return {
    entries,
    remember(entry: FileTransfer) { setEntries((before) => [entry, ...before.filter((value) => value.id !== entry.id || value.safe !== entry.safe)].slice(0, 32)) },
    forget(id: string, safe: string) { setEntries((before) => before.filter((entry) => entry.id !== id || entry.safe !== safe)) },
    clear() { setEntries([]) },
  }
}
