import { createSignal } from "solid-js"
import { z } from "zod"

const id = z.string().regex(/^[a-f0-9]{32}$/)
export const fileOutcome = z.object({
  operation_id: id, safe_id: id, opening: id, source_opening: id.nullable(),
  state: z.enum(["unknown", "incomplete", "ready", "published", "discarded"]),
  receipt: z.object({ id, manifest_sha256: z.string().regex(/^[a-f0-9]{64}$/), entries: z.number().int().min(1).max(16384), bytes: z.number().int().nonnegative().max(16 * 1024 ** 3) }).strict().nullable(),
  can_recover: z.boolean(), can_discard: z.boolean(),
}).strict().refine((value) => {
  if (value.receipt && value.receipt.id !== value.operation_id) return false
  if (value.state === "unknown") return !value.source_opening && !value.receipt && !value.can_recover && !value.can_discard
  if (value.state === "incomplete") return !!value.source_opening && !value.receipt && !value.can_recover
  if (value.state === "ready") return !!value.source_opening && !!value.receipt && value.can_recover
  if (value.state === "published") return !!value.source_opening && !!value.receipt && !value.can_recover && !value.can_discard
  return !!value.source_opening && !value.receipt && !value.can_recover && !value.can_discard
})

// Paths stay only in this manager's memory, never in a desktop profile or log.
export type FileTransfer = { id: string; safe: string; opening: string; kind: "import" | "export"; source: string; destination: string }
export type FileOutcome = z.infer<typeof fileOutcome>

export function createFileTransfers() {
  const [entries, setEntries] = createSignal<FileTransfer[]>([])
  return {
    entries,
    remember(entry: FileTransfer) { setEntries((before) => [entry, ...before.filter((value) => value.id !== entry.id || value.safe !== entry.safe)].slice(0, 32)) },
    clear() { setEntries([]) },
  }
}
