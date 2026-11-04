import { z } from "zod"
import { fileReceipt } from "./native-file-transfers"

export const fileIdentity = z.object({ operation_id: z.string().regex(/^[a-f0-9]{32}$/), safe_id: z.string().regex(/^[a-f0-9]{32}$/), opening: z.string().regex(/^[a-f0-9]{32}$/) }).strict()
const bytes = z.number().int().nonnegative().max(16 * 1024 ** 3)
const count = z.number().int().nonnegative().max(16384)
const summary = z.object({ manifest_sha256: z.string().regex(/^[a-f0-9]{64}$/), entries: count.min(1), files: count, directories: count, bytes }).strict()
  .refine((value) => value.files + value.directories >= 1 && value.files + value.directories <= value.entries && value.entries - value.files - value.directories <= 31)
const review = z.object({ event: z.literal("review"), identity: fileIdentity, direction: z.enum(["import", "export"]), name: z.string().refine((value) => !!value && Buffer.byteLength(value) <= 255 && !/[\p{Cc}\p{Bidi_Control}\p{Zl}\p{Zp}/\\]/u.test(value) && value !== "." && value !== ".."), summary }).strict()
  .refine((value) => value.direction !== "import" || value.summary.files + value.summary.directories === value.summary.entries)
const progress = z.object({ event: z.literal("progress"), identity: fileIdentity, phase: z.enum(["copying", "finalizing"]), bytes, total_bytes: bytes }).strict()
  .refine((value) => value.bytes <= value.total_bytes && (value.phase !== "finalizing" || value.bytes === value.total_bytes))
const finished = z.object({ event: z.literal("finished"), identity: fileIdentity, outcome: z.enum(["completed", "interrupted", "cancelled-before-copy"]), receipt: fileReceipt.nullable() }).strict()
  .refine((value) => (value.outcome === "completed") === !!value.receipt && (!value.receipt || value.receipt.id === value.identity.operation_id))
export const fileEvent = z.union([review, progress, finished])
export type FileIdentity = z.infer<typeof fileIdentity>
export type FileEvent = z.infer<typeof fileEvent>
export type FileReview = z.infer<typeof review>
export type FileFinished = z.infer<typeof finished>
export type FileCopyRequest = { args: string[]; identity: FileIdentity; direction: "import" | "export"; name: string }
export type RunningFileCopy = { approve: (digest: string) => Promise<void>; cancel: () => Promise<void>; done: Promise<{ code: number; finished?: FileFinished }> }
export type NativeFileClient = { start: (request: FileCopyRequest, event: (value: FileEvent) => void) => RunningFileCopy; close: () => Promise<void> }
