import { z } from "zod"
import type { Field } from "./form"
import { capacity } from "./state"

export const mib = 1024 ** 2
export const reserve = 64 * mib
export const storageUsage = z.object({
  result: z.literal("storage"),
  usage: z.object({ capacity: z.number().int().positive().max(1024 ** 4), used: z.number().int().nonnegative(), available: z.number().int().nonnegative() })
    .refine((value) => value.used + value.available <= value.capacity),
})

export function sizeField(value: number, available: number, current = 0): Field {
  return {
    id: "mib", label: "Capacity (MiB)", value: String(value),
    description: `512 MiB is the small default. 1024 MiB = 1 GiB. ${capacity(available)} available in Oblivion.${current ? " Growth keeps the original until its replacement is verified, so free space must cover the entire new volume." : " Space is reserved now; you can increase it later."}`,
    validate: (input) => {
      if (!/^\d+$/.test(input) || Number(input) < 128 || Number(input) > 1024 ** 2) return "Enter a capacity from 128 to 1048576 MiB."
      if (Number(input) * mib <= current) return "Choose a capacity larger than the current volume. Shrinking is not supported."
      if (Number(input) * mib + reserve > available) return "Not enough free storage for this volume and the 64 MiB reserve."
    },
  }
}

export function importSpace(bytes: number, entries: number) {
  // Include ext4 block rounding, directory/receipt metadata and working headroom.
  return bytes + entries * 8192 + reserve
}

export function suggestedSize(current: number, missing = 0) {
  return Math.ceil((current + Math.max(missing, 512 * mib)) / (512 * mib)) * 512
}
