import path from "node:path"
import { z } from "zod"

export const nativeStatus = z.object({
  general_present: z.boolean(),
  general_open: z.boolean(),
  general_readonly: z.boolean(),
  recovery_required: z.boolean(),
  sessions: z.array(z.string().regex(/^[a-f0-9]{32}$/)),
  session_titles: z.record(z.string(), z.string()),
  open_sessions: z.array(z.object({
    slot: z.number().int(),
    id: z.string().nullable(),
    mode: z.string().nullable(),
    recovery_required: z.boolean(),
  })),
  session_sizes: z.record(z.string(), z.number()).optional(),
  available_bytes: z.number().nullable().optional(),
})

export type NativeStatus = z.infer<typeof nativeStatus>
export type NativeRuntime = {
  status: () => Promise<NativeStatus>
  run: (args: string[]) => Promise<number>
  exit: () => Promise<void> | void
}

export function nativeLauncher() {
  return process.env.OBLIVION_LAUNCHER ?? path.join(path.dirname(process.execPath), "oblivion")
}

export async function readNativeStatus(launcher: string) {
  const child = Bun.spawn([launcher, "status", "--json"], {
    stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout: 10_000,
    env: { ...process.env, OBLIVION_MANAGER_ACTIVE: "1" },
  })
  const output = await new Response(child.stdout).text()
  if (await child.exited !== 0) throw new Error("The Oblivion runtime is unavailable. Press R to retry.")
  return nativeStatus.parse(JSON.parse(output))
}

export function nativePreview(exit: () => void): NativeRuntime {
  const ids = ["0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789"]
  let current: NativeStatus = {
    general_present: true, general_open: false, general_readonly: false,
    recovery_required: false, sessions: ids,
    session_titles: { [ids[0]]: "Research", [ids[1]]: "Development" },
    open_sessions: [], session_sizes: { [ids[0]]: 3 * 1024 ** 3, [ids[1]]: 1024 ** 3 },
    available_bytes: 12 * 1024 ** 3,
  }
  return {
    async status() { return current },
    async run(args) {
      if (args[0] === "init") current = { ...current, general_present: true }
      if (args[0] === "unlock" || args[0] === "ephemeral") current = { ...current, general_open: true, general_readonly: args[0] === "ephemeral" }
      if (args[0] === "lock") current = { ...current, general_open: false, open_sessions: [] }
      if (args[0] === "close") current = { ...current, open_sessions: current.open_sessions.filter((safe) => safe.id !== args[1]) }
      return 0
    },
    exit,
  }
}
