import path from "node:path"
import { z } from "zod"

const opening = z.object({ slot: z.number().int().min(0).max(31), safe_id: z.string().regex(/^[a-f0-9]{32}$/), nonce: z.string().regex(/^[a-f0-9]{32}$/) })
export const storagePlan = z.object({ device: z.string(), identity: z.string(), table: z.string(), disk_bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), start: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), sectors: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), partition: z.number().int().positive() }).strict()
export type StoragePlan = z.infer<typeof storagePlan>
export const nativeActivity = z.object({ host: z.string().regex(/^[a-f0-9]{32}$/), safe: opening.nullable() })
export const idleLock = z.object({
  preferences: z.object({ version: z.literal(1), safe_minutes: z.number().int().min(0).max(1440), host_minutes: z.number().int().min(0).max(1440) }),
  storage: z.enum(["defaults", "saved-encrypted", "ram-only"]), writable: z.boolean(),
  host: z.object({ nonce: z.string().regex(/^[a-f0-9]{32}$/), remaining_seconds: z.number().nonnegative().nullable(), closing: z.boolean() }).nullable(),
  safes: z.array(z.object({ opening, remaining_seconds: z.number().nonnegative().nullable(), closing: z.boolean() })),
  last_error: z.string().nullable(),
})

export const nativeStatus = z.object({
  app_open: z.boolean(), app_mode: z.enum(["locked", "persistent", "read-only", "ram-only"]),
  idle_lock: idleLock,
  general_present: z.boolean(),
  general_incomplete: z.boolean(),
  persistence: z.object({ plan: storagePlan.nullable(), present: z.boolean(), incomplete: z.boolean(), unavailable: z.string().nullable() }).nullable(),
  general_open: z.boolean(),
  general_readonly: z.boolean(),
  recovery_required: z.boolean(),
  sessions: z.array(z.string().regex(/^[a-f0-9]{32}$/)),
  safe_parents: z.array(z.object({ id: z.string().regex(/^[a-f0-9]{32}$/), parent: z.string().regex(/^[a-f0-9]{32}$/) })),
  agent_safes: z.array(z.object({
    id: z.string().regex(/^[a-f0-9]{32}$/), parent: z.string().regex(/^[a-f0-9]{32}$/), created_by_agent: z.literal(true),
    agent: z.enum(["codex", "claude", "opencode2"]), ephemeral: z.boolean(), mib: z.number().int().positive(),
    state: z.enum(["awaiting-start", "failed", "recovery-required"]),
  })).max(128),
  session_titles: z.record(z.string(), z.string()),
  open_sessions: z.array(z.object({
    slot: z.number().int(),
    id: z.string().nullable(),
    mode: z.string().nullable(),
    recovery_required: z.boolean(),
  })),
  session_sizes: z.record(z.string(), z.number()).optional(),
  available_bytes: z.number().nullable().optional(),
  ephemeral_session_bytes: z.number().nonnegative().optional(),
  system: z.object({ os: z.string(), architecture: z.string(), cpu: z.string(), cores: z.number(), memory_total: z.number(), memory_available: z.number() }).optional(),
  network_status: z.object({
    label: z.enum(["NOT STARTED", "CONNECTING", "TOR READY", "SOCKS5 READY", "OFFLINE", "OFFLINE · NO NETWORK DEVICE", "STATUS UNKNOWN"]),
    direct_blocked: z.boolean(),
    host_link: z.enum(["CONNECTED", "OFFLINE", "STATUS UNKNOWN"]),
    age_ms: z.number().nonnegative(),
    tor_progress: z.number().nullable().optional(),
  }).optional(),
  egress: z.object({ selected: z.object({ mode: z.enum(["tor", "socks5"]), endpoint: z.string().optional() }) }).nullable().optional(),
  safe_access: z.object({ current: z.enum(["open", "strict", "offline"]), saved: z.enum(["open", "strict", "offline"]).nullable(), temporary: z.boolean() }),
})

export type NativeStatus = z.infer<typeof nativeStatus>
export type NativeOverlay = { page: "files" | "network"; safe: string }
export type NativeRuntime = {
  status: () => Promise<NativeStatus>
  run: (args: string[]) => Promise<number>
  query: (args: string[]) => Promise<unknown>
  activity: (input: z.infer<typeof nativeActivity>) => Promise<void>
  exit: () => Promise<void> | void
}

export function capacity(bytes: number) {
  return bytes >= 1024 ** 3 ? `${(bytes / 1024 ** 3).toFixed(1)} GiB` : `${Math.floor(bytes / 1024 ** 2)} MiB`
}

export function nativeLauncher() {
  return process.env.OBLIVION_LAUNCHER ?? path.join(path.dirname(process.execPath), "oblivion")
}

export function nativeOverlay(args: string[]): NativeOverlay | undefined {
  if (!args.includes("--native-overlay")) return undefined
  const parsed = z.tuple([z.literal("--native-overlay"), z.enum(["files", "network"]), z.literal("--safe"), z.string().regex(/^[a-f0-9]{32}$/)]).safeParse(args)
  if (!parsed.success) throw new Error("Usage: oblivion-manager --native-overlay files|network --safe SAFE_ID")
  return { page: parsed.data[1], safe: parsed.data[3] }
}

export async function readNativeStatus(launcher: string) {
  return nativeStatus.parse(await readNativeJson(launcher, ["status", "--json"]))
}

export async function readNativeJson(launcher: string, args: string[]) {
  const child = Bun.spawn([launcher, ...args], {
    stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout: 10_000,
    env: { ...process.env, OBLIVION_MANAGER_ACTIVE: "1" },
  })
  const output = await new Response(child.stdout).text()
  if (await child.exited !== 0) throw new Error("The Oblivion runtime is unavailable. Press R to retry.")
  return JSON.parse(output) as unknown
}

export async function reportNativeActivity(launcher: string, input: z.infer<typeof nativeActivity>) {
  const child = Bun.spawn([launcher, "activity"], {
    stdin: "pipe", stdout: "ignore", stderr: "ignore", timeout: 2000,
    env: { ...process.env, OBLIVION_MANAGER_ACTIVE: "1" },
  })
  child.stdin.write(JSON.stringify(input))
  child.stdin.end()
  await child.exited
}

export function nativePreview(exit: () => void, initial: Partial<NativeStatus> = {}): NativeRuntime {
  const ids = ["0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789"]
  let current: NativeStatus = {
    app_open: false, app_mode: "locked",
    safe_access: { current: "open", saved: null, temporary: false },
    idle_lock: { preferences: { version: 1, safe_minutes: 15, host_minutes: 30 }, storage: "defaults", writable: false, host: null, safes: [], last_error: null },
    general_present: true, general_open: false, general_readonly: false,
    general_incomplete: false, persistence: null,
    recovery_required: false, sessions: ids,
    safe_parents: [],
    agent_safes: [],
    session_titles: { [ids[0]]: "Research", [ids[1]]: "Development" },
    open_sessions: [], session_sizes: { [ids[0]]: 3 * 1024 ** 3, [ids[1]]: 1024 ** 3 },
    available_bytes: 12 * 1024 ** 3,
    ...initial,
  }
  return {
    async activity() {},
    async status() { return current },
    async query(args) {
      if (args[0] === "share" && args[1] === "imports") return []
      if (args[0] === "network") return { ...current, network_status: { label: "NOT STARTED", direct_blocked: false, host_link: "STATUS UNKNOWN", age_ms: 0 }, safe_access: { current: "open", saved: null, temporary: false } }
      if (args[0] === "files" && args[1] === "list") {
        const selected = args.find((value) => value === "workspace" || value === "imports" || value.startsWith("workspace/") || value.startsWith("imports/")) ?? ""
        return { path: selected, next_cursor: null, skipped: 0, entries: selected ? selected === "workspace" ? [{ name: "project", path: "workspace/project", kind: "directory", bytes: 0 }] : [] : ["workspace", "imports"].map((name) => ({ name, path: name, kind: "directory", bytes: 0 })) }
      }
      throw new Error("Preview data is unavailable for this operation.")
    },
    async run(args) {
      if (args[0] === "init") current = { ...current, general_present: !args.includes("--reset-incomplete"), general_incomplete: false, persistence: current.persistence ? { ...current.persistence, present: !args.includes("--reset-incomplete"), incomplete: false } : null }
      if (args[0] === "unlock" || args[0] === "ephemeral") current = { ...current, app_open: true, app_mode: args[0] === "ephemeral" ? "ram-only" : args[1] === "--read-only" ? "read-only" : "persistent", general_open: args[0] !== "ephemeral", general_readonly: args[0] === "unlock" && args[1] === "--read-only", idle_lock: { ...current.idle_lock, writable: args[0] === "unlock" && args[1] !== "--read-only", host: { nonce: "c".repeat(32), remaining_seconds: 1800, closing: false } } }
      if (args[0] === "lock") current = { ...current, app_open: false, app_mode: "locked", general_open: false, general_readonly: false, open_sessions: [], idle_lock: { ...current.idle_lock, writable: false, host: null, safes: [] } }
      if (args[0] === "close") current = { ...current, open_sessions: current.open_sessions.filter((safe) => safe.id !== args[1]), idle_lock: { ...current.idle_lock, safes: current.idle_lock.safes.filter((safe) => safe.opening.safe_id !== args[1]) } }
      if (args[0] === "settings" && args[1] === "idle") current = { ...current, idle_lock: { ...current.idle_lock, storage: current.app_mode === "persistent" ? "saved-encrypted" : "ram-only", preferences: { version: 1, safe_minutes: Number(args[args.indexOf("--safe-minutes") + 1]), host_minutes: Number(args[args.indexOf("--host-minutes") + 1]) } } }
      if (args[0] === "safe" && args[1] === "open" && !current.open_sessions.some((opened) => opened.id === args[2])) current = { ...current, open_sessions: [...current.open_sessions, { slot: current.open_sessions.length, id: args[2], mode: "documents", recovery_required: false }], idle_lock: { ...current.idle_lock, safes: [...current.idle_lock.safes, { opening: { slot: current.open_sessions.length, safe_id: args[2], nonce: "d".repeat(32) }, remaining_seconds: 900, closing: false }] } }
      return 0
    },
    exit,
  }
}
