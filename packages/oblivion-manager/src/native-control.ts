import path from "node:path"
import { z } from "zod"

const opening = z.object({ slot: z.number().int().min(0).max(31), safe_id: z.string().regex(/^[a-f0-9]{32}$/), nonce: z.string().regex(/^[a-f0-9]{32}$/) })
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
  general_bytes: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  general_open: z.boolean(),
  general_readonly: z.boolean(),
  recovery_required: z.boolean(),
  family_password_pending: z.array(z.string().regex(/^[a-f0-9]{32}$/)).max(32768),
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

export function statusReader(read: (initial: boolean) => Promise<NativeStatus>) {
  let initial = true
  let pending: Promise<NativeStatus> | undefined
  return () => {
    if (pending) return pending
    const starting = initial
    pending = read(starting).then((state) => { initial = false; return state }).finally(() => { pending = undefined })
    return pending
  }
}

export async function readNativeStatus(launcher: string, timeout = 10_000) {
  return nativeStatus.parse(await readNativeJson(launcher, ["status", "--json"], timeout))
}

export async function readNativeJson(launcher: string, args: string[], timeout = 10_000) {
  const child = Bun.spawn([launcher, ...args], {
    stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout,
  })
  const output = await new Response(child.stdout).text()
  if (await child.exited !== 0) throw new Error("The Oblivion runtime is unavailable. Press R to retry.")
  return JSON.parse(output) as unknown
}

export async function reportNativeActivity(launcher: string, input: z.infer<typeof nativeActivity>) {
  const child = Bun.spawn([launcher, "activity"], {
    stdin: "pipe", stdout: "ignore", stderr: "ignore", timeout: 2000,
  })
  child.stdin.write(JSON.stringify(input))
  child.stdin.end()
  await child.exited
}

export function nativePreview(exit: () => void, initial: Partial<NativeStatus> = {}): NativeRuntime {
  const ids = ["0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789"]
  const tasks = new Map<string, { attempts: number; request: string; state: "running" | "cancelled" }>()
  const passwordChanges: { transaction: string; family_id: string; members: { safe_id: string; title: string }[]; outcome: "complete" }[] = []
  let current: NativeStatus = {
    app_open: false, app_mode: "locked",
    safe_access: { current: "open", saved: null, temporary: false },
    idle_lock: { preferences: { version: 1, safe_minutes: 15, host_minutes: 30 }, storage: "defaults", writable: false, host: null, safes: [], last_error: null },
    general_present: true, general_open: false, general_readonly: false,
    general_incomplete: false, general_bytes: 8 * 1024 ** 3,
    recovery_required: false, family_password_pending: [], sessions: ids,
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
      if (args[0] === "safe" && args[1] === "password") {
        if (!current.idle_lock.host || current.app_mode !== "persistent") throw new Error("Unlock the preview storage first.")
        if (args[2] === "status") return { host_opening: current.idle_lock.host.nonce, transactions: passwordChanges }
        const id = args[3]
        if (args[2] !== "preview" || !current.sessions.includes(id) || current.open_sessions.some((entry) => entry.id === id)) throw new Error("Choose a closed preview Safe.")
        return { host_opening: current.idle_lock.host.nonce, family_id: id, members: [{ safe_id: id, title: current.session_titles[id] }], sha256: "f".repeat(64) }
      }
      if (args[0] === "safe" && args[1] === "task") {
        const origin = current.agent_safes.find((record) => record.id === args[3])
        if (!origin || !current.open_sessions.some((opened) => opened.id === origin.id)) throw new Error("Open the preview Safe to review its task.")
        const attempt = tasks.get(origin.id)
        const status = { version: 1, safe_id: origin.id, agent: origin.agent, request_id: "e".repeat(32),
          attempt_request_id: attempt?.request ?? null, attempts: attempt?.attempts ?? 0, attempt_limit: 16,
          phase: attempt ? "submitted" : "not-started", job: attempt ? { job_id: "a".repeat(32), request_id: attempt.request, agent: origin.agent, state: attempt.state, native_chat_id: null, reason: null } : null,
          can_start: !attempt, can_retry: attempt?.state === "cancelled" && attempt.attempts < 16, can_cancel: attempt?.state === "running", blocked: null }
        return args[2] === "review" ? { status, task: "Preview task: inspect the workspace and describe the project. This local preview does not submit a task or start an agent." } : status
      }
      if (args[0] === "share" && args[1] === "imports") return []
      if (args[0] === "backup" && args[1] === "status") return { transactions: [] }
      if (args[0] === "network") return { ...current, network_status: { label: "NOT STARTED", direct_blocked: false, host_link: "STATUS UNKNOWN", age_ms: 0 }, safe_access: { current: "open", saved: null, temporary: false } }
      if (args[0] === "files" && args[1] === "list") {
        const selected = args.find((value) => value === "workspace" || value === "imports" || value.startsWith("workspace/") || value.startsWith("imports/")) ?? ""
        return { path: selected, next_cursor: null, skipped: 0, entries: selected ? selected === "workspace" ? [{ name: "project", path: "workspace/project", kind: "directory", bytes: 0 }] : [] : ["workspace", "imports"].map((name) => ({ name, path: name, kind: "directory", bytes: 0 })) }
      }
      throw new Error("Preview data is unavailable for this operation.")
    },
    async run(args) {
      if (args[0] === "safe" && args[1] === "password") {
        const id = args[2]
        if (!current.idle_lock.host || current.app_mode !== "persistent" || !current.sessions.includes(id)
          || current.open_sessions.some((entry) => entry.id === id) || args[3] !== "--confirmed-plan" || args[4] !== "f".repeat(64)) return 130
        passwordChanges.push({ transaction: passwordChanges.length.toString(16).padStart(32, "0"), family_id: id,
          members: [{ safe_id: id, title: current.session_titles[id] }], outcome: "complete" })
        return 0
      }
      if (args[0] === "safe" && args[1] === "task") {
        const previous = tasks.get(args[3])
        if (args[2] === "start" && !previous) tasks.set(args[3], { attempts: 1, request: "e".repeat(32), state: "running" })
        if (args[2] === "retry" && previous?.state === "cancelled" && previous.attempts < 16) tasks.set(args[3], { attempts: previous.attempts + 1, request: (previous.attempts + 1).toString(16).padStart(32, "0"), state: "running" })
        if (args[2] === "cancel" && previous) tasks.set(args[3], { ...previous, state: "cancelled" })
      }
      if (args[0] === "init") current = { ...current, general_present: !args.includes("--reset-incomplete"), general_incomplete: false }
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
