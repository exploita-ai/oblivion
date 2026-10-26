import { z } from "zod"

const identifier = z.string().regex(/^[a-f0-9]{32}$/)
export const provider = z.enum(["abliteration-ai", "refuseless", "openrouter"])
const transport = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("tor") }),
  z.object({ mode: z.literal("socks5"), endpoint: z.string(), authenticated: z.boolean() }),
])

export const preferences = z.object({
  version: z.literal(1),
  completed: z.boolean(),
  keyboard: z.string(),
  variant: z.string().default(""),
  timezone: z.string(),
})

export const status = z.object({
  debug_available: z.boolean().default(false),
  general_present: z.boolean(),
  general_incomplete: z.boolean(),
  general_open: z.boolean(),
  general_mounted: z.boolean(),
  general_readonly: z.boolean(),
  session_open: z.boolean(),
  session_mode: z.enum(["documents", "chat", "starting"]).nullable().default(null),
  active_session: z.string().nullable().default(null),
  network_status: z.object({
    label: z.enum(["NOT STARTED", "CONNECTING", "TOR READY", "SOCKS5 READY", "OFFLINE", "OFFLINE · NO NETWORK DEVICE", "STATUS UNKNOWN"]),
    host_link: z.enum(["CONNECTED", "OFFLINE", "STATUS UNKNOWN"]).default("STATUS UNKNOWN"),
    direct_blocked: z.boolean(), age_ms: z.number().nonnegative().default(0),
  }).optional(),
  system: z.object({ os: z.string(), architecture: z.string(), cpu: z.string(), cores: z.number(), memory_total: z.number(), memory_available: z.number() }).optional(),
  connections: z.object({
    internet: z.enum(["available", "offline", "local", "unknown"]),
    wifi_enabled: z.boolean(),
    devices: z.array(z.object({ name: z.string(), kind: z.enum(["wifi", "ethernet"]), state: z.string() })),
    access_points: z.array(z.object({ device: z.string(), bssid: z.string(), ssid: z.string(), signal: z.number(), security: z.string(), active: z.boolean() })),
  }).nullable().optional(),
  sessions: z.array(identifier),
  session_titles: z.record(z.string(), z.string()).default({}),
  incomplete_sessions: z.array(identifier),
  available_bytes: z.number().nullable(),
  session_bytes: z.number(),
  vm_state: z.string().nullable(),
  laboratory_emulation: z.boolean(),
  recovery_required: z.boolean(),
  api_key_present: z.boolean().nullable(),
  api_keys: z.object({
    entries: z.array(z.object({ id: identifier, provider, name: z.string(), temporary: z.boolean() })),
    default: identifier.nullable(),
    selected: identifier.nullable(),
  }).nullable(),
  egress: z.object({ saved: transport, selected: transport, temporary: z.boolean() }).nullable(),
  network_policy: z.object({
    enabled: z.boolean(),
    temporary: z.boolean(),
    policy: z.object({
      version: z.number(),
      rules: z.array(z.object({
        destination: z.string(),
        port: z.number(),
        action: z.enum(["allow", "deny", "ask"]),
        session: identifier.nullable().optional(),
      })),
    }),
  }).nullable(),
  gateway_state: z.string().nullable(),
  gateway_vm_state: z.string().nullable(),
  gateway_network: z.boolean(),
  transfers_configured: z.boolean(),
  network_profiles_saved: z.boolean().nullable(),
  persistence: z.object({
    present: z.boolean(),
    incomplete: z.boolean(),
    unavailable: z.string().nullable(),
    plan: z.object({
      device: z.string(), identity: z.string(), table: z.string(), disk_bytes: z.number(),
      start: z.number(), sectors: z.number(), partition: z.number(),
    }).nullable(),
  }).nullable(),
  settings: z.object({
    current: preferences,
    saved: preferences.nullable(),
  }).optional(),
})

export type Status = z.infer<typeof status>
export type Preferences = z.infer<typeof preferences>


export function capacity(bytes: number) {
  return bytes >= 1024 ** 3 ? `${(bytes / 1024 ** 3).toFixed(1)} GiB` : `${Math.floor(bytes / 1024 ** 2)} MiB`
}

export function defaults(): Preferences {
  return { version: 1, completed: false, keyboard: "us", variant: "", timezone: "UTC" }
}
