import { ControlError } from "./control"
import { defaults, preferences, type Status } from "./state"
import { z } from "zod"
import type { Runtime } from "./app"

// An explicit in-memory UI preview. It never opens the controller socket,
// starts a VM, writes preferences or sends a provider request.
export function preview(exit: () => void): Runtime {
  let state: Status = {
    session_titles: {}, debug_available: false,
    general_present: true, general_incomplete: false, general_open: true, general_mounted: true,
    general_readonly: false, session_open: false, session_mode: null, active_session: null,
    network_status: { label: "NOT STARTED", host_link: "CONNECTED", age_ms: 0, direct_blocked: false },
    system: { os: "Debian GNU/Linux 13 (trixie)", architecture: "aarch64", cpu: "ARM64 virtual CPU", cores: 4, memory_total: 8 * 1024 ** 3, memory_available: 5 * 1024 ** 3 },
    connections: { internet: "local", wifi_enabled: true, devices: [{ name: "eth0", kind: "ethernet", state: "connected" }, { name: "wlan0", kind: "wifi", state: "disconnected" }], access_points: [
      { device: "wlan0", bssid: "02:00:00:00:00:01", ssid: "Home Wi-Fi", signal: 87, security: "WPA2", active: false },
      { device: "wlan0", bssid: "02:00:00:00:00:02", ssid: "Guest", signal: 62, security: "--", active: false },
      { device: "wlan0", bssid: "02:00:00:00:00:03", ssid: "Office", signal: 44, security: "WPA2 802.1X", active: false },
    ] },
    sessions: ["a".repeat(32), "b".repeat(32), "c".repeat(32)], incomplete_sessions: [],
    available_bytes: 2095181824, session_bytes: 536870912, vm_state: "inactive", laboratory_emulation: false,
    recovery_required: false, api_key_present: true,
    api_keys: { entries: [{ id: "d".repeat(32), name: "Personal", temporary: false }], default: "d".repeat(32), selected: "d".repeat(32) },
    egress: { saved: { mode: "tor" }, selected: { mode: "tor" }, temporary: false },
    network_policy: { enabled: false, temporary: false, policy: { version: 1, rules: [] } },
    gateway_state: "active", gateway_vm_state: "active", gateway_network: true,
    transfers_configured: true, network_profiles_saved: true,
    persistence: { present: true, incomplete: false, unavailable: null, plan: { device: "sdc", identity: "8:32", table: "preview", disk_bytes: 3880779776, start: 2138112, sectors: 5439488, partition: 5 } },
    settings: { current: { ...defaults(), completed: true }, saved: { ...defaults(), completed: true } },
  }
  let savedPolicy = state.network_policy
  return {
    async request(input) {
      if (input.operation === "rename-session") {
        const value = z.object({ id: z.string(), title: z.string() }).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        state = { ...state, session_titles: { ...state.session_titles, [value.id]: value.title } }
        return ""
      }
      if (input.operation === "claim-intro") return "false"
      if (input.operation === "connections") {
        const command = z.discriminatedUnion("action", [
          z.object({ action: z.literal("scan") }),
          z.object({ action: z.literal("radio"), enabled: z.boolean() }),
          z.object({ action: z.literal("connect"), device: z.string(), bssid: z.string().optional(), password: z.string().optional() }),
          z.object({ action: z.literal("disconnect"), device: z.string() }),
        ]).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        const connections = state.connections!
        if (command.action === "scan") return ""
        if (command.action === "radio") {
          state = { ...state, connections: { ...connections, wifi_enabled: command.enabled, access_points: connections.access_points.map((ap) => ({ ...ap, active: command.enabled && ap.active })) } }
          return ""
        }
        const ap = command.action === "connect" ? connections.access_points.find((ap) => ap.bssid === command.bssid) : undefined
        if (ap?.security.includes("WPA2") && (command.action !== "connect" || (command.password?.length ?? 0) < 8)) throw new ControlError("invalid_wifi_password")
        state = { ...state, connections: { ...connections, devices: connections.devices.map((device) => device.name === command.device ? { ...device, state: command.action === "connect" ? "connected" : "disconnected" } : device), access_points: connections.access_points.map((item) => item.device === command.device ? { ...item, active: item === ap } : item) } }
        return ""
      }
      if (input.operation === "egress") {
        const command = z.object({ action: z.enum(["select", "save"]), transport: z.discriminatedUnion("mode", [
          z.object({ mode: z.literal("tor") }),
          z.object({ mode: z.literal("socks5"), endpoint: z.string(), authentication: z.object({ username: z.string(), password: z.string() }).nullable() }),
        ]) }).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        if (command.action === "save" && (!state.general_mounted || state.general_readonly)) throw new ControlError("general_not_writable")
        const selected = command.transport.mode === "tor" ? command.transport : { mode: "socks5" as const, endpoint: command.transport.endpoint, authenticated: !!command.transport.authentication }
        state = { ...state, egress: { selected, saved: command.action === "save" ? selected : state.egress!.saved, temporary: command.action !== "save" } }
        return ""
      }
      if (input.operation === "network-policy") {
        const command = z.object({ action: z.enum(["put", "remove"]), save: z.boolean(), rule: z.object({ destination: z.string(), port: z.number(), action: z.enum(["allow", "deny"]), session: z.string().nullable().optional() }) }).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        if (command.save && (!state.general_mounted || state.general_readonly)) throw new ControlError("general_not_writable")
        const rules = (state.network_policy?.policy.rules ?? []).filter((rule) => rule.destination !== command.rule.destination || rule.port !== command.rule.port || rule.session !== command.rule.session)
        state = { ...state, network_policy: { enabled: true, temporary: !command.save, policy: { version: 1, rules: command.action === "put" ? [...rules, command.rule] : rules } } }
        if (command.save) savedPolicy = state.network_policy
        return ""
      }
      if (input.operation === "save-network") {
        if (!state.general_mounted || state.general_readonly) throw new ControlError("general_not_writable")
        state = { ...state, network_profiles_saved: true }; return ""
      }
      if (input.operation === "settings-catalog") return JSON.stringify({ keyboards: [{ value: "us", label: "English (US)", variants: [{ value: "", label: "Default" }] }, { value: "it", label: "Italian", variants: [{ value: "", label: "Default" }] }], timezones: ["UTC", "Europe/Rome", "Europe/London", "America/New_York"] })
      if (input.operation === "browse") {
        const request = z.object({ path: z.string() }).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        return JSON.stringify({ path: request.path, entries: request.path ? [{ name: "example.txt", directory: false, bytes: 42 }] : [{ name: "imports", directory: true, bytes: 0 }, { name: "workspace", directory: true, bytes: 0 }], next: null, skipped: 0 })
      }
      if (input.operation === "open-documents") { state = { ...state, session_open: true, session_mode: "documents", active_session: input.session ?? null, network_status: { label: "OFFLINE · NO NETWORK DEVICE", host_link: "CONNECTED", age_ms: 0, direct_blocked: true } }; return "" }
      if (input.operation === "close") { state = { ...state, session_open: false, session_mode: null, active_session: null, api_keys: state.api_keys ? { ...state.api_keys, selected: null } : null, network_status: { label: "NOT STARTED", host_link: "CONNECTED", age_ms: 0, direct_blocked: false } }; return "" }
      if (input.operation === "create") { const id = crypto.randomUUID().replaceAll("-", ""); state = { ...state, sessions: [...state.sessions, id] }; return id }
      if (input.operation === "open-documents-ephemeral") { state = { ...state, session_open: true, session_mode: "documents", active_session: "ephemeral", network_status: { label: "OFFLINE · NO NETWORK DEVICE", host_link: "CONNECTED", age_ms: 0, direct_blocked: true } }; return "" }
      if (input.operation === "api-keys") {
        const value = z.object({ action: z.enum(["add", "temporary", "select", "default", "rename", "replace", "remove"]), id: z.string().optional(), name: z.string().optional() }).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        const keys = state.api_keys ?? { entries: [], default: null, selected: null }
        if (value.action === "add" || value.action === "temporary") {
          const id = crypto.randomUUID().replaceAll("-", "")
          state = { ...state, api_keys: { ...keys, default: keys.default ?? id, entries: [...keys.entries, { id, name: value.name ?? "Preview", temporary: value.action === "temporary" }] } }
          return ""
        }
        state = { ...state, api_keys: { entries: keys.entries.filter((entry) => value.action !== "remove" || entry.id !== value.id).map((entry) => entry.id === value.id && value.action === "rename" ? { ...entry, name: value.name ?? entry.name } : entry), default: value.action === "default" ? value.id ?? null : value.action === "remove" && keys.default === value.id ? null : keys.default, selected: value.action === "select" ? value.id ?? null : value.action === "remove" && keys.selected === value.id ? null : keys.selected } }
        return ""
      }
      if (input.operation === "transfers") return JSON.stringify({ configured: true, export_configured: true, active: false, sources: [] })
      if (input.operation === "status") return JSON.stringify(state)
      if (input.operation === "lock") { state = { ...state, general_open: false, general_mounted: false, sessions: [], egress: { saved: state.egress!.saved, selected: { mode: "tor" }, temporary: false }, network_policy: { enabled: false, temporary: false, policy: { version: 1, rules: [] } } }; return "" }
      if (input.operation === "unlock" || input.operation === "unlock-ephemeral") { state = { ...state, general_open: true, general_mounted: true, general_readonly: input.operation === "unlock-ephemeral", sessions: ["a".repeat(32)], egress: { saved: state.egress!.saved, selected: state.egress!.saved, temporary: false }, network_policy: savedPolicy }; return "" }
      if (input.operation === "settings") {
        const inputValue = z.object({ action: z.enum(["apply", "save"]), preferences }).parse(JSON.parse(new TextDecoder().decode(input.payload)))
        state = { ...state, settings: { current: inputValue.preferences, saved: inputValue.action === "save" ? inputValue.preferences : state.settings?.saved ?? null } }
        return ""
      }
      throw new ControlError("preview_only")
    },
    async console() { throw new ControlError("preview_only") },
    async documents() { throw new ControlError("preview_only") },
    exit,
  }
}
