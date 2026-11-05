import { createSignal, For, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard } from "@opentui/solid"
import { ActionBar } from "./action-bar"
import { Menu } from "./menu"
import { PageHeader } from "./page-header"
import { FormView } from "./form"
import { capacity, nativeStatus, type NativeRuntime, type NativeStatus } from "./native-control"
import { theme } from "./theme"
import { liveMedia, type LiveDevice } from "./native-usb"

export type NetworkObservation = { safe: string; state: NativeStatus; received: number }

export function scopedNetworkObservation(observation: NetworkObservation | undefined, safe: string | undefined, host: NativeStatus | undefined, now: number) {
  if (!observation || !safe || observation.safe !== safe || !host?.app_open || !observation.state.app_open
    || host.recovery_required || observation.state.recovery_required || host.idle_lock.host?.closing || !host.idle_lock.host
    || observation.state.idle_lock.host?.closing
    || host.idle_lock.host.nonce !== observation.state.idle_lock.host?.nonce
    || now - observation.received + (observation.state.network_status?.age_ms ?? 10_001) > 10_000) return undefined
  const current = host.idle_lock.safes.find((entry) => entry.opening.safe_id === safe)
  const reported = observation.state.idle_lock.safes.find((entry) => entry.opening.safe_id === safe)
  const active = host.open_sessions.find((entry) => entry.id === safe)
  if (!current || current.closing || !reported || reported.closing || !active || active.recovery_required
    || active.slot !== current.opening.slot || current.opening.slot !== reported.opening.slot
    || current.opening.nonce !== reported.opening.nonce) return undefined
  return observation.state
}
const policies = [
  { id: "open-internet", value: "open", name: "Open Internet", description: "Allow TCP to public destinations through this Safe's Tor or SOCKS5 route. Explicit deny rules still apply." },
  { id: "strict", value: "strict", name: "Strict", description: "Restrict this Safe to destinations permitted by its gateway rules, through its protected route." },
  { id: "offline", value: "offline", name: "Offline", description: "Block this Safe's network access, including provider requests. Local file operations remain available." },
] as const

export function NativeNetwork(props: { safe: string; name: string; open: boolean; runtime: NativeRuntime; run: (args: string[]) => Promise<boolean>; observed: (value: NetworkObservation) => void; back: () => void }) {
  const [snapshot, setSnapshot] = createSignal<NativeStatus>()
  const [selected, setSelected] = createSignal(0)
  const [error, setError] = createSignal("")
  const [working, setWorking] = createSignal(false)
  const [view, setView] = createSignal<"policy" | "transport" | "proxy">("policy")
  const [routeSelected, setRouteSelected] = createSignal(0)
  const [received, setReceived] = createSignal(0)
  const [now, setNow] = createSignal(performance.now())
  let pending = false
  let stopped = false

  async function change(args: string[]) {
    if (working()) return
    setWorking(true)
    try {
      if (await props.run(["network", "set", "--safe", props.safe, ...args])) { setView("policy"); await refresh() }
    } finally { setWorking(false) }
  }

  function apply(index: number) { if (policies[index]) void change(["--policy", policies[index].id]) }
  function route(index: number) { if (index === 0) { void change(["--tor"]); return }; setView("proxy") }
  const transportLabel = () => now() - received() + (snapshot()?.network_status?.age_ms ?? 10_001) > 10_000 ? "STATUS UNKNOWN" : snapshot()?.network_status?.label ?? "STATUS UNKNOWN"

  async function refresh() {
    if (pending || !props.open) return
    pending = true
    try {
      const value = nativeStatus.parse(await props.runtime.query(["network", "status", "--safe", props.safe, "--json"]))
      if (stopped) return
      setSnapshot(value)
      setReceived(performance.now())
      setError("")
      props.observed({ safe: props.safe, state: value, received: performance.now() })
    } catch {
      if (!stopped) { setSnapshot(undefined); setError("Network status is unavailable. No protected route has been verified.") }
    } finally { pending = false }
  }

  onMount(() => {
    void refresh()
    const timer = setInterval(() => { void refresh() }, 5000)
    const clock = setInterval(() => setNow(performance.now()), 1000)
    onCleanup(() => { clearInterval(timer); clearInterval(clock) })
  })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (!props.open) { if (key.name === "escape") { key.preventDefault(); props.back() }; return }
    if (view() === "proxy") return
    if (key.name === "escape") { key.preventDefault(); if (view() === "transport") setView("policy"); else props.back(); return }
    if (key.name === "t") { key.preventDefault(); setView("transport"); return }
    if (key.name === "r") { key.preventDefault(); void refresh() }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={props.open} fallback={<Menu title="Network" description={`${props.name} is locked. Open it offline to inspect or change its gateway settings.`}
      items={[{ name: "Open Safe offline", description: "Unlock this Safe without starting an agent or connecting a protected route.", action: "Open Safe", run: () => { void props.run(["safe", "open", props.safe]).then(async (ok) => { if (ok) await refresh() }) } }]}
      selected={0} change={() => {}} focused choose={() => { void props.run(["safe", "open", props.safe]).then(async (ok) => { if (ok) await refresh() }) }} back={props.back} />}>
    <Show when={view() === "proxy"}><FormView form={{ title: "SOCKS5 proxy", description: "This Safe uses remote DNS through the proxy. A password is requested privately in the terminal when a username is supplied.", fields: [
      { id: "endpoint", label: "IPv4 address and port", value: snapshot()?.egress?.selected.endpoint ?? "", validate: (value) => {
        const parts = value.split(":")
        if (!/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(value) || parts[0].split(".").some((part) => Number(part) > 255) || Number(parts[1]) < 1 || Number(parts[1]) > 65535) return "Enter an IPv4 address and port, for example 192.0.2.10:1080."
        return undefined
      } },
      { id: "username", label: "Username (optional)" },
    ], submit: "Apply proxy", run: async () => {} }} cancel={() => setView("transport")} submit={(values) => { void change(["-x", `socks5h://${values.username ? encodeURIComponent(values.username) + "@" : ""}${values.endpoint}`]) }} /></Show>
    <Show when={view() === "transport"}><Menu title="Connection privacy" description={`${props.name} · ${transportLabel()}`}
      items={[
        { name: "Tor", badge: snapshot()?.egress?.selected.mode === "tor" ? "Selected" : undefined, description: "Use this Safe's independent Tor gateway. Status becomes ready only after verification.", action: "Use Tor", run: () => route(0) },
        { name: "SOCKS5 proxy", badge: snapshot()?.egress?.selected.mode === "socks5" ? "Selected" : undefined, description: "Configure a proxy for this Safe, with optional authentication and remote DNS.", action: "Configure proxy", run: () => route(1) },
      ]} selected={routeSelected()} change={setRouteSelected} focused disabled={working()} choose={route} back={() => setView("policy")} /></Show>
    <Show when={view() === "policy"}><Menu title="Network access" description={`${props.name} · ${transportLabel()} · Applies to every agent in this Safe.`}
      toolbar={[{ title: "Change route", key: "T", run: () => setView("transport") }, { title: "Refresh", key: "R", run: () => { void refresh() } }]}
      items={policies.map((policy, index) => ({ name: policy.name, description: policy.description, badge: snapshot()?.safe_access.current === policy.value ? "Current" : undefined, action: "Apply policy", run: () => { void apply(index) } }))}
      selected={selected()} change={setSelected} focused disabled={working()}
      choose={apply} back={props.back} /></Show>
    <Show when={error()}><text fg={theme.feedback.warning}>{error()}</text></Show>
    </Show>
  </box>
}

export function NativeNetworkIndicator(props: { observation?: NetworkObservation; safe?: string; host?: NativeStatus; hostReceived: number }) {
  const [now, setNow] = createSignal(performance.now())
  const timer = setInterval(() => setNow(performance.now()), 1000)
  onCleanup(() => clearInterval(timer))
  const current = () => scopedNetworkObservation(props.observation, props.safe, props.host, now())
  const policy = () => policies.find((entry) => entry.value === current()?.safe_access.current)?.name
  const protectedRoute = (label: string) => props.host?.open_sessions.some((entry) => entry.id === props.safe && entry.mode === "agent")
    && current()?.open_sessions.some((entry) => entry.id === props.safe && entry.mode === "agent" && !entry.recovery_required)
    && current()?.network_status?.label === label && current()?.network_status?.direct_blocked && current()?.network_status?.host_link === "CONNECTED"
  const host = () => now() - props.hostReceived + (props.host?.network_status?.age_ms ?? 10_001) <= 10_000 ? props.host?.network_status?.host_link : undefined
  return <box flexDirection="row" gap={2} flexShrink={0}>
    <For each={[
      { name: "Network", mark: host() === "CONNECTED" ? "+" : host() === "OFFLINE" ? " " : "?" },
      { name: "Tor", mark: protectedRoute("TOR READY") ? "+" : " " },
      { name: "SOCKS5", mark: protectedRoute("SOCKS5 READY") ? "+" : " " },
    ]}>{(indicator) => <box flexDirection="row" gap={1}><text fg={theme.text.muted}>{indicator.name}</text><text fg={indicator.mark === "+" ? theme.feedback.success : indicator.mark === "?" ? theme.feedback.warning : theme.text.muted}>[{indicator.mark}]</text><Show when={indicator.name === "Network" && policy()}>{(value) => <text fg={theme.text.base}>· {value()}</text>}</Show></box>}</For>
  </box>
}

export function NativeSystem(props: { state?: NativeStatus; live?: NativeRuntime }) {
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <PageHeader title="System" description={props.live ? "Resources reported by the Debian runtime and the Live host." : "Resources reported by the Debian runtime hosting your Safes."} />
    <box flexDirection="column" flexShrink={0} gap={props.live ? 0 : 1}>
      <For each={[
        ["Operating system", props.state?.system?.os ?? "Unavailable"],
        ["Architecture", props.state?.system?.architecture ?? "Unavailable"],
        ["CPU", props.state?.system?.cpu ?? "Unavailable"],
        ["CPU cores", String(props.state?.system?.cores ?? "Unavailable")],
        ["Memory", props.state?.system ? `${Math.floor(props.state.system.memory_available / 1024 ** 2)} MiB available / ${Math.floor(props.state.system.memory_total / 1024 ** 2)} MiB` : "Unavailable"],
        ["Encrypted storage", props.state?.available_bytes == null ? "Unavailable" : `${(props.state.available_bytes / 1024 ** 3).toFixed(1)} GiB available`],
      ]}>{(row) => <box flexDirection="row" gap={2} flexShrink={0}><text width={19} fg={theme.text.muted}>{row[0]}</text><text fg={theme.text.base}>{row[1]}</text></box>}</For>
    </box>
    <Show when={props.live}>{(runtime) => <LiveMedia runtime={runtime()} />}</Show>
  </box>
}

function LiveMedia(props: { runtime: NativeRuntime }) {
  const [devices, setDevices] = createSignal<LiveDevice[]>()
  const [reading, setReading] = createSignal(false)
  let stopped = false
  async function refresh() {
    if (reading()) return
    setDevices(undefined)
    setReading(true)
    try {
      const media = liveMedia.parse(await props.runtime.query(["runtime", "live-media", "--json"]))
      if (!stopped) setDevices(media.devices)
    } catch {
      if (!stopped) setDevices(undefined)
    } finally { if (!stopped) setReading(false) }
  }
  onMount(() => { void refresh() })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || key.name !== "r") return
    key.preventDefault()
    void refresh()
  })
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <text fg={theme.text.base}><b>Removable USB media</b></text>
    <Show when={devices()?.length} fallback={<text fg={theme.text.muted}>{reading() ? "Inspecting USB media…" : devices() ? "No available USB media. Connect a separate drive and refresh." : "USB media inventory is unavailable."}</text>}>
      <scrollbox flexGrow={1} minHeight={1} focused>
        <For each={devices()}>{(device) => <box flexDirection="row" gap={2}>
          <text width={19} fg={theme.text.muted}>{device.name}</text>
          <text fg={theme.text.base}>{capacity(device.bytes)} · {device.read_only ? "Read-only" : "Writable"}</text>
        </box>}</For>
      </scrollbox>
    </Show>
    <ActionBar actions={[{ title: "Refresh media", key: "R", disabled: reading(), run: () => { void refresh() } }]} />
  </box>
}
