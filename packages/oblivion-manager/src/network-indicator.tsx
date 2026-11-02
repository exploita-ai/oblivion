import { For } from "solid-js"
import type { Status } from "./state"
import { theme } from "./theme"

export type NetworkLabel = NonNullable<Status["network_status"]>["label"]
export type NetworkConnection = NonNullable<Status["connections"]>["internet"]

export function NetworkIndicator(props: { label: NetworkLabel; host: string; blocked: boolean; connection: NetworkConnection; transport: string; access?: "strict" | "open" | "offline" }) {
  const ready = () => props.blocked && props.host === "CONNECTED"
  const route = (mode: string) => {
    if (props.access === "offline") return " "
    if (props.label === "STATUS UNKNOWN") return "?"
    if (props.label === `${mode === "tor" ? "TOR" : "SOCKS5"} READY`) return ready() ? "+" : "?"
    if (props.label === "CONNECTING" && props.transport === mode) return "."
    return " "
  }
  const indicators = () => [
    { name: "Network", mark: props.connection === "available" || props.connection === "local" ? "+" : props.connection === "offline" ? " " : "?" },
    { name: "Tor", mark: route("tor") },
    { name: "SOCKS5", mark: route("socks5") },
  ]
  return <box flexDirection="row" gap={3} flexShrink={0}>
    <For each={indicators()}>{(indicator) => <box flexDirection="row" gap={1}>
      <text fg={theme.text.muted}>{indicator.name}</text>
      <text fg={indicator.mark === "+" ? theme.feedback.success : indicator.mark === "?" || indicator.mark === "." ? theme.feedback.warning : theme.text.muted}>[{indicator.mark}]</text>
      {indicator.name === "Network" && props.access && <text fg={theme.text.base}>{props.access === "open" ? "Open Web" : props.access === "strict" ? "Strict" : "Offline"}</text>}
    </box>}</For>
  </box>
}
