import { For } from "solid-js"
import { PageHeader } from "./page-header"
import { capacity, type Status } from "./state"
import { theme } from "./theme"

export function SystemPage(props: { status: Status; focused: boolean }) {
  const rows = () => [
    ["Operating system", props.status.system?.os ?? "Unavailable"],
    ["Architecture", props.status.system?.architecture ?? "Unavailable"],
    ["CPU", props.status.system?.cpu ?? "Unavailable"],
    ["CPU cores", String(props.status.system?.cores ?? "Unavailable")],
    ["Memory", props.status.system ? `${capacity(props.status.system.memory_available)} available / ${capacity(props.status.system.memory_total)}` : "Unavailable"],
    ["Boot storage", props.status.persistence?.plan ? capacity(props.status.persistence.plan.disk_bytes) : "Unavailable"],
    ["Encrypted storage", props.status.available_bytes === null ? "Read-only" : `${capacity(props.status.available_bytes)} available`],
    ["Session size", capacity(props.status.session_bytes)],
    ["Mode", props.status.general_readonly ? "Ephemeral · RAM only" : "Persistent · Encrypted"],
  ]
  return <box flexDirection="column" flexGrow={1} minHeight={0} gap={1}>
    <PageHeader title="System" description="Hardware and storage on this device." />
    <scrollbox flexGrow={1} minHeight={0} focused={props.focused}>
      <For each={rows()}>{(row) => <box flexDirection="row" flexShrink={0} paddingBottom={1} gap={2}>
        <text width={19} flexShrink={0} fg={theme.text.muted}>{row[0]}</text>
        <text fg={theme.text.base}>{row[1]}</text>
      </box>}</For>
    </scrollbox>
  </box>
}
