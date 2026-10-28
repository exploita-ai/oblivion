import { For } from "solid-js"
import { z } from "zod"
import { PageHeader } from "./page-header"
import { ActionBar, type PageAction } from "./action-bar"
import { theme } from "./theme"

export const debugStatus = z.object({
  ssh_active: z.boolean(), addresses: z.array(z.string()), fingerprint: z.string().nullable(),
})

export function DebugPage(props: { status?: z.infer<typeof debugStatus>; actions: PageAction[]; focused: boolean; activate: () => void }) {
  const rows = () => [
    ["SSH access", props.status ? props.status.ssh_active ? "Enabled" : "Disabled" : "Not checked"],
    ["Local address", props.status?.addresses.join(", ") || "Unavailable"],
    ["User", "oblivion-test"],
    ["Host fingerprint", props.status?.fingerprint ?? "Available after enabling access"],
  ]
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <PageHeader title="Debug" description="Local diagnostics for this test image. Access uses the Mac's dedicated SSH key and lasts only for this boot." />
    <ActionBar actions={props.actions} focused={props.focused} activate={props.activate} />
    <scrollbox flexGrow={1} minHeight={0} marginTop={1}>
      <For each={rows()}>{(row) => <box flexDirection="row" flexShrink={0} gap={2} paddingBottom={1}>
        <text width={17} flexShrink={0} fg={theme.text.muted}>{row[0]}</text>
        <text flexGrow={1} minWidth={0} fg={theme.text.base}>{row[1]}</text>
      </box>}</For>
      <text fg={theme.text.muted}>Enable temporary diagnostic access from your test computer. Diagnostic keys stay in RAM. Chat data is never shown here.</text>
    </scrollbox>
  </box>
}
