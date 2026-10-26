import { Show } from "solid-js"
import { useTerminalDimensions } from "@opentui/solid"
import { ActionItem, SelectList } from "@opencode/tui-kit"
import { palette, theme } from "./theme"
import { ActionBar, type PageAction } from "./action-bar"
import { PageHeader } from "./page-header"

export type MenuItem = { name: string; description: string; disabled?: string; badge?: string; action?: string; run: () => void }

export function Menu(props: { title: string; description: string; toolbar?: PageAction[]; actionsFocused?: boolean; focusActions?: () => void; empty?: string; details?: boolean; items: MenuItem[]; selected: number; focused: boolean; disabled?: boolean; actions?: boolean; back?: () => void; focus?: () => void; change: (index: number) => void; choose: (index: number) => void }) {
  const dimensions = useTerminalDimensions()
  const spacious = () => dimensions().width >= 110 && dimensions().height >= 32
  const current = () => props.items[props.selected]
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <PageHeader title={props.title} description={props.description} />
    <Show when={props.toolbar?.length}><box flexShrink={0} paddingBottom={1} border={["bottom"]} borderColor={theme.border.base}>
      <ActionBar actions={props.toolbar!} focused={props.actionsFocused} disabled={props.disabled} activate={props.focusActions} />
    </box></Show>
    <Show when={props.items.length} fallback={<text fg={theme.text.muted}>{props.empty ?? "No items yet."}</text>}><SelectList theme={palette} items={props.items.map((item) => ({ title: item.name, footer: item.badge }))}
      selected={props.selected} focused={props.focused} disabled={props.disabled} spacing={spacious() ? 1 : 0} maxHeight={Math.max(1, props.items.length * (spacious() ? 2 : 1))}
      onFocus={props.focus} onChange={props.change} onSelect={props.choose} /></Show>
    <Show when={props.details !== false && current()}>{(item) => <box flexShrink={0} flexDirection="column" gap={1} paddingTop={1} marginTop={spacious() ? 1 : 0}
      border={["top"]} borderColor={theme.border.base}>
      <text fg={theme.text.muted}>{item().description}</text>
      <Show when={item().disabled}>
        <text fg={theme.feedback.info}>Unavailable: {item().disabled}</text>
      </Show>
      <Show when={props.actions !== false}><box flexDirection="row" gap={3}>
        <Show when={!item().disabled}><ActionItem theme={palette} modern flush variant="primary"
          action={{ title: item().action ?? item().name.replace(/^\+ /, ""), key: "Enter", disabled: props.disabled, onTrigger: () => props.choose(props.selected) }} /></Show>
        <Show when={props.back}><ActionItem theme={palette} modern flush variant="secondary"
          action={{ title: "Back", key: "Esc", disabled: props.disabled, onTrigger: props.back }} /></Show>
      </box></Show>
    </box>}</Show>
  </box>
}
