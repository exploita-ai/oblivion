import { createSignal, For } from "solid-js"
import { useKeyboard } from "@opentui/solid"
import { ActionItem } from "@opencode/tui-kit"
import { palette } from "./theme"

export type PageAction = { title: string; key: string; disabled?: boolean; run: () => void }

export function ActionBar(props: { actions: PageAction[]; focused?: boolean; disabled?: boolean; activate?: () => void }) {
  const [selected, setSelected] = createSignal(0)
  useKeyboard((key) => {
    if (key.defaultPrevented || !props.focused || props.disabled) return
    if (["left", "right", "up", "down"].includes(key.name)) {
      key.preventDefault()
      setSelected((value) => (value + (key.name === "left" || key.name === "up" ? props.actions.length - 1 : 1)) % props.actions.length)
    }
    if (key.name === "return") {
      key.preventDefault()
      const action = props.actions[Math.min(selected(), props.actions.length - 1)]
      if (action && !action.disabled) action.run()
    }
  })
  return <box flexDirection="row" gap={2} flexShrink={0}>
    <For each={props.actions}>{(action, index) => <ActionItem theme={palette} modern flush variant="secondary" focused={props.focused && selected() === index()}
      action={{ title: action.title, key: action.key, disabled: props.disabled || action.disabled, onTrigger: () => { props.activate?.(); setSelected(index()); action.run() } }} />}</For>
  </box>
}
