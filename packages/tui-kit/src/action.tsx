import { createSignal, Show } from "solid-js"
import type { RGBA } from "@opentui/core"
import type { ResolvedTheme } from "@opencode/theme/tui"

export type Action = { title: string; key?: string; disabled?: boolean; color?: RGBA; onTrigger?: () => void }

// Shared with OpenCode dialogs; behavior providers stay in their owning app.
export function ActionItem(props: { action: Action; variant: "primary" | "secondary"; theme: ResolvedTheme; modern?: boolean; focused?: boolean; flush?: boolean }) {
  const [hovered, setHovered] = createSignal(false)
  const trigger = () => {
    if (props.action.disabled) return
    props.action.onTrigger?.()
  }
  const label = (key: RGBA) => (
    <>
      <span
        style={{
          fg: props.action.disabled ? props.theme.text.action.primary.disabled : (props.action.color ?? (props.focused ? props.theme.text.action[props.variant].focused : props.theme.text.action[props.variant].base)),
        }}
      >
        {props.focused && !props.flush ? "> " : ""}<Show when={props.focused && props.flush} fallback={props.action.title}><u>{props.action.title}</u></Show>
      </span>
      <Show when={props.action.key}>
        <span style={{ fg: props.action.disabled ? props.theme.text.action.primary.disabled : (props.action.color ?? key) }}>
          {" " + props.action.key}
        </span>
      </Show>
    </>
  )
  return (
    <Show when={props.modern} fallback={<text onMouseUp={trigger}>{label(props.theme.text.muted)}</text>}>
      <box
        paddingLeft={props.flush ? 0 : 1}
        paddingRight={props.flush ? 0 : 1}
        flexShrink={0}
        backgroundColor={
          props.focused ? props.theme.background.action[props.variant].focused : hovered() && !props.action.disabled ? props.theme.background.action[props.variant].hovered : undefined
        }
        onMouseOver={() => setHovered(true)}
        onMouseOut={() => setHovered(false)}
        onMouseUp={trigger}
      >
        <text>{label(props.theme.text.shortcut)}</text>
      </box>
    </Show>
  )
}
