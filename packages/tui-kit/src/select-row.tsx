import { RGBA, TextAttributes } from "@opentui/core"
import { createMemo, Show, type JSX } from "solid-js"
import type { ResolvedTheme } from "@opencode/theme/tui"

// The production OpenCode row; callers own filtering, focus and actions.
export function SelectRow(props: {
  theme: ResolvedTheme
  modern?: boolean
  inset?: number
  title: string
  titleView?: JSX.Element
  description?: string
  active: boolean
  current: boolean
  footer?: JSX.Element | string
  footerColor?: RGBA
  footerOverhang?: number
  gutter?: (color: RGBA) => JSX.Element
  margin?: JSX.Element
  activeBackground?: RGBA
  activeColor?: RGBA
}) {
  const text = createMemo(() => {
    if (props.active) return props.activeColor ?? props.theme.text.action.primary.focused
    if (props.current && !props.modern) return props.theme.text.formfield.selected
    return props.theme.text.base
  })
  // Secondary text (description and footer).
  const secondary = () => {
    if (!props.modern) return props.active ? text() : props.theme.text.muted
    return props.active ? props.theme.text.action.secondary.focused : props.theme.text.faint
  }

  const row = () => (
    // A marker or gutter takes its cell plus the row gap out of the left padding,
    // so titles line up with unmarked rows: scroll pad (1) + marker (1) + gap (1).
    <box
      flexDirection="row"
      flexGrow={props.modern ? 1 : undefined}
      paddingLeft={props.current || props.gutter ? (props.inset ?? 4) - 3 : (props.inset ?? 4) - 1}
      paddingRight={(props.inset ?? 4) - (props.modern ? 0 : 1)}
      gap={1}
      backgroundColor={
        props.active ? (props.activeBackground ?? props.theme.background.action.primary.focused) : RGBA.fromInts(0, 0, 0, 0)
      }
    >
      <Show when={!props.current && props.margin}>
        <box position="absolute" left={(props.inset ?? 4) - 3} flexShrink={0}>
          {props.margin}
        </box>
      </Show>
      <Show when={props.current && !props.gutter}>
        <text flexShrink={0} fg={props.modern ? props.theme.text.formfield.selected : text()}>
          {props.modern ? "▪" : "●"}
        </text>
      </Show>
      <Show when={props.gutter}>
        <box flexShrink={0}>{props.gutter?.(text())}</box>
      </Show>
      <text
        flexGrow={1}
        fg={text()}
        attributes={props.active && !props.modern ? TextAttributes.BOLD : undefined}
        overflow="hidden"
        wrapMode="none"
        paddingLeft={3}
      >
        {props.titleView ?? props.title}
        <Show when={props.description}>
          <span style={{ fg: secondary() }}>{" " + props.description}</span>
        </Show>
      </text>
      <Show when={props.footer}>
        <box flexShrink={0} marginRight={props.footerOverhang ? -props.footerOverhang : undefined}>
          <text fg={props.active || !props.footerColor ? secondary() : props.footerColor}>{props.footer}</text>
        </box>
      </Show>
    </box>
  )

  return (
    <Show when={props.modern} fallback={row()}>
      <box flexDirection="row">
        <text width={1} flexShrink={0} fg={props.theme.text.formfield.focused}>
          {props.active ? "┃" : " "}
        </text>
        {row()}
      </box>
    </Show>
  )
}
