import { MouseButton, ScrollBoxRenderable } from "@opentui/core"
import { useKeyboard } from "@opentui/solid"
import { createEffect, createSignal, For, onCleanup } from "solid-js"
import type { ResolvedTheme } from "@opencode/theme/tui"
import { SelectRow } from "./select-row"
import { moveSelection, reconcileSelection, revealSelectionOffset } from "./select-controller"

export type ListItem = { title: string; description?: string; footer?: string; current?: boolean }

// OpenCode's row and selection controller with an application-independent
// keyboard/mouse boundary. The caller owns focus, authorization and side effects.
export function SelectList(props: {
  items: ListItem[]
  theme: ResolvedTheme
  selected?: number
  focused: boolean
  disabled?: boolean
  height?: number
  maxHeight?: number
  spacing?: number
  onFocus?: () => void
  onChange?: (index: number) => void
  onSelect?: (index: number) => void
}) {
  const [cursor, setCursor] = createSignal(0)
  const [scroll, setScroll] = createSignal<ScrollBoxRenderable>()
  const [height, setHeight] = createSignal(1)
  const selected = () => reconcileSelection(props.selected ?? cursor(), props.items.length)
  const rowHeight = () => 1 + (props.spacing ?? 0)
  function move(index: number) {
    if (props.disabled) return
    const next = reconcileSelection(index, props.items.length)
    setCursor(next)
    props.onChange?.(next)
  }
  function select(index: number) {
    if (props.disabled || !props.items[index]) return
    move(index)
    props.onSelect?.(index)
  }
  function reveal() {
    const target = scroll()
    if (!target) return
    target.scrollTo(revealSelectionOffset(target.scrollTop, {
      count: props.items.length * rowHeight(), limit: height(), selected: selected() * rowHeight(),
    }))
  }
  createEffect(reveal)
  useKeyboard((key) => {
    if (key.defaultPrevented || !props.focused || props.disabled) return
    if (key.name === "return") { key.preventDefault(); select(selected()); return }
    const delta = key.name === "down" ? 1 : key.name === "up" ? -1
      : key.name === "pagedown" ? Math.max(1, Math.floor(height() / rowHeight()))
      : key.name === "pageup" ? -Math.max(1, Math.floor(height() / rowHeight())) : 0
    if (key.name === "home" || key.name === "end") {
      key.preventDefault(); move(key.name === "home" ? 0 : props.items.length - 1); return
    }
    if (!delta) return
    key.preventDefault()
    move(moveSelection(selected(), { count: props.items.length, delta, policy: "clamp" }))
  })
  createEffect(() => { if (props.focused && !props.disabled) scroll()?.focus(); else scroll()?.blur() })
  return <scrollbox flexGrow={props.height === undefined ? 1 : 0} flexShrink={props.height === undefined ? 1 : 0}
    height={props.height} maxHeight={props.maxHeight} minHeight={1} minWidth={0} scrollX={false}
    scrollbarOptions={{ visible: false }} backgroundColor={props.theme.background.base}
    ref={(value) => {
      setScroll(value)
      const resize = () => setHeight(Math.max(1, value.viewport.height))
      value.viewport.on("resize", resize)
      // Initial content layout can follow viewport layout; only then can the
      // scrollbox reveal a previously selected item outside the first page.
      value.content.on("resize", reveal)
      onCleanup(() => {
        value.viewport.off("resize", resize)
        value.content.off("resize", reveal)
      })
      resize()
    }}
    onMouseDown={() => { if (!props.disabled) props.onFocus?.() }}>
    <For each={props.items}>{(item, index) => <box height={rowHeight()} flexShrink={0}
      onMouseMove={() => { if (props.focused) move(index()) }}
      onMouseDown={(event) => { if (event.button === MouseButton.LEFT) move(index()) }}
      onMouseUp={(event) => { if (event.button === MouseButton.LEFT) select(index()) }}>
      <SelectRow theme={props.theme} modern title={item.title} description={item.description} footer={item.footer}
        current={!!item.current} active={props.focused && !props.disabled && selected() === index()} />
    </box>}</For>
  </scrollbox>
}
