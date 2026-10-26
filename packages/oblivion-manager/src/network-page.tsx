import { createSignal, For } from "solid-js"
import { useKeyboard, useTerminalDimensions } from "@opentui/solid"
import { Menu, type MenuItem } from "./menu"
import type { PageAction } from "./action-bar"
import { theme } from "./theme"

export const networkTabs = ["Connection", "Privacy", "Rules"] as const

export function NetworkPage(props: {
  toolbar: PageAction[]; tab: number; changeTab: (tab: number) => void; description: string;
  items: MenuItem[]; selected: number; change: (index: number) => void; choose: (index: number) => void;
  focused: boolean; disabled: boolean; activate: () => void; sidebar: () => void; back: () => void;
}) {
  const dimensions = useTerminalDimensions()
  const spacious = () => dimensions().width >= 110 && dimensions().height >= 32
  const [area, setArea] = createSignal<"tabs" | "actions" | "list">("tabs")
  const activate = (area: "tabs" | "actions" | "list") => { props.activate(); setArea(area) }
  useKeyboard((key) => {
    if (!props.focused || props.disabled || key.defaultPrevented) return
    if (key.name === "tab") {
      key.preventDefault()
      const areas = props.toolbar.length ? ["tabs", "actions", "list"] as const : ["tabs", "list"] as const
      const index = areas.indexOf(area() as "tabs" | "list") + (key.shift ? -1 : 1)
      if (index < 0 || index >= areas.length) { props.sidebar(); setArea("tabs"); return }
      setArea(areas[index]); return
    }
    if (key.name === "escape") { key.preventDefault(); if (area() !== "tabs") { setArea("tabs"); return }; props.back(); return }
    if (area() !== "tabs") return
    if (["left", "right", "up", "down"].includes(key.name)) {
      key.preventDefault()
      props.changeTab((props.tab + (key.name === "left" || key.name === "up" ? 2 : 1)) % 3); return
    }
    if (key.name === "return") { key.preventDefault(); setArea("list") }
  })
  return <box flexDirection="column" flexGrow={1} minHeight={0} gap={spacious() ? 1 : 0}>
    <box flexShrink={0} flexDirection="row" gap={3} marginBottom={spacious() ? 1 : 0}>
      <For each={networkTabs}>{(tab, index) => <box paddingLeft={1} paddingRight={1}
        backgroundColor={props.tab === index() ? theme.background.selection : theme.background.base}
        onMouseDown={() => { if (props.disabled) return; activate("tabs"); props.changeTab(index()) }}>
        <text fg={props.tab === index() ? theme.navigation.active : theme.navigation.inactive}>{props.focused && area() === "tabs" && props.tab === index() ? "› " : "  "}{tab}</text>
      </box>}</For>
    </box>
    <Menu toolbar={props.toolbar} actionsFocused={props.focused && area() === "actions"} focusActions={() => activate("actions")} empty={props.tab === 2 ? "No access rules. Add a rule to control a destination." : "No connections available."} title={networkTabs[props.tab]} description={props.description} items={props.items}
      selected={props.selected} change={props.change} choose={props.choose} disabled={props.disabled}
      focused={props.focused && area() === "list"} focus={() => activate("list")} back={props.back} />
    <text flexShrink={0} fg={theme.text.muted}>← → Sections · Tab Focus · Esc Back</text>
  </box>
}
