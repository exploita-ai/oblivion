import { createEffect, For } from "solid-js"
import type { ScrollBoxRenderable } from "@opentui/core"
import { theme } from "./theme"

export type SessionTab = { slot: number; title: string; mode: string | null; recovery: boolean }

export function SessionTabs(props: {
  sessions: SessionTab[]; selected: number; disabled: boolean; select: (slot: number) => void
}) {
  let scroll: ScrollBoxRenderable | undefined
  let reveal = true
  createEffect(() => { props.selected; props.sessions; reveal = true })
  const showSelected = () => {
    if (!reveal || !scroll) return
    const tab = scroll.content.findDescendantById(`session-tab-${props.selected}`)
    if (!tab || !tab.width) return
    reveal = false
    scroll.scrollChildIntoView(tab.id)
  }
  return <box renderAfter={showSelected} flexShrink={0} height={3} border={["bottom"]} borderColor={theme.border.base} paddingLeft={1} paddingRight={1}>
    <scrollbox ref={scroll} scrollX scrollY={false} flexGrow={1} onSizeChange={() => { reveal = true }} contentOptions={{ flexDirection: "row", gap: 2, maxWidth: undefined }}>
      <For each={[{ slot: 0, title: "Sessions", mode: null, recovery: false }, ...props.sessions]}>{(session) =>
        <box id={`session-tab-${session.slot}`} flexShrink={0} height={1} paddingLeft={1} paddingRight={1}
          backgroundColor={props.selected === session.slot ? theme.background.selection : theme.background.base}
          onMouseDown={() => { if (!props.disabled) props.select(session.slot) }}>
          <text wrapMode="none" fg={props.selected === session.slot ? theme.navigation.focused : theme.navigation.inactive}>
            {`${props.selected === session.slot ? "› " : "  "}${session.title}${session.recovery ? " · Recovery" : session.mode === "starting" ? " · Starting" : session.mode === "documents" ? " · Offline" : ""}`}
          </text>
        </box>
      }</For>
    </scrollbox>
  </box>
}

export function sessionSocket(path: string, slot = 0) {
  if (!Number.isInteger(slot) || slot < 0 || slot >= 32) throw new Error("invalid_session_slot")
  if (!slot) return path
  return path.replace(/^\/run\/(oblivion-(?:transfer|onion)-host)(\/|$)/, `/run/$1-s${slot}$2`)
}
