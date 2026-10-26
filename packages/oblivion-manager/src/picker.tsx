import { useKeyboard } from "@opentui/solid"
import { createMemo, createSignal, Show } from "solid-js"
import { palette, theme } from "./theme"
import { SelectList } from "@opencode/tui-kit"
import { PageHeader } from "./page-header"

export type Choice = { value: string; label: string; description?: string }
export function Picker(props: { title: string; description: string; choices: Choice[]; selected?: string; choose: (value: string) => void; back: () => void }) {
  const [query, setQuery] = createSignal("")
  const [focus, setFocus] = createSignal<"search" | "list">("search")
  const [selected, setSelected] = createSignal(Math.max(0, props.choices.findIndex((choice) => choice.value === props.selected)))
  const filtered = createMemo(() => props.choices.filter((choice) => `${choice.label} ${choice.value}`.toLocaleLowerCase().includes(query().toLocaleLowerCase())))
  useKeyboard((key) => {
    if (key.name === "escape") { key.preventDefault(); props.back(); return }
    if (key.name === "tab") { key.preventDefault(); setFocus((value) => value === "search" ? "list" : "search"); return }
    if (focus() === "search" && (key.name === "down" || key.name === "up")) { key.preventDefault(); setSelected((value) => Math.max(0, Math.min(filtered().length - 1, value + (key.name === "down" ? 1 : -1)))); setFocus("list") }
  })
  return <box flexGrow={1} minHeight={0}><box width="100%" flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <PageHeader title={props.title} description={props.description} />
    <box flexShrink={0} height={3} borderStyle="single" borderColor={focus() === "search" ? theme.border.focused : theme.border.base} paddingLeft={1} paddingRight={1}>
      <input onMouseDown={() => setFocus("search")} flexGrow={1} focused={focus() === "search"} value={query()} placeholder="Search..." maxLength={128}
        onInput={(value) => { setQuery(value); setSelected(0) }} onSubmit={() => { const choice = filtered()[selected()]; if (choice) props.choose(choice.value) }}
        textColor={theme.text.base} backgroundColor={theme.background.field} focusedBackgroundColor={theme.background.field} />
    </box>
    <SelectList theme={palette} items={filtered().map((choice) => ({ title: choice.label, footer: choice.description }))}
      focused={focus() === "list"} selected={selected()} onFocus={() => setFocus("list")} onChange={setSelected}
      onSelect={(index) => { const choice = filtered()[index]; if (choice) props.choose(choice.value) }} />
    <Show when={!filtered().length}><text fg={theme.feedback.info}>{props.choices.length ? "No matches. Change the search or press Esc to go back." : "No items available. Press Esc to go back."}</text></Show>
    <text flexShrink={0} fg={theme.text.muted}>{filtered().length} options · ↑↓ select · Tab search/list · Enter choose · Esc back</text>
  </box></box>
}
