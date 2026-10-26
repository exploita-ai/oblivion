// Adapted from termcn's MIT OpenTUI FilePicker. See LICENSE and PROVENANCE.md.
// Solid port: directory metadata is supplied by the VM, never node:fs on the host.
import { useKeyboard } from "@opentui/solid"
import { createMemo, createSignal, Show } from "solid-js"
import { palette, theme } from "../../theme"
import { SelectList } from "@opencode/tui-kit"

export type FileEntry = { name: string; path: string; directory: boolean; bytes: number }

export function FilePicker(props: {
  currentDir: string
  entries: FileEntry[]
  selected: string[]
  focused: boolean
  busy?: boolean
  next?: boolean
  previous?: boolean
  onFocus?: () => void
  onNavigate: (path: string) => void
  onChange: (paths: string[]) => void
  onNext: () => void
  onPrevious?: () => void
  onBack: () => void
}) {
  const [cursor, setCursor] = createSignal(0)
  const parentEntry = () => ({ name: "..", path: props.currentDir.split("/").slice(0, -1).join("/"), directory: true, bytes: 0 })
  const allEntries = createMemo(() => [...(props.currentDir ? [parentEntry()] : []), ...props.entries])
  const selected = () => new Set(props.selected)

  function toggle(entry: FileEntry) {
    if (entry.name === "..") return
    props.onChange(selected().has(entry.path) ? props.selected.filter((path) => path !== entry.path) : [...props.selected, entry.path])
  }

  useKeyboard((key) => {
    if (key.defaultPrevented || !props.focused || props.busy) return
    if (key.name === "escape") { key.preventDefault(); props.onBack(); return }
    if (key.name === "space" || key.sequence === " ") {
      key.preventDefault()
      const entry = allEntries()[cursor()]
      if (entry) toggle(entry)
    }
  })

  return <box flexGrow={1} flexShrink={1} flexBasis={0} minWidth={0} minHeight={4} flexDirection="column">
    <box height={2} flexShrink={0} border={["bottom"]} borderColor={props.focused ? theme.border.focused : theme.border.base} paddingLeft={1} paddingRight={1}>
      <text fg={theme.text.base}><b>/{props.currentDir}</b></text>
    </box>
    <SelectList theme={palette} focused={props.focused} disabled={props.busy} selected={cursor()} onFocus={props.onFocus}
      items={[
        ...allEntries().map((entry) => ({ title: `${entry.name === ".." ? "   " : selected().has(entry.path) ? "[x]" : "[ ]"} ${entry.directory ? "/" : " "} ${entry.name}${entry.directory ? "/" : ""}`, footer: entry.directory ? "Folder" : `${entry.bytes.toLocaleString("en-US")} B` })),
        ...(props.previous ? [{ title: "← Previous page" }] : []),
        ...(props.next ? [{ title: "Next page →" }] : []),
      ]}
      onChange={setCursor}
      onSelect={(index) => {
        const entry = allEntries()[index]
        if (!entry) { setCursor(0); if (props.previous && index === allEntries().length) { props.onPrevious?.(); return }; props.onNext(); return }
        if (entry.directory) { setCursor(0); props.onNavigate(entry.path); return }
        toggle(entry)
      }} />
    <Show when={props.entries.length === 0 && !props.busy}><text fg={theme.text.muted}>No files in this directory.</text></Show>
    <text minHeight={1} flexShrink={0} fg={theme.text.muted}>{props.busy ? "Reading directory..." : `${props.selected.length} selected · ↑↓ move · Enter open · Space select · Esc back`}</text>
  </box>
}
