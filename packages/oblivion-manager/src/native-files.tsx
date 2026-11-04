import path from "node:path"
import { readdir, stat } from "node:fs/promises"
import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard } from "@opentui/solid"
import { z } from "zod"
import { Menu } from "./menu"
import { FormView } from "./form"
import { PageHeader } from "./page-header"
import { BusyModal } from "./busy-modal"
import { FilePicker } from "./vendor/termcn/file-picker"
import { theme } from "./theme"
import type { NativeRuntime } from "./native-control"

const directory = z.object({
  path: z.string(), entries: z.array(z.object({ name: z.string(), path: z.string(), kind: z.enum(["directory", "file"]), bytes: z.number().nonnegative() })),
  next_cursor: z.string().nullable(), skipped: z.number().optional(),
})

export function NativeFiles(props: { safe: string; name: string; runtime: NativeRuntime; run: (args: string[]) => Promise<boolean>; back: () => void }) {
  const [page, setPage] = createSignal<"menu" | "source" | "guest" | "destination" | "name" | "confirm">("menu")
  const [selected, setSelected] = createSignal(0)
  const [operation, setOperation] = createSignal<"import" | "export">("import")
  const [source, setSource] = createSignal("")
  const [destination, setDestination] = createSignal("")
  const [name, setName] = createSignal("")
  const [notice, setNotice] = createSignal("")
  useKeyboard((key) => { if (!key.defaultPrevented && key.name === "escape" && page() === "menu") { key.preventDefault(); props.back() } })
  const actions = () => [
    { name: "Import", description: "Choose one local file or folder. A verified copy is published into this Safe's writable workspace.", action: "Choose source", run: () => { setOperation("import"); setPage("source") } },
    { name: "Export", description: "Choose a file or folder under workspace or imports, then a destination on this computer.", action: "Choose Safe files", run: () => { void props.run(["safe", "open", props.safe]).then((ok) => { if (ok) { setOperation("export"); setPage("guest") } }) } },
  ]

  async function confirm() {
    if (!await props.run(["safe", "open", props.safe])) return
    const args = operation() === "import"
      ? ["files", "import", "--safe", props.safe, source(), "--name", name()]
      : ["files", "export", "--safe", props.safe, source(), destination()]
    const ok = await props.run(args)
    setNotice(ok ? "Copy completed and verified." : "The copy did not complete. Its destination was not replaced.")
    setPage("menu")
  }

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={page() === "menu"}><Menu title="Files" description={`${props.name} · Explicit copies between this computer and this Safe.`}
      items={actions()} selected={selected()} change={setSelected} focused choose={(index) => actions()[index]?.run()} back={props.back} />
      <text fg={theme.text.muted}>Agents running in another terminal keep working. Files are shared by agents in this Safe.</text>
      <Show when={notice()}><text fg={theme.feedback.info}>{notice()}</text></Show>
    </Show>
    <Show when={page() === "source" || page() === "destination"}><LocalChooser directoryOnly={page() === "destination"} back={() => setPage("menu")} choose={(value) => {
      if (page() === "source") { setSource(value); setName(path.basename(value)); setPage("name"); return }
      setDestination(value); setPage("confirm")
    }} /></Show>
    <Show when={page() === "guest"}><GuestChooser safe={props.safe} runtime={props.runtime} back={() => setPage("menu")} choose={(value) => { setSource(value); setPage("destination") }} /></Show>
    <Show when={page() === "name"}><FormView form={{ title: "Name the imported copy", description: `Source on this computer · ${source()}`, fields: [{ id: "name", label: "Workspace name", value: name(), validate: (value) => !value || value.includes("/") || value.includes("\\") || value === "." || value === ".." || Buffer.byteLength(value) > 255 ? "Choose a single file or folder name." : undefined }], submit: "Review copy", run: async () => {} }} cancel={() => setPage("menu")} submit={(values) => { setName(values.name); setPage("confirm") }} /></Show>
    <Show when={page() === "confirm"}><FormView form={{
      title: operation() === "import" ? "Confirm import" : "Confirm export",
      description: operation() === "import" ? `From this computer · ${source()}\nTo Safe ${props.name} · workspace/${name()}` : `From Safe ${props.name} · ${source()}\nTo this computer · ${path.join(destination(), path.basename(source()))}`,
      fields: [], submit: operation() === "import" ? "Import copy" : "Export copy", run: async () => {},
    }} cancel={() => setPage("menu")} submit={() => { void confirm() }} /></Show>
  </box>
}

export function LocalChooser(props: { directoryOnly: boolean; filesOnly?: boolean; title?: string; initialDirectory?: string; choose: (value: string) => void; back: () => void }) {
  const [current, setCurrent] = createSignal(props.initialDirectory ?? process.cwd())
  const [entries, setEntries] = createSignal<{ name: string; directory: boolean; bytes: number }[]>([])
  const [selected, setSelected] = createSignal(0)
  const [offset, setOffset] = createSignal(0)
  const [total, setTotal] = createSignal(0)
  const [error, setError] = createSignal("")
  const [working, setWorking] = createSignal(false)
  let stopped = false

  function choose(index: number) {
    if (working()) return
    const entry = entries()[index]
    if (!entry) return
    if (entry.directory) { void load(path.join(current(), entry.name)); return }
    props.choose(path.join(current(), entry.name))
  }

  async function load(next: string, start = 0) {
    if (working()) return
    setWorking(true)
    try {
      const available = (await readdir(next, { withFileTypes: true })).filter((item) => (item.isDirectory() || !props.directoryOnly && item.isFile()) && !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(item.name)).sort((a, b) => Number(b.isDirectory()) - Number(a.isDirectory()) || a.name.localeCompare(b.name))
      const page = await Promise.all(available.slice(start, start + 100).map(async (item) => ({ name: item.name, directory: item.isDirectory(), bytes: item.isFile() ? (await stat(path.join(next, item.name))).size : 0 })))
      if (stopped) return
      setCurrent(next); setEntries(page); setOffset(start); setTotal(available.length); setSelected(0); setError("")
    } catch { if (!stopped) setError("This directory cannot be read. Choose another location.") }
    finally { if (!stopped) setWorking(false) }
  }
  onMount(() => { void load(current()) })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (key.name === "escape") { key.preventDefault(); props.back(); return }
    if (key.name === "backspace") { key.preventDefault(); void load(path.dirname(current())); return }
    if (key.name === "." && props.directoryOnly) { key.preventDefault(); props.choose(current()); return }
    if (key.name === "space") { key.preventDefault(); const entry = entries()[selected()]; if (entry && (!props.filesOnly || !entry.directory)) props.choose(path.join(current(), entry.name)); return }
    if (key.name === "pagedown" && offset() + 100 < total()) { key.preventDefault(); void load(current(), offset() + 100) }
    if (key.name === "pageup" && offset()) { key.preventDefault(); void load(current(), Math.max(0, offset() - 100)) }
  })
  return <box flexGrow={1} minHeight={0}><Menu title={props.title ?? (props.directoryOnly ? "Choose destination directory" : "Choose a local file or folder")} description={`${current()}\n${props.filesOnly ? "Space chooses a file" : "Space chooses an entry"} · Enter opens folders · ${total()} entries`} selected={selected()} change={setSelected} focused disabled={working()}
    items={entries().map((entry, index) => ({ name: `${entry.name}${entry.directory ? "/" : ""}`, badge: entry.directory ? "Folder" : `${entry.bytes.toLocaleString("en-US")} B`, description: "", run: () => choose(index) }))}
    choose={choose}
    toolbar={[
      { title: "Parent", key: "Backspace", run: () => { void load(path.dirname(current())) } },
      ...(props.directoryOnly ? [{ title: "Use this folder", key: ".", run: () => props.choose(current()) }] : []),
      { title: "Previous", key: "PageUp", disabled: offset() === 0, run: () => { void load(current(), Math.max(0, offset() - 100)) } },
      { title: "Next", key: "PageDown", disabled: offset() + 100 >= total(), run: () => { void load(current(), offset() + 100) } },
    ]}
    empty={error() || (working() ? "Reading directory…" : "No selectable entries. Backspace opens the parent directory.")}
    details={false} back={props.back} /><Show when={error()}><text flexShrink={0} fg={theme.feedback.warning}>{error()}</text></Show><Show when={working()}><BusyModal text="Reading folder" /></Show></box>
}

function GuestChooser(props: { safe: string; runtime: NativeRuntime; choose: (value: string) => void; back: () => void }) {
  const [page, setPage] = createSignal<z.infer<typeof directory>>({ path: "", entries: [], next_cursor: null })
  const [cursors, setCursors] = createSignal<string[]>([])
  const [working, setWorking] = createSignal(false)
  const [error, setError] = createSignal("")
  let stopped = false
  async function load(path: string, history: string[] = []) {
    if (working()) return
    setWorking(true)
    try {
      const next = directory.parse(await props.runtime.query(["files", "list", "--safe", props.safe, ...(path ? [path] : []), "--json", ...(history.length ? ["--cursor", history.at(-1)!] : [])]))
      if (!stopped) { setPage(next); setCursors(history); setError("") }
    } catch { if (!stopped) setError("Safe files are unavailable. Return and reopen Files to retry.") }
    finally { if (!stopped) setWorking(false) }
  }
  onMount(() => { void load("") })
  onCleanup(() => { stopped = true })
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <PageHeader title="Choose Safe files" description="Browse workspace or imports. Space selects a file or directory for export." />
    <FilePicker currentDir={page().path} entries={page().entries.map((entry) => ({ ...entry, directory: entry.kind === "directory" }))} selected={[]} focused busy={working()}
      next={!!page().next_cursor} previous={!!cursors().length} onNavigate={(path) => { void load(path) }} onChange={(paths) => { if (!paths[0]) return; if (!paths[0].includes("/")) { void load(paths[0]); return }; props.choose(paths[0]) }}
      onNext={() => { const cursor = page().next_cursor; if (cursor) void load(page().path, [...cursors(), cursor]) }}
      onPrevious={() => { void load(page().path, cursors().slice(0, -1)) }} onBack={props.back} />
    <Show when={error()}><text fg={theme.feedback.warning}>{error()}</text></Show>
    <Show when={working()}><BusyModal text="Reading Safe files" /></Show>
  </box>
}
