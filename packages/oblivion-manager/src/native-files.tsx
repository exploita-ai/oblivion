import path from "node:path"
import { lstat, readdir, stat } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import parse from "shell-quote/parse"
import { createEffect, createSignal, on, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard, usePaste } from "@opentui/solid"
import { z } from "zod"
import { Menu } from "./menu"
import { FormView } from "./form"
import { PageHeader } from "./page-header"
import { BusyModal } from "./busy-modal"
import { ActionBar } from "./action-bar"
import { FilePicker } from "./vendor/termcn/file-picker"
import { theme } from "./theme"
import type { NativeRuntime } from "./native-control"
import { createFileTransfers, fileOutcome, type FileOutcome, type FileTransfer } from "./native-file-transfers"

const unsafePathText = /[\p{Cc}\p{Bidi_Control}\p{Zl}\p{Zp}]/u

const directory = z.object({
  path: z.string(), entries: z.array(z.object({ name: z.string(), path: z.string(), kind: z.enum(["directory", "file"]), bytes: z.number().nonnegative() })),
  next_cursor: z.string().nullable(), skipped: z.number().optional(),
})

export function NativeFiles(props: { safe: string; name: string; opening?: string; blocked?: string; transfers?: ReturnType<typeof createFileTransfers>; runtime: NativeRuntime; run: (args: string[]) => Promise<boolean>; back: () => void }) {
  const transfers = props.transfers ?? createFileTransfers()
  const [page, setPage] = createSignal<"menu" | "source" | "guest" | "destination" | "name" | "confirm" | "records" | "outcome" | "recover" | "discard">("menu")
  const [selected, setSelected] = createSignal(0)
  const [operation, setOperation] = createSignal<"import" | "export">("import")
  const [source, setSource] = createSignal("")
  const [destination, setDestination] = createSignal("")
  const [name, setName] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [transaction, setTransaction] = createSignal<string>()
  const [observed, setObserved] = createSignal<FileOutcome>()
  const [confirmation, setConfirmation] = createSignal<FileOutcome>()
  const [working, setWorking] = createSignal(false)
  let stopped = false
  const records = () => transfers.entries().filter((entry) => entry.safe === props.safe)
  const current = () => records().find((entry) => entry.id === transaction())
  const generation = () => `${props.safe}/${props.opening ?? ""}`
  const recoverable = () => !!current() && !props.blocked && observed()?.state === "ready" && observed()?.can_recover
  const discardable = () => !!current() && !props.blocked && ["ready", "incomplete"].includes(observed()?.state ?? "") && observed()?.can_discard

  async function read(entry: FileTransfer) {
    const expected = generation()
    const state = await props.runtime.status()
    const opened = state.idle_lock.safes.find((safe) => safe.opening.safe_id === entry.safe && !safe.closing)?.opening
    if (stopped || !state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opened || props.opening && props.opening !== opened.nonce || expected !== generation()) throw new Error("Safe opening unavailable")
    const result = fileOutcome.parse(await props.runtime.query(["files", "status", "--safe", entry.safe, "--operation", entry.id, "--opening", opened.nonce,
      ...(entry.kind === "export" ? ["--destination", entry.destination] : []), "--json"]))
    if (expected !== generation() || entry.safe !== props.safe || result.operation_id !== entry.id || result.safe_id !== entry.safe || result.opening !== opened.nonce || result.source_opening && result.source_opening !== entry.opening) throw new Error("Copy identity changed")
    return result
  }

  async function refresh() {
    const entry = current()
    if (!entry || working() || stopped) return
    const expected = generation()
    setWorking(true)
    try {
      const result = await read(entry)
      if (!stopped && expected === generation() && current()?.id === entry.id) { setObserved(result); setNotice("") }
      return result
    } catch {
      if (!stopped && expected === generation()) { setObserved(undefined); setNotice("Recorded status is unavailable. The destination may already contain this copy. Inspect it before trying another copy.") }
    } finally { if (!stopped) setWorking(false) }
  }

  async function inspect(entry: FileTransfer) {
    if (working()) return
    setTransaction(entry.id); setObserved(undefined); setConfirmation(undefined); setNotice(""); setPage("outcome")
    try {
      if (!await props.run(["safe", "open", props.safe])) { setNotice("Open this Safe to inspect the recorded outcome. No copy will be retried automatically."); return }
      await refresh()
    } catch { if (!stopped) setNotice("The Safe could not be opened. Keep the operation ID; no copy will be retried automatically.") }
  }

  async function confirm() {
    if (working() || props.blocked) return
    const safe = props.safe
    setWorking(true)
    try {
      if (!await props.run(["safe", "open", safe]) || stopped || props.safe !== safe) return
      const expected = generation()
      const state = await props.runtime.status()
      if (stopped || expected !== generation()) return
      const opened = state.idle_lock.safes.find((entry) => entry.opening.safe_id === safe && !entry.closing)?.opening
      if (!state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opened) { setNotice("The Safe is no longer available. Reopen it before copying."); return }
      if (props.opening && props.opening !== opened.nonce) { setNotice("The Safe opening changed. Refresh Files and review the copy again."); return }
      const entry: FileTransfer = { id: crypto.randomUUID().replaceAll("-", ""), safe, opening: opened.nonce, kind: operation(), source: source(), destination: operation() === "import" ? `workspace/${name()}` : destination() }
      // Remember the operation before the CLI can mutate either destination.
      transfers.remember(entry)
      setTransaction(entry.id); setObserved(undefined); setPage("outcome")
      const args = entry.kind === "import"
        ? ["files", "import", "--safe", entry.safe, entry.source, "--name", name()]
        : ["files", "export", "--safe", entry.safe, entry.source, entry.destination]
      try { await props.run([...args, "--operation", entry.id, "--opening", opened.nonce]) }
      catch { /* A lost command result cannot prove whether publication happened. */ }
    } catch { if (!stopped) setNotice("The copy could not be prepared. Check the runtime before confirming again.") }
    finally { if (!stopped) { setWorking(false); if (page() === "outcome") await refresh() } }
  }

  async function prepare(action: "recover" | "discard") {
    if (working() || props.blocked) return
    const result = await refresh()
    if (!result || stopped || (action === "recover" ? !recoverable() : !discardable())) return
    setConfirmation(result); setPage(action)
  }

  async function execute() {
    const entry = current()
    const reviewed = confirmation()
    const action = page()
    if (!entry || !reviewed || working() || props.blocked || !["recover", "discard"].includes(action)) return
    const result = await refresh()
    if (!result || stopped) return
    if (JSON.stringify(result) !== JSON.stringify(reviewed) || (action === "recover" ? !recoverable() : !discardable())) {
      setConfirmation(undefined); setPage("outcome"); setNotice("The recorded outcome changed. Review its current state before continuing."); return
    }
    setWorking(true); setPage("outcome"); setConfirmation(undefined)
    try {
      await props.run(["files", action, "--safe", entry.safe, "--operation", entry.id, "--opening", result.opening,
        ...(entry.kind === "export" ? ["--destination", entry.destination] : []), "--json"])
    } catch { /* Always inspect authoritative status after a lost reply. */ }
    finally { if (!stopped) { setWorking(false); await refresh() } }
  }

  function back() {
    if (working()) return
    if (page() === "menu") { props.back(); return }
    if (page() === "recover" || page() === "discard") { setConfirmation(undefined); setPage("outcome"); return }
    setPage("menu"); setSelected(0)
  }

  const actions = () => [
    { name: "Import", description: "Choose one local file or folder. A verified copy is published into this Safe's writable workspace.", action: "Choose source", disabled: props.blocked, run: () => { setOperation("import"); setPage("source") } },
    { name: "Export", description: "Choose a file or folder under workspace or imports, then a destination on this computer.", action: "Choose Safe files", disabled: props.blocked, run: () => { void props.run(["safe", "open", props.safe]).then((ok) => { if (ok) { setOperation("export"); setPage("guest") } }) } },
    { name: "Transfers and recovery", description: "Inspect this manager's recorded operation IDs. Verify an uncertain outcome, publish verified staging without copying again, or explicitly discard incomplete staging.", action: "Inspect transfers", run: () => { setSelected(0); setPage("records") } },
  ]
  const label = () => observed()?.state === "published" ? "Copy completed and verified."
    : observed()?.state === "ready" ? "Verified copy · publication unconfirmed"
    : observed()?.state === "incomplete" ? "Copy incomplete · inspect staging"
    : observed()?.state === "discarded" ? "Private staging discarded"
    : "Outcome unknown · inspect before another copy"
  const description = () => { const entry = current(); return entry ? `${entry.kind === "import" ? "Import" : "Export"} · ${props.name}\nOperation ${entry.id}` : "Choose a recorded operation." }

  createEffect(on(() => [props.safe, props.opening], () => { setObserved(undefined); setConfirmation(undefined); if (["recover", "discard"].includes(page())) setPage("outcome") }, { defer: true }))
  createEffect(() => { if (transaction() && !current()) { setObserved(undefined); setConfirmation(undefined); setTransaction(undefined); setPage("records") } })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (key.name === "escape" && ["menu", "records", "outcome"].includes(page())) { key.preventDefault(); back(); return }
    if (page() !== "outcome") return
    if (key.name === "r") { key.preventDefault(); void refresh() }
    if (key.name === "c" && recoverable()) { key.preventDefault(); void prepare("recover") }
    if (key.name === "d" && discardable()) { key.preventDefault(); void prepare("discard") }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={page() === "menu"}><Menu title="Files" description={`${props.name} · Explicit copies between this computer and this Safe.`}
      items={actions()} selected={selected()} change={setSelected} focused disabled={working()} choose={(index) => { const action = actions()[index]; if (!action?.disabled) action?.run() }} back={props.back} />
      <text fg={theme.text.muted}>Agents running in another terminal keep working. Files are shared by agents in this Safe.</text>
    </Show>
    <Show when={page() === "records"}><Menu title="File transfers" description="The latest 32 operations stay in this manager's RAM. No automatic retries. Keep an operation ID for CLI inspection after closing the manager."
      items={records().map((entry) => ({ name: `${entry.kind === "import" ? "Import" : "Export"} ${path.basename(entry.source)}`, badge: entry.id.slice(0, 8), description: `Operation ${entry.id}\nFrom ${entry.source}\nTo ${entry.destination}`, action: "Inspect outcome", run: () => { void inspect(entry) } }))}
      selected={selected()} change={setSelected} focused disabled={working()} choose={(index) => { const entry = records()[index]; if (entry) void inspect(entry) }} back={back} empty="No operations recorded in this manager yet." /></Show>
    <Show when={page() === "outcome"}><PageHeader title="Copy outcome" description={description()} />
      <scrollbox flexGrow={1} minHeight={0}><box flexDirection="column" gap={1}>
        <text fg={observed()?.state === "published" ? theme.feedback.success : theme.feedback.warning}>{label()}</text>
        <text fg={theme.text.muted}>{`From · ${current()?.source}\nTo · ${current()?.destination}`}</text>
        <Show when={observed()?.receipt}>{(receipt) => <text fg={theme.text.muted}>{`${receipt().entries} entries · ${receipt().bytes.toLocaleString("en-US")} B\nSHA-256 ${receipt().manifest_sha256}`}</text>}</Show>
        <Show when={observed()?.state === "published"}><text fg={theme.text.muted}>Recorded publication receipt. Later changes to destination files are not checked.</text></Show>
        <Show when={observed()?.source_opening && observed()?.source_opening !== observed()?.opening}><text fg={theme.feedback.info}>This copy belongs to an earlier opening. Its status was checked against the current Safe opening.</text></Show>
        <Show when={!observed() || observed()?.state === "unknown"}><text fg={theme.text.muted}>The copy may have reached its destination. Check recorded status and the destination before creating another operation.</text></Show>
        <Show when={props.blocked}><text fg={theme.feedback.warning}>{props.blocked}</text></Show>
      </box></scrollbox>
      <ActionBar focused disabled={working()} actions={[
        { title: "Refresh status", key: "R", run: () => { void refresh() } },
        ...(recoverable() ? [{ title: "Recover verified copy", key: "C", run: () => { void prepare("recover") } }] : []),
        ...(discardable() ? [{ title: "Discard staging", key: "D", run: () => { void prepare("discard") } }] : []),
        { title: "Back", key: "Esc", run: back },
      ]} />
    </Show>
    <Show when={page() === "recover" || page() === "discard"}><FormView form={{ title: page() === "recover" ? "Publish verified copy?" : "Discard incomplete copy?",
      description: `${description()}\nDestination · ${current()?.destination}\n${page() === "recover" ? "Confirm publication using the verified copy. No source files are copied again; an existing destination is never overwritten." : "Remove only this operation's private staging. Published files and other operations are kept."}`,
      fields: [], submit: page() === "recover" ? "Publish verified copy" : "Discard private staging", run: async () => {},
    }} cancel={back} submit={() => { void execute() }} /></Show>
    <Show when={page() === "source" || page() === "destination"}><LocalChooser directoryOnly={page() === "destination"} back={back} choose={(value) => {
      if (page() === "source") { setSource(value); setName(path.basename(value)); setPage("name"); return }
      setDestination(value); setPage("confirm")
    }} /></Show>
    <Show when={page() === "guest"}><GuestChooser safe={props.safe} runtime={props.runtime} back={back} choose={(value) => { setSource(value); setPage("destination") }} /></Show>
    <Show when={page() === "name"}><FormView form={{ title: "Name the imported copy", description: `Source on this computer · ${source()}`, fields: [{ id: "name", label: "Workspace name", value: name(), validate: (value) => !value || unsafePathText.test(value) || value.includes("/") || value.includes("\\") || value === "." || value === ".." || Buffer.byteLength(value) > 255 ? "Choose a single file or folder name." : undefined }], submit: "Review copy", run: async () => {} }} cancel={back} submit={(values) => { setName(values.name); setPage("confirm") }} /></Show>
    <Show when={page() === "confirm"}><FormView form={{ title: operation() === "import" ? "Confirm import" : "Confirm export",
      description: operation() === "import" ? `From this computer · ${source()}\nTo Safe ${props.name} · workspace/${name()}` : `From Safe ${props.name} · ${source()}\nTo this computer · ${path.join(destination(), path.basename(source()))}`,
      fields: [], submit: operation() === "import" ? "Import copy" : "Export copy", run: async () => {},
    }} cancel={back} submit={() => { void confirm() }} /></Show>
    <Show when={props.blocked && page() !== "outcome"}><text flexShrink={0} fg={theme.feedback.warning}>{props.blocked}</text></Show>
    <Show when={notice()}><text flexShrink={0} fg={theme.feedback.warning}>{notice()}</text></Show>
    <Show when={working()}><BusyModal text={page() === "outcome" ? "Checking copy outcome" : "Preparing copy"} /></Show>
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
  const [view, setView] = createSignal<"browse" | "path" | "review">("browse")
  const [entered, setEntered] = createSignal("")
  const [candidate, setCandidate] = createSignal<{ path: string; directory: boolean; bytes: number }>()
  let stopped = false

  function enterPath() { setError(""); setView("path") }
  function cancelPath() { setCandidate(undefined); setError(""); setView("browse") }
  function browseCandidate() { const value = candidate(); if (!value?.directory || working()) return; setView("browse"); void load(value.path) }
  function useCandidate() { const value = candidate(); if (!value || working() || props.filesOnly && value.directory) return; props.choose(value.path) }

  async function inspect(value: string) {
    if (working()) return
    setEntered(value)
    setWorking(true)
    setError("")
    try {
      const selected = await localPath(value, current())
      const info = selected.info
      if (stopped) return
      if (info.isSymbolicLink() || !info.isDirectory() && !info.isFile()) { setError("Choose a regular local file or directory. Symbolic links are not selectable."); return }
      if (props.directoryOnly && !info.isDirectory()) { setError("This operation requires a directory. Choose a local folder."); return }
      setCandidate({ path: selected.path, directory: info.isDirectory(), bytes: info.size })
      setView("review")
    } catch { if (!stopped) setError("Enter one existing local path or local file:// URL. Controls, remote authorities and multiple paths are not accepted.") }
    finally { if (!stopped) setWorking(false) }
  }

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
      const available = (await readdir(next, { withFileTypes: true })).filter((item) => (item.isDirectory() || !props.directoryOnly && item.isFile()) && !unsafePathText.test(item.name)).sort((a, b) => Number(b.isDirectory()) - Number(a.isDirectory()) || a.name.localeCompare(b.name))
      const page = await Promise.all(available.slice(start, start + 100).map(async (item) => ({ name: item.name, directory: item.isDirectory(), bytes: item.isFile() ? (await stat(path.join(next, item.name))).size : 0 })))
      if (stopped) return
      setCurrent(next); setEntries(page); setOffset(start); setTotal(available.length); setSelected(0); setError("")
    } catch { if (!stopped) setError("This directory cannot be read. Choose another location.") }
    finally { if (!stopped) setWorking(false) }
  }
  onMount(() => { void load(current()) })
  onCleanup(() => { stopped = true })
  usePaste((event) => {
    if (view() !== "path") return
    if (!unsafePathText.test(new TextDecoder().decode(event.bytes))) return
    event.preventDefault()
    setError("Paste one path without control characters or line breaks.")
  })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (view() === "path") return
    if (view() === "review") {
      if (key.name === "b" && candidate()?.directory) { key.preventDefault(); browseCandidate() }
      return
    }
    if (key.name === "escape") { key.preventDefault(); props.back(); return }
    if (key.name === "p") { key.preventDefault(); enterPath(); return }
    if (key.name === "backspace") { key.preventDefault(); void load(path.dirname(current())); return }
    if (key.name === "." && props.directoryOnly) { key.preventDefault(); props.choose(current()); return }
    if (key.name === "space") { key.preventDefault(); const entry = entries()[selected()]; if (entry && (!props.filesOnly || !entry.directory)) props.choose(path.join(current(), entry.name)); return }
    if (key.name === "pagedown" && offset() + 100 < total()) { key.preventDefault(); void load(current(), offset() + 100) }
    if (key.name === "pageup" && offset()) { key.preventDefault(); void load(current(), Math.max(0, offset() - 100)) }
  })
  return <box flexGrow={1} minHeight={0} flexDirection="column">
    <Show when={view() === "path"}><FormView form={{ title: "Enter local path", description: "Paste one path, local file:// URL or terminal-dropped path. POSIX quoting is accepted without shell expansion. Nothing is copied until you choose and review it.",
      fields: [{ id: "path", label: "File or directory on this computer", value: entered(), validate: (value) => !value || unsafePathText.test(value) ? "Enter one path without control characters or line breaks." : undefined }],
      submit: "Inspect path", run: async () => {} }} cancel={cancelPath} submit={(values) => { void inspect(values.path) }} /></Show>
    <Show when={view() === "review" && candidate()}><FormView form={{ title: "Review local path", description: `${candidate()?.path}\n${candidate()?.directory ? "Directory" : `Regular file · ${candidate()?.bytes.toLocaleString("en-US")} B`}\n${props.filesOnly && candidate()?.directory ? "This operation accepts files. Browse this folder to choose one." : "Choose this path to continue to the operation's review. No copy has started."}`,
      fields: [], submit: props.filesOnly && candidate()?.directory ? "Browse folder" : candidate()?.directory ? "Choose folder" : "Choose file", run: async () => {} }} cancel={cancelPath} submit={() => { if (props.filesOnly && candidate()?.directory) { browseCandidate(); return }; useCandidate() }} /></Show>
    <Show when={view() === "review" && candidate()?.directory && !props.filesOnly}><ActionBar actions={[{ title: "Browse folder", key: "B", disabled: working(), run: browseCandidate }]} /></Show>
    <Show when={view() === "browse"}><Menu title={props.title ?? (props.directoryOnly ? "Choose destination directory" : "Choose a local file or folder")} description={`${current()}\n${props.filesOnly ? "Space chooses a file" : "Space chooses an entry"} · Enter opens folders · ${total()} entries`} selected={selected()} change={setSelected} focused disabled={working()}
    items={entries().map((entry, index) => ({ name: `${entry.name}${entry.directory ? "/" : ""}`, badge: entry.directory ? "Folder" : `${entry.bytes.toLocaleString("en-US")} B`, description: "", run: () => choose(index) }))}
    choose={choose}
    toolbar={[
      { title: "Enter path", key: "P", run: enterPath },
      { title: "Parent", key: "Backspace", run: () => { void load(path.dirname(current())) } },
      ...(props.directoryOnly ? [{ title: "Use this folder", key: ".", run: () => props.choose(current()) }] : []),
      { title: "Previous", key: "PageUp", disabled: offset() === 0, run: () => { void load(current(), Math.max(0, offset() - 100)) } },
      { title: "Next", key: "PageDown", disabled: offset() + 100 >= total(), run: () => { void load(current(), offset() + 100) } },
    ]}
    empty={error() || (working() ? "Reading directory…" : "No selectable entries. Backspace opens the parent directory.")}
    details={false} back={props.back} /></Show><Show when={error()}><text flexShrink={0} fg={theme.feedback.warning}>{error()}</text></Show><Show when={working()}><BusyModal text="Reading local path" /></Show></box>
}

async function localPath(input: string, current: string) {
  if (!input || unsafePathText.test(input)) throw new Error("Invalid path")
  // A real native filename wins over terminal escaping, including literal
  // backslashes, quotes, spaces and $. Only absence permits interpretation.
  const literal = path.resolve(current, input)
  const info = await lstat(literal).catch((error: unknown) => {
    if (error instanceof Error && "code" in error && (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "ENAMETOOLONG")) return
    throw error
  })
  if (info) return { path: literal, info }
  const spelling = input.trim()
  const value = /^file:/i.test(spelling) ? spelling : terminalPath(spelling)
  if (/^file:/i.test(value)) {
    const url = new URL(value)
    if (url.hostname && url.hostname !== "localhost" || url.search || url.hash) throw new Error("Local URL required")
    const decoded = fileURLToPath(url)
    if (unsafePathText.test(decoded)) throw new Error("Invalid path")
    return { path: decoded, info: await lstat(decoded) }
  }
  const resolved = path.resolve(current, value)
  return { path: resolved, info: await lstat(resolved) }
}

function terminalPath(input: string) {
  // shell-quote intentionally tolerates incomplete quotes. Restrict its input
  // to one complete POSIX word, then delegate decoding to the maintained parser.
  // Expansion, commands, comments and unquoted glob syntax are not this field.
  if (!/^(?:[^ '"\\$`|&;()<>*?#{}~]|\\[^\n]|'[^']*'|"(?:[^"\\$`]|\\[^\n])*")+ *$/.test(input)) throw new Error("Enter one complete path")
  const words = parse(input, () => { throw new Error("Shell expansion is not supported") })
  if (words.length !== 1 || typeof words[0] !== "string" || !words[0]) throw new Error("Enter one path")
  if (unsafePathText.test(words[0])) throw new Error("Invalid path")
  return words[0]
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
