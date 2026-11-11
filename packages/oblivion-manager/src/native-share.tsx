import path from "node:path"
import { ScrollBoxRenderable } from "@opentui/core"
import { createEffect, createMemo, createSignal, Show, untrack } from "solid-js"
import { useKeyboard, usePaste, useTerminalDimensions } from "@opentui/solid"
import { FormView } from "./form"
import { LocalChooser } from "./native-files"
import { PageHeader } from "./page-header"
import { Menu } from "./menu"
import { BusyModal } from "./busy-modal"
import { ActionBar } from "./action-bar"
import { theme } from "./theme"

export type ShareSelection = { operation: "import" }
  | { operation: "export"; scope: "safe"; safe: string; name: string; closed: boolean; branch?: { count: number; closed: boolean } }
  | { operation: "export"; scope: "all"; count: number; closed: boolean }

type ContentFilter = { kind: "path" | "exclude" | "exclude-chat"; value: string }

export function NativeShare(props: { selection: ShareSelection; run: (args: string[]) => Promise<number>; back: () => void; initialDirectory?: string; opening?: string }) {
  const dimensions = useTerminalDimensions()
  const [page, setPage] = createSignal<"scope" | "choose" | "name" | "review" | "result" | "filters" | "add-filter">(props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch ? "scope" : "choose")
  const [scope, setScope] = createSignal<"safe" | "branch">("safe")
  const [selectedScope, setSelectedScope] = createSignal(0)
  const [directory, setDirectory] = createSignal(props.initialDirectory ?? process.cwd())
  const [source, setSource] = createSignal("")
  const [filename, setFilename] = createSignal(props.selection.operation === "export" ? props.selection.scope === "all" ? "oblivion-all.oblivion-share" : `oblivion-${props.selection.safe.slice(0, 8)}.oblivion-share` : "")
  const [working, setWorking] = createSignal(false)
  const [exitCode, setExitCode] = createSignal<number>()
  const [applySettings, setApplySettings] = createSignal(false)
  const [includeSettings, setIncludeSettings] = createSignal(false)
  const [filters, setFilters] = createSignal<ContentFilter[]>([])
  const [includeChats, setIncludeChats] = createSignal(true)
  const [filterKind, setFilterKind] = createSignal<ContentFilter["kind"]>("path")
  const [selectedFilter, setSelectedFilter] = createSignal(0)
  const [area, setArea] = createSignal<"list" | "actions">("actions")
  const [filterError, setFilterError] = createSignal("")
  const context = createMemo(() => `${props.opening ?? ""}/${props.selection.operation}/${props.selection.operation === "export" ? props.selection.scope === "safe" ? props.selection.safe : "all" : "import"}`)
  let scroll: ScrollBoxRenderable | undefined
  const available = () => props.selection.operation === "import" || props.selection.closed && (props.selection.scope === "all" || scope() !== "branch" || !!props.selection.branch?.closed)
  const sourceLabel = () => props.selection.operation === "import" ? ""
    : props.selection.scope === "all" ? `All ${props.selection.count} persistent Safes`
    : scope() === "branch" ? `Branch ${props.selection.name} · ${props.selection.branch?.count} Safes`
    : `Safe ${props.selection.name} (${props.selection.safe.slice(0, 8)})`
  const scopes = () => props.selection.operation === "export" && props.selection.scope === "safe" ? [
    { name: "This Safe only", description: `Export ${props.selection.name} without its descendants.`, action: "Choose destination", run: () => { setScope("safe"); setPage("choose") } },
    { name: "Safe and descendants", description: `Export this branch of ${props.selection.branch?.count} persistent Safes. Every included Safe must be closed.`, disabled: !props.selection.branch?.closed ? "Close the included descendant Safes first." : undefined, action: "Choose destination", run: () => { if (props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch?.closed) { setScope("branch"); setPage("choose") } } },
  ] : []
  const output = () => path.join(directory(), filename())
  const shareAll = () => props.selection.operation === "export" && props.selection.scope === "all"
  const exportCancelled = () => props.selection.operation === "export" && exitCode() === 130
  const selectorArgs = () => props.selection.operation !== "export" ? [] : props.selection.scope === "all" ? ["--all"] : [scope() === "branch" ? "--branch" : "--safe", props.selection.safe]
  const filterText = () => [
    `Include conversations: ${includeChats() ? "Yes" : "No (--no-chats)"}`,
    ...(filters().some((entry) => entry.kind === "path") ? [] : ["Included paths (default): workspace, imports"]),
    ...filters().map((entry) => `--${entry.kind} ${entry.value}`),
  ].join("\n")

  function review() { setPage("review"); setArea("actions") }
  function contentFilters() { if (props.selection.operation !== "export" || working()) return; setPage("filters"); setArea("list") }
  function addFilter(kind: ContentFilter["kind"]) { if (filters().length >= 32 || working()) return; setFilterError(""); setFilterKind(kind); setPage("add-filter") }
  function removeFilter() { setFilters((before) => before.filter((_, index) => index !== selectedFilter())); setSelectedFilter((before) => Math.max(0, before - 1)) }

  function validateFilter(value: string) {
    if (filters().length >= 32 || filters().reduce((bytes, entry) => bytes + Buffer.byteLength(entry.value), Buffer.byteLength(value)) > 8192) return "Use at most 32 filters and 8192 UTF-8 bytes in total."
    if (filters().some((entry) => entry.kind === filterKind() && entry.value === value)) return "This exact filter is already listed."
    if (filterKind() === "exclude-chat") return /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value) ? undefined : "Enter one lowercase Share conversation reference, not a native agent ID."
    const components = value.split("/")
    return !value || Buffer.byteLength(value) > 4096 || /[\\\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(value) || !["workspace", "imports"].includes(components[0]) || components.length > 32 || components.some((part) => !part || part === "." || part === ".." || Buffer.byteLength(part) > 255)
      ? "Enter one literal workspace or imports path, without empty, dot or parent components."
      : undefined
  }

  async function confirm() {
    if (working() || !available()) return
    const generation = `${context()}/${scope()}/${source()}`
    setWorking(true)
    try {
      const code = await props.run(props.selection.operation === "export"
        ? ["share", "export", ...selectorArgs(), output(), ...filters().flatMap((entry) => [`--${entry.kind}`, entry.value]), ...(!includeChats() ? ["--no-chats"] : []), ...(shareAll() && includeSettings() ? ["--include-settings"] : [])]
        : ["share", "import", source(), ...(applySettings() ? ["--apply-settings"] : [])])
      if (generation !== `${context()}/${scope()}/${source()}`) return
      setExitCode(code)
      setPage("result")
    } finally { setWorking(false) }
  }

  createEffect(() => {
    context()
    untrack(() => {
      setFilters([]); setIncludeChats(true); setApplySettings(false); setIncludeSettings(false); setSelectedFilter(0); setSelectedScope(0); setScope("safe"); setArea("actions")
      setSource(""); setExitCode(undefined); setFilterError("")
      setFilename(props.selection.operation === "export" ? props.selection.scope === "all" ? "oblivion-all.oblivion-share" : `oblivion-${props.selection.safe.slice(0, 8)}.oblivion-share` : "")
      setPage(props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch ? "scope" : "choose")
    })
  })
  createEffect(() => { scope(); setFilters([]); setIncludeChats(true); setSelectedFilter(0) })
  createEffect(() => { source(); setFilters([]); setIncludeChats(true); setApplySettings(false); setSelectedFilter(0) })
  usePaste((event) => {
    if (page() !== "add-filter" || !/[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(new TextDecoder().decode(event.bytes))) return
    event.preventDefault()
    setFilterError("Paste one literal entry without control characters or line breaks.")
  })
  useKeyboard((key) => {
    if (key.defaultPrevented || working() || props.selection.operation !== "export") return
    if (page() === "review") {
      if (key.name === "escape") { key.preventDefault(); setPage("name"); return }
      if (key.name === "f") { key.preventDefault(); contentFilters(); return }
      if (key.name === "i" && shareAll()) { key.preventDefault(); setIncludeSettings((value) => !value); return }
      if (key.name === "tab") { key.preventDefault(); setArea((value) => value === "list" ? "actions" : "list"); return }
      if (area() !== "list") return
      if (["up", "down", "pageup", "pagedown", "home", "end"].includes(key.name)) {
        key.preventDefault()
        if (key.name === "home") scroll?.scrollTo(0)
        else if (key.name === "end") scroll?.scrollTo(scroll.scrollHeight)
        else scroll?.scrollBy((key.name === "up" || key.name === "pageup" ? -1 : 1) * (key.name === "pageup" || key.name === "pagedown" ? Math.max(1, (scroll?.viewport.height ?? 2) - 1) : 1))
      }
      return
    }
    if (page() !== "filters") return
    if (key.name === "escape") { key.preventDefault(); review(); return }
    if (key.name === "tab") { key.preventDefault(); setArea((value) => value === "list" ? "actions" : "list"); return }
    if (key.name === "p" || key.name === "x" || key.name === "h") { key.preventDefault(); addFilter(key.name === "p" ? "path" : key.name === "x" ? "exclude" : "exclude-chat"); return }
    if (key.name === "c") { key.preventDefault(); setIncludeChats((value) => !value); return }
    if (key.name === "d") { key.preventDefault(); removeFilter() }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={available()} fallback={<FormView form={{ title: "Close this Safe before Share", description: "An included Safe is open in another terminal. Close and lock the selected Safe or branch before exporting. Other Safes can keep working.", fields: [], submit: "Back to Safes", run: async () => {} }} cancel={props.back} submit={props.back} />}>
      <Show when={page() === "scope"}><Menu title="Choose Share scope" description="Export this Safe alone or include its persistent descendants. Provider login stores are excluded."
        items={scopes()} selected={selectedScope()} change={setSelectedScope} focused choose={(index) => { const item = scopes()[index]; if (item && !item.disabled) item.run() }} back={props.back} /></Show>
      <Show when={page() === "choose"}><LocalChooser
        title={props.selection.operation === "export" ? "Choose Share destination" : "Choose an encrypted Share file"}
        directoryOnly={props.selection.operation === "export"} filesOnly={props.selection.operation === "import"}
        initialDirectory={directory()} back={() => { if (props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch) { setPage("scope"); return }; props.back() }} choose={(value) => {
          if (props.selection.operation === "import") { setSource(value); setDirectory(path.dirname(value)); review(); return }
          setDirectory(value); setPage("name")
        }} /></Show>
      <Show when={page() === "name"}><FormView form={{
        title: "Name the encrypted Share", description: `Destination on this computer · ${directory()}`,
        fields: [{ id: "filename", label: "Share filename", value: filename(), validate: (value) => !value || value === "." || value === ".." || /[/\\\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value) || Buffer.byteLength(value) > 255 ? "Choose a single filename of at most 255 UTF-8 bytes." : undefined }],
        submit: "Review Share", run: async () => {},
      }} cancel={() => setPage("choose")} submit={(values) => { setFilename(values.filename); review() }} /></Show>
      <Show when={page() === "filters" && props.selection.operation === "export"}><Menu title="Share content filters" description={`${sourceLabel()}\nThe same literal filters apply to every selected Safe. These are selectors, not a filesystem preview.\n${includeChats() ? "Conversations included" : "Conversations excluded"} · ${filters().length}/32 filters · No include paths means workspace + imports.`}
        items={filters().map((entry) => ({ name: `--${entry.kind} ${entry.value}`, description: `Exact literal argument: ${entry.value}`, run: () => {} }))} selected={selectedFilter()} change={setSelectedFilter} focused={area() === "list"} choose={() => {}} actions={false} details={false} empty="No custom filters. Default paths are workspace and imports."
        toolbar={[
          { title: "Include path", key: "P", disabled: filters().length >= 32, run: () => addFilter("path") }, { title: "Exclude path", key: "X", disabled: filters().length >= 32, run: () => addFilter("exclude") },
          { title: "Exclude chat", key: "H", disabled: filters().length >= 32, run: () => addFilter("exclude-chat") }, { title: includeChats() ? "Chats: on" : "Chats: off", key: "C", run: () => setIncludeChats((value) => !value) },
          { title: "Remove selected", key: "D", disabled: !filters().length, run: removeFilter }, { title: "Review", key: "Esc", run: review },
        ]} actionsFocused={area() === "actions"} focusActions={() => setArea("actions")} focus={() => setArea("list")} /></Show>
      <Show when={page() === "add-filter" && props.selection.operation === "export"}><FormView form={{ title: filterKind() === "path" ? "Include one path" : filterKind() === "exclude" ? "Exclude one path" : "Exclude one conversation",
        description: filterKind() === "exclude-chat" ? "Enter a conversation reference from the Share contents review. This selects an export item; it does not convert or synchronize native chats."
          : "Enter one literal path under workspace or imports. Spaces and commas are part of the name. No glob, shell, environment or home expansion is performed. The CLI checks actual contents.",
        fields: [{ id: "value", label: filterKind() === "exclude-chat" ? "Share conversation reference" : "Literal guest path", validate: validateFilter }], submit: "Add filter", run: async () => {} }} cancel={() => { setFilterError(""); setPage("filters"); setArea("list") }} submit={(values) => { setFilterError(""); setFilters((before) => [...before, { kind: filterKind(), value: values.value }]); setSelectedFilter(filters().length - 1); setPage("filters"); setArea("list") }} /><Show when={filterError()}><text fg={theme.feedback.warning}>{filterError()}</text></Show></Show>
      <Show when={page() === "review" && props.selection.operation === "export"}>
        <PageHeader title="Review Share export" description={sourceLabel()} />
        <scrollbox ref={(value) => { scroll = value }} flexGrow={1} minHeight={0} border borderColor={area() === "list" ? theme.border.focused : theme.border.base} padding={1} contentOptions={{ minHeight: 0 }}>
          <text fg={theme.text.base} wrapMode="word">{`Scope · ${selectorArgs().join(" ")}\nDestination · ${output()}${shareAll() ? `\nAutomatic-lock timers · ${includeSettings() ? "Included" : "Excluded"}` : ""}\nProvider login stores are excluded. Conversations reopen in their original agent. Content scan is best effort; it does not guarantee removal of secrets.\n\n${filterText()}\n\nFilters apply identically to every selected Safe. The detailed terminal review shows the selected contents and lets you exclude files or conversations before approval.`}</text>
        </scrollbox>
        <text fg={theme.text.muted}>{area() === "list" ? "↑ ↓ / PgUp PgDn scroll · Tab actions" : "Tab review text · ← → select action"}</text>
        <ActionBar focused={area() === "actions"} disabled={working()} actions={[
          { title: "Review contents", key: "Enter", run: () => { void confirm() } },
          { title: "Content filters", key: "F", run: contentFilters },
          ...(shareAll() ? [{ title: includeSettings() ? "Exclude lock timers" : "Include lock timers", key: "I", run: () => setIncludeSettings((value) => !value) }] : []),
          { title: "Cancel", key: "Esc", run: () => setPage("name") },
        ]} />
      </Show>
      <Show when={page() === "review" && props.selection.operation === "import"}><box flexGrow={1} minHeight={0} alignItems="center" justifyContent="center"><box width="100%" maxWidth={104} height={Math.min(22, dimensions().height - 7)} maxHeight="100%" minHeight={0} padding={1} border borderColor={theme.border.base} backgroundColor={theme.background.panel}><FormView form={{
        title: "Review Share import",
        description: `Source · ${source()}\nNew encrypted Safes; existing Safes are not replaced. Safes import offline.\nProvider login stores are excluded. Authenticate agents separately.\nContent scan is best effort; it does not guarantee removal of secrets.\nPasswords and shared timer values are reviewed privately in the terminal.`,
        fields: [{ id: "settings", label: "Apply shared automatic-lock settings (if included)", checkbox: true, value: String(applySettings()) }], submit: "Continue to import", run: async () => {},
      }} cancel={() => setPage("choose")} submit={(values) => { setApplySettings(values.settings === "true"); void confirm() }} /></box></box></Show>
      <Show when={page() === "result"}><PageHeader title={exitCode() === 0 ? props.selection.operation === "export" ? "Share exported" : "Share imported" : exitCode() === 130 ? "Share cancelled" : props.selection.operation === "import" && exitCode() === 2 ? "Safes imported · settings not applied" : "Share did not complete"}
        description={exitCode() === 0 ? props.selection.operation === "export" ? "The encrypted Share was verified and saved. Send its password through a separate channel." : "New encrypted Safes were published offline. Open them to review their contents and authenticate agents separately." : exitCode() === 130 ? props.selection.operation === "import" ? "Operation cancelled. Check Share imports and your Safes before retrying an import." : "Operation cancelled. Check the destination before retrying an export." : props.selection.operation === "import" && exitCode() === 2 ? "The Safes were already imported. Do not import the Share again. Review your Safes and configure Automatic lock in Settings." : "Review the terminal output and check your Safes before retrying an import."} />
        <FormView form={{ title: props.selection.operation === "export" ? "Share export" : "Share import", description: props.selection.operation === "export" ? `Destination · ${output()}` : `Source · ${source()}`, fields: [], submit: exportCancelled() ? "Back to review" : "Back to Safes", run: async () => {} }} cancel={props.back} submit={() => exportCancelled() ? review() : props.back()} />
      </Show>
    </Show>
    <Show when={working()}><BusyModal text="Preparing Share" /></Show>
  </box>
}
