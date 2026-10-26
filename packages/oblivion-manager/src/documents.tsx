import { useKeyboard, useTerminalDimensions } from "@opentui/solid"
import { createEffect, createSignal, onCleanup, onMount, Show } from "solid-js"
import { ControlError, type Request } from "./control"
import { BusyModal } from "./busy-modal"
import { FormView, type Form } from "./form"
import { Picker } from "./picker"
import { palette, theme } from "./theme"
import { SelectList } from "@opencode/tui-kit"
import { PageHeader } from "./page-header"
import { FilePicker } from "./vendor/termcn/file-picker"
import { connectTransfer, devicesSchema, pageSchema, startedSchema, type Offer, type Page, type Recovery, type Transfer } from "./transfer"

export function Documents(props: {
  request: (value: Request) => Promise<string>
  connect?: (id: string) => Promise<Transfer>
  session: string
  chat: boolean
  focused?: boolean
  focusSidebar?: () => void
  activate?: () => void
  back: () => void
  onNavigationLock?: (locked: boolean) => void
}) {
  const dimensions = useTerminalDimensions()
  const wide = () => dimensions().width >= 140
  const spacious = () => wide() && dimensions().height >= 32
  const [page, setPage] = createSignal<Page>({ path: "", entries: [], next: null, skipped: 0 })
  const [selected, setSelected] = createSignal<string[]>([])
  const [cursors, setCursors] = createSignal<(string | undefined)[]>([undefined])
  const [focus, setFocus] = createSignal<"files" | "actions">("files")
  const [mode, setMode] = createSignal<"session" | "import">("session")
  const [device, setDevice] = createSignal("")
  const [devices, setDevices] = createSignal<{ export: boolean; choices: { value: string; label: string }[] }>()
  const [form, setForm] = createSignal<Form>()
  const [offer, setOffer] = createSignal<{ manifest: Offer; export: boolean }>()
  const [recovery, setRecovery] = createSignal<Extract<Recovery, { result: "inventory" }>>()
  const [busy, setBusy] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [failed, setFailed] = createSignal(false)
  let transfer: Transfer | undefined
  let job: string | undefined
  let cancelling: Promise<void> | undefined
  let cancelled = false
  let disposed = false

  function focusArea(area: "files" | "actions") {
    setFocus(area)
    props.activate?.()
  }

  // Keep the transfer workflow open until it has finished or been cancelled.
  // Ordinary browsing may switch directly to the host menu or the running chat.
  createEffect(() => props.onNavigationLock?.(!!busy() || !!form() || !!devices() || !!recovery() || !!offer() || mode() === "import" || !!job))

  async function command(value: object) {
    return props.request({ operation: "transfers", payload: new TextEncoder().encode(JSON.stringify(value)) })
  }
  async function cleanup() {
    transfer?.close(); transfer = undefined
    if (!job) return
    cancelling ??= command({ operation: "cancel" }).then(() => { job = undefined }).finally(() => { cancelling = undefined })
    await cancelling
  }
  async function run(label: string, task: () => Promise<void>) {
    if (busy()) return
    cancelled = false
    setBusy(label); setNotice(""); setFailed(false)
    try { await task() }
    catch (error) {
      setFailed(!cancelled)
      setNotice(cancelled ? "Transfer cancelled." : error instanceof ControlError ? `Operation stopped (${error.code}).` : "Operation stopped. The device or directory may no longer be available.")
      if (job || mode() === "import" || offer()) {
        await cleanup().catch(() => setNotice("Cleanup required. Close and lock the session before continuing."))
        setMode("session"); setOffer(undefined); setSelected([])
        setPage({ path: "", entries: [], next: null, skipped: 0 }); setCursors([undefined])
        if (!job) await browse().catch(() => undefined)
      }
    } finally { if (!disposed) setBusy("") }
  }
  async function browse(path = "", after?: string, direction: "reset" | "next" | "previous" = "reset") {
    const result = mode() === "import" && transfer
      ? await transfer.browse(path, after)
      : pageSchema.parse(JSON.parse(await props.request({ operation: "browse", payload: new TextEncoder().encode(JSON.stringify({ path, after: after ?? null, limit: 100 })) })))
    if (disposed) return
    setPage(result)
    setCursors((values) => direction === "next" ? [...values, after] : direction === "previous" ? values.slice(0, -1) : [undefined])
  }
  async function home() {
    await cleanup(); setMode("session"); setSelected([]); setOffer(undefined); setForm(undefined); setDevices(undefined); setRecovery(undefined)
    await browse(); setFocus("files")
  }
  async function prepare(exporting: boolean, target: string) {
    const started = startedSchema.parse(JSON.parse(await command(exporting ? { operation: "export", target } : { operation: "import", source: target })))
    job = started.id
    transfer = await (props.connect ?? connectTransfer)(started.id)
    if (exporting) { await makeOffer(true); return }
    setMode("import"); setSelected([]); setDevices(undefined); await browse(); setFocus("files")
  }
  async function makeOffer(exporting: boolean) {
    if (!transfer || !selected().length) return
    const paths = selected().filter((path, index, all) => !all.some((parent, other) => other !== index && path.startsWith(parent + "/")))
    setOffer({ manifest: await transfer.offer(paths), export: exporting })
    setDevices(undefined)
  }
  async function chooseDevice(exporting: boolean) {
    if (exporting && !selected().length) { setNotice("Select one or more files or folders with Space."); return }
    const status = devicesSchema.parse(JSON.parse(await command({ operation: "list" })))
    if (status.active) { setNotice("A transfer is already active. Cancel it before starting another."); return }
    setDevices({ export: exporting, choices: status.sources.map((source) => ({ value: source.id, label: `${source.name} · ${Math.round(source.bytes / 1048576)} MiB` })) })
  }
  async function recover(request: { operation: "list"; after: string | null } | { operation: "discard"; id: string }) {
    await cleanup()
    job = startedSchema.parse(JSON.parse(await command({ operation: "recover" }))).id
    transfer = await (props.connect ?? connectTransfer)(job)
    const result = await transfer.recover(request)
    await cleanup()
    if (result.result === "inventory") { setRecovery(result); return }
    setNotice(`Discarded unfinished private copy ${result.id.slice(0, 8)}.`)
    await recover({ operation: "list", after: null })
  }
  const actions = () => mode() === "import" ? [
    { name: "Review import", run: () => run("Reading and hashing selection", () => makeOffer(false)) },
    { name: "Cancel import", run: () => run("Cancel import", home) },
  ] : [
    { name: "Import", run: () => run("List USB devices", () => chooseDevice(false)) },
    { name: "Export selected", run: () => run("List USB devices", () => chooseDevice(true)) },
    { name: "Transfer history / recovery", run: () => run("Read transfer records", () => recover({ operation: "list", after: null })) },
    { name: "Return", run: () => props.back() },
  ]
  useKeyboard((key) => {
    if (key.defaultPrevented || props.focused === false) return
    if (form() || devices() || recovery()) return
    if (busy()) {
      if (key.name === "escape" && job) {
        key.preventDefault()
        cancelled = true
        void cleanup().catch(() => { setFailed(true); setNotice("Cleanup required. Close and lock the session before continuing.") })
      }
      return
    }
    if (key.name === "tab") {
      key.preventDefault()
      if (props.focusSidebar && (key.shift ? focus() === "files" : focus() === "actions") && mode() === "session" && !offer()) { props.focusSidebar(); return }
      setFocus((value) => value === "files" ? "actions" : "files")
    }
    if (offer() && key.name === "escape") { key.preventDefault(); void run("Cancel transfer", home); return }
    if (key.name === "escape" && focus() === "actions") { key.preventDefault(); setFocus("files") }
  })
  onMount(() => { void run("Read session documents", () => browse()) })
  onCleanup(() => { disposed = true; props.onNavigationLock?.(false); transfer?.close(); if (job) void command({ operation: "cancel" }).catch(() => undefined) })

  return <box flexGrow={1} minHeight={0} flexDirection="column">
    <Show when={!form() && !devices() && !recovery()}><PageHeader title={offer() ? "Review transfer" : "Documents"}
      description={props.chat ? "Chat remains active while you browse." : "Offline documents · no network device"} /></Show>
    <Show when={!form()} fallback={<FormView form={form()!} cancel={() => setForm(undefined)} submit={(values) => { const current = form()!; setForm(undefined); void run(current.title, () => current.run(values)) }} />}>
      <Show when={!devices()} fallback={<Picker title={devices()?.export ? "Export / Destination device" : "Import / Source device"} description={devices()?.choices.length ? "Choose a removable device. The Oblivion USB is excluded." : "No removable USB devices found. Connect a device, then reopen Import or Export."} choices={devices()?.choices ?? []} back={() => setDevices(undefined)} choose={(id) => {
        const selected = devices()!
        setDevice(selected.choices.find((choice) => choice.value === id)!.label)
        if (!selected.export) { void run("Prepare read-only source", () => prepare(false, id)); return }
        setForm({ title: "Authorize writing to USB", description: `Destination: ${device()}. Exported files will be ordinary readable copies. Mounting may update filesystem metadata. Existing files are preserved.`, fields: [], submit: "Authorize and prepare export", run: () => prepare(true, id) })
      }} />}>
        <Show when={!recovery()} fallback={<Picker title="Transfer history / Recovery" description="Published copies remain editable by chat. Only unfinished private copies can be discarded." choices={[
          ...(recovery()?.records ?? []).map((record) => ({ value: record.id, label: `${record.id.slice(0, 8)} · ${record.state}`, description: record.receipt ? `${record.receipt.entries} entries · ${record.receipt.bytes} bytes verified` : "No complete receipt" })),
          ...(recovery()?.next ? [{ value: "next", label: "Next page" }] : []),
        ]} back={() => setRecovery(undefined)} choose={(id) => {
          if (id === "next") { void run("Read transfer records", () => recover({ operation: "list", after: recovery()!.next })); return }
          if (recovery()!.records.find((record) => record.id === id)?.state !== "private") return
          setForm({ title: "Discard unfinished private copy", description: `Remove unfinished transfer ${id.slice(0, 8)}. Published documents are preserved.`, fields: [], submit: "Discard private copy", run: () => recover({ operation: "discard", id }) })
        }} />}>
          <Show when={!offer()} fallback={<box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
            <text fg={theme.text.base}>{offer()?.export ? `Session → ${device()}` : `${device()} → session /imports`}</text>
            <text fg={theme.text.base}>{offer()?.manifest.entries.length} entries · {offer()?.manifest.bytes.toLocaleString("en-US")} bytes</text>
            <SelectList theme={palette} focused={props.focused !== false && focus() === "files"} disabled={!!busy()} onFocus={() => focusArea("files")}
              items={(offer()?.manifest.entries ?? []).map((entry) => ({ title: `${entry.kind === "directory" ? "/" : " "} ${entry.path}` }))} />
            <text fg={theme.text.muted}>{offer()?.export ? "Readable copies leave the encrypted session." : "Verified imports become available to chat; using them as context may send their contents to Abliteration."}</text>
            <SelectList theme={palette} height={2} focused={props.focused !== false && focus() === "actions"} disabled={!!busy()} onFocus={() => focusArea("actions")}
              items={[{ title: "Confirm copy" }, { title: "Cancel" }]} onSelect={(index) => {
              if (index === 1) { void run("Cancel transfer", home); return }
              void run("Copying and verifying · Esc cancels", async () => {
                const receipt = await transfer!.approve(offer()!.manifest)
                await home(); setNotice(`Verified ${receipt.entries} entries, ${receipt.bytes.toLocaleString("en-US")} bytes. Transfer complete.`)
              })
            }} />
          </box>}>
            <text height={1} flexShrink={0} fg={theme.text.muted}>{mode() === "import" ? `Source: ${device()} (read-only)` : "Roots: workspace / imports"}</text>
            <box flexGrow={1} flexShrink={1} flexBasis={0} minHeight={0} flexDirection={wide() ? "row" : "column"} gap={wide() ? 3 : 1}>
            <FilePicker currentDir={page().path} entries={page().entries.map((entry) => ({ ...entry, path: [page().path, entry.name].filter(Boolean).join("/") }))} selected={selected()} focused={props.focused !== false && focus() === "files"} onFocus={() => focusArea("files")} busy={!!busy()} next={!!page().next} previous={cursors().length > 1}
              onNavigate={(path) => { void run("Read directory", () => browse(path)) }} onChange={setSelected}
              onNext={() => { void run("Read next page", () => browse(page().path, page().next ?? undefined, "next")) }}
              onPrevious={() => { void run("Read previous page", () => browse(page().path, cursors().at(-2), "previous")) }}
              onBack={() => { if (page().path) { void run("Read parent directory", () => browse(page().path.split("/").slice(0, -1).join("/"))); return }; if (mode() === "import") { void run("Cancel import", home); return }; props.back() }} />
            <Show when={page().skipped}><text fg={theme.text.muted}>Some unsupported names, links or special files were omitted.</text></Show>
            <box width={wide() ? 40 : "100%"} flexShrink={0} flexDirection="column" paddingTop={wide() ? 1 : 0}>
            <Show when={wide()}><text fg={theme.text.muted}>Transfers</text><box height={1} /></Show>
            <SelectList theme={palette} height={actions().length * (spacious() ? 2 : 1)} spacing={spacious() ? 1 : 0} focused={props.focused !== false && focus() === "actions"} disabled={!!busy()}
              onFocus={() => focusArea("actions")} items={actions().map((action) => ({ title: action.name }))}
              onSelect={(index) => { void actions()[index]?.run() }} />
            <Show when={wide()}><box height={1} /><text fg={theme.text.muted}>{mode() === "import" ? "Select documents, then review the copy before importing." : "Import from a USB device. To export, first mark files with Space."}</text></Show>
            </box></box>
          </Show>
        </Show>
      </Show>
    </Show>
    <Show when={busy()}><BusyModal text={busy()} cancellable={!!job} /></Show>
    <text height={1} flexShrink={0} fg={failed() ? theme.feedback.error : theme.text.muted}>{notice() || `Focus: ${props.focused === false ? "MENU" : focus().toUpperCase()} · Tab switches area · Esc returns`}</text>
  </box>
}
