import { useKeyboard } from "@opentui/solid"
import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { z } from "zod"
import { SelectList } from "@opencode/tui-kit"
import { BusyModal } from "./busy-modal"
import { ControlError, type Request } from "./control"
import { FormView } from "./form"
import { PageHeader } from "./page-header"
import { Picker } from "./picker"
import { capacity } from "./state"
import { connectTransfer, devicesSchema, type Offer, type Page, type Transfer } from "./transfer"
import { palette, theme } from "./theme"
import { FilePicker } from "./vendor/termcn/file-picker"

const started = z.object({ id: z.string().regex(/^[a-f0-9]{32}$/), bytes: z.number().int().min(32 * 1024 ** 2).max(1024 ** 4) })
const errors: Record<string, string> = {
  unsupported_backup_version: "This backup format is not supported by this version of Oblivion.",
  invalid_backup_metadata: "This backup does not contain valid Oblivion session metadata.",
  invalid_backup_database: "The chat database could not be verified by this version of Oblivion.",
  chat_export_unavailable: "Offline database verification did not complete. Check the backup and try again.",
  insufficient_restore_space: "Oblivion storage does not have enough free space for a session backup.",
  session_must_be_closed: "Close and lock the active session before restoring a backup.",
  general_not_writable: "Restore requires writable encrypted storage. Ephemeral mode cannot save restored sessions.",
  transfer_already_running: "Another file transfer is active. Finish or cancel it before restoring a session.",
  transfer_cleanup_required: "An earlier transfer needs cleanup. Lock Oblivion before continuing.",
  source_not_available: "The selected device is no longer available. Reattach it and refresh the list.",
}

export function SessionRestore(props: { request: (request: Request) => Promise<string>; back: () => void }) {
  const [devices, setDevices] = createSignal<z.infer<typeof devicesSchema>["sources"]>([])
  const [device, setDevice] = createSignal<z.infer<typeof devicesSchema>["sources"][number]>()
  const [page, setPage] = createSignal<Page>({ path: "", entries: [], next: null, skipped: 0 })
  const [cursors, setCursors] = createSignal<(string | undefined)[]>([undefined])
  const [selected, setSelected] = createSignal<string[]>([])
  const [focus, setFocus] = createSignal<"files" | "actions">("files")
  const [offer, setOffer] = createSignal<Offer>()
  const [copied, setCopied] = createSignal(false)
  const [restored, setRestored] = createSignal("")
  const [busy, setBusy] = createSignal("")
  const [error, setError] = createSignal("")
  const [cleanupRequired, setCleanupRequired] = createSignal(false)
  let operation: z.infer<typeof started> | undefined
  let transfer: Transfer | undefined
  let preparing: Promise<z.infer<typeof started>> | undefined
  let finishing: Promise<string> | undefined
  let stopping: Promise<void> | undefined
  let discarding: Promise<void> | undefined
  let active = false
  let published = false
  let disposed = false
  let cancelling = false

  async function command(value: object, timeoutMs?: number) {
    const payload = new TextEncoder().encode(JSON.stringify(value))
    try { return await props.request({ operation: "transfers", payload, timeoutMs }) }
    finally { payload.fill(0) }
  }
  async function release() {
    transfer?.close(); transfer = undefined
    if (stopping) return stopping
    if (!active) return
    stopping = (async () => {
      await preparing?.catch(() => undefined)
      await command({ operation: "cancel" })
      active = false
    })()
    try { await stopping } finally { stopping = undefined }
  }
  async function discard() {
    if (discarding) return discarding
    discarding = (async () => {
      await finishing?.catch(() => undefined)
      await release()
      if (operation && !published) await command({ operation: "restore-discard", id: operation.id })
      operation = undefined
    })()
    try { await discarding } finally { discarding = undefined }
  }
  async function run(label: string, action: () => Promise<void>, retry = false) {
    if (busy()) return
    setBusy(label); setError("")
    try { await action() }
    catch (failure) {
      if (retry) {
        if (!disposed && failure instanceof ControlError && ["maintenance_cleanup_required", "recovery_required"].includes(failure.code)) setCleanupRequired(true)
      } else {
        try { await discard() } catch { if (!disposed) setCleanupRequired(true); return }
        if (!disposed) { setDevice(undefined); setOffer(undefined) }
      }
      if (!disposed && !cancelling) setError(failure instanceof ControlError
        ? `${errors[failure.code] ?? `Restore stopped (${failure.code}).`} Original sessions and source media are preserved.`
        : "Could not copy or verify this backup. Check the device, free space, session password and backup compatibility. Original sessions and source media are preserved.")
    } finally { if (!disposed) setBusy("") }
  }
  async function list() {
    const result = devicesSchema.parse(JSON.parse(await command({ operation: "list" })))
    if (result.active) throw new ControlError("transfer_already_running")
    if (!disposed) setDevices(result.sources)
  }
  async function browse(path = "", after?: string, direction: "reset" | "next" | "previous" = "reset") {
    const result = await transfer!.browse(path, after)
    if (disposed) return
    setPage(result); setSelected([])
    setCursors((values) => direction === "next" ? [...values, after] : direction === "previous" ? values.slice(0, -1) : [undefined])
  }
  async function prepare(source: string) {
    active = true
    const pending = command({ operation: "restore", source }, 360_000).then((value) => {
      operation = started.parse(JSON.parse(value)); return operation
    })
    preparing = pending
    const result = await pending.finally(() => { if (preparing === pending) preparing = undefined })
    if (disposed) { await discard(); return }
    transfer = await connectTransfer(result.id, undefined, { entries: 1, bytes: result.bytes, budgetMs: 3_600_000 })
    if (disposed) { await discard(); return }
    await browse()
  }
  async function review() {
    const manifest = await transfer!.offer(selected())
    if (manifest.entries.length !== 1 || manifest.entries[0].kind !== "file" || manifest.entries[0].path !== "session.oblivion" || manifest.bytes < 32 * 1024 ** 2) throw new ControlError("invalid_manifest")
    if (!disposed) setOffer(manifest)
  }
  async function copy() {
    await transfer!.approve(offer()!)
    await release()
    if (!disposed) { setOffer(undefined); setCopied(true) }
  }
  async function verify(password: string) {
    const id = operation!.id
    const pending = command({ operation: "restore-finish", id, password }, 360_000).then((value) => { published = true; return value })
    finishing = pending
    await pending.finally(() => { if (finishing === pending) finishing = undefined })
    if (!disposed) setRestored(id.slice(0, 8))
  }
  async function cancel() {
    if (cancelling) return
    cancelling = true; setBusy("Stopping restore and removing its private copy")
    try { await discard(); if (!disposed) props.back() }
    catch { if (!disposed) setCleanupRequired(true) }
    finally { cancelling = false; if (!disposed) setBusy("") }
  }
  useKeyboard((key) => {
    if (key.defaultPrevented) return
    if (key.name === "escape" && busy() && transfer) { key.preventDefault(); key.stopPropagation(); void cancel(); return }
    if (key.ctrl && key.name === "r" && !busy() && !device()) { key.preventDefault(); void run("Refreshing sources", list) }
    if (device() && !busy() && !copied() && !offer()) {
      if (key.name === "tab") { key.preventDefault(); setFocus((value) => value === "files" ? "actions" : "files"); return }
      if (key.name === "return" && key.ctrl && selected().length) { key.preventDefault(); void run("Reading and hashing encrypted backup", review) }
    }
  })
  onMount(() => { void run("Reading backup sources", list) })
  onCleanup(() => { disposed = true; transfer?.close(); void discard().catch(() => {}) })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={!busy()}><Show when={!cleanupRequired()} fallback={<FormView form={{ title: "Restore cleanup required", description: "Cleanup has not been verified. Return to the manager and lock Oblivion to complete recovery before opening a session.", fields: [], submit: "Return to manager", run: async () => props.back() }} cancel={props.back} submit={props.back} />}>
      <Show when={!restored()} fallback={<FormView form={{ title: "Session restored", description: `New session ${restored()} was verified offline, locked and added to your encrypted storage. All chats and documents are retained. Original sessions and source media are preserved. Provider keys use your general Oblivion settings.`, fields: [], submit: "Back to sessions", run: async () => props.back() }} cancel={props.back} submit={props.back} />}>
        <Show when={!copied()} fallback={<FormView form={{ title: "Unlock and verify backup", description: "The encrypted copy is ready. Enter its original session password. Oblivion verifies the filesystem, metadata and chat database in an offline VM before adding a separate session. A wrong password can be retried without copying again.", fields: [{ id: "password", label: "Session password", secret: true, validate: (value) => value ? undefined : "Enter the session password." }], submit: "Verify and restore", run: async (values) => verify(values.password) }} cancel={() => { void cancel() }} submit={(values) => { void run("Verifying backup offline and locking the restored session", () => verify(values.password), true) }} />}>
          <Show when={!offer()} fallback={<FormView form={{ title: "Copy encrypted session", description: `Source: ${device()?.name}\n${selected()[0]} · ${capacity(offer()!.bytes)}\nCopy this encrypted volume into your Oblivion storage. It is not added to Sessions until the offline checks pass. Original sessions and source media are preserved.`, fields: [], submit: "Copy backup", run: copy }} cancel={() => { void cancel() }} submit={() => { void run("Copying and verifying encrypted volume", copy) }} />}>
            <Show when={device()} fallback={<>
              <Picker title="Restore session / Source" description={devices().length ? "Choose USB or prepared virtual media containing a session.oblivion backup. Sources are opened read-only; Oblivion system storage is excluded." : "Attach USB or prepared virtual media containing a backup. Ctrl+R refreshes the list. Sources are opened read-only."}
                choices={devices().map((source) => ({ value: source.id, label: `${source.name} · ${source.kind === "virtual" ? "Virtual media" : "USB"}`, description: capacity(source.bytes) }))}
                back={props.back} choose={(id) => { setDevice(devices().find((source) => source.id === id)); void run("Opening read-only backup source", () => prepare(id)) }} />
              <text fg={theme.text.action} onMouseDown={() => { void run("Refreshing sources", list) }}>Refresh Ctrl+R</text>
            </>}>
              <PageHeader title="Select encrypted backup" description={`Source: ${device()?.name} · Read-only · Select one file`} />
              <FilePicker currentDir={page().path} entries={page().entries.map((entry) => ({ ...entry, path: [page().path, entry.name].filter(Boolean).join("/") }))} selected={selected()} focused={focus() === "files"} onFocus={() => setFocus("files")} busy={!!busy()} next={!!page().next} previous={cursors().length > 1}
                onNavigate={(path) => { void run("Reading directory", () => browse(path)) }}
                onChange={(paths) => { const path = paths.at(-1); if (path && page().entries.some((entry) => entry.directory && [page().path, entry.name].filter(Boolean).join("/") === path)) { setError("Open the folder and select one backup file."); return }; setError(""); setSelected(path ? [path] : []) }}
                onNext={() => { void run("Reading next page", () => browse(page().path, page().next ?? undefined, "next")) }}
                onPrevious={() => { void run("Reading previous page", () => browse(page().path, cursors().at(-2), "previous")) }}
                onBack={() => { if (page().path) { void run("Reading parent directory", () => browse(page().path.split("/").slice(0, -1).join("/"))); return }; void cancel() }} />
              <Show when={page().skipped}><text fg={theme.text.muted}>Unsupported names, links or special files were omitted.</text></Show>
              <SelectList theme={palette} height={2} focused={focus() === "actions"} onFocus={() => setFocus("actions")}
                items={[{ title: "Review backup" }, { title: "Cancel restore" }]} onSelect={(index) => {
                  if (index === 1) { void cancel(); return }
                  if (!selected().length) { setError("Select one backup file first."); return }
                  void run("Reading and hashing encrypted backup", review)
                }} />
              <text fg={theme.text.muted}>Tab actions · Ctrl+Enter review</text>
            </Show>
          </Show>
        </Show>
      </Show>
    </Show></Show>
    <Show when={error()}><text fg={theme.feedback.error}>{error()}</text></Show>
    <Show when={busy()}><BusyModal text={busy()} cancellable={!!transfer} /></Show>
  </box>
}
