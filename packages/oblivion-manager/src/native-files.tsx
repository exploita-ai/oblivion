import path from "node:path"
import { readdir, stat } from "node:fs/promises"
import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard, usePaste } from "@opentui/solid"
import { ScrollBoxRenderable } from "@opentui/core"
import { z } from "zod"
import { Menu } from "./menu"
import { FormView } from "./form"
import { PageHeader } from "./page-header"
import { BusyModal } from "./busy-modal"
import { ActionBar } from "./action-bar"
import { FilePicker } from "./vendor/termcn/file-picker"
import { theme } from "./theme"
import { capacity, type NativeRuntime } from "./native-control"
import { liveMedia, type LiveDevice, type UsbBrowser } from "./native-usb"
import { createFileTransfers, fileInventory, fileOutcome, type FileInventory, type FileOutcome, type FileReference, type FileTransfer } from "./native-file-transfers"
import type { FileMappingEntry, FileReview, RunningFileCopy } from "./native-file-events"
import { SelectionBasket, selectionError, type FileSelection } from "./file-selection"
import { inspectLocalPaths, maximumPathBytes, unsafePathText } from "./local-path"

const directory = z.object({
  path: z.string(), entries: z.array(z.object({ name: z.string(), path: z.string(), kind: z.enum(["directory", "file"]), bytes: z.number().nonnegative() })),
  next_cursor: z.string().nullable(), skipped: z.number().optional(),
})

export function NativeFiles(props: { safe: string; name: string; opening?: string; blocked?: string; transfers?: ReturnType<typeof createFileTransfers>; runtime: NativeRuntime; run: (args: string[]) => Promise<boolean>; back: () => void }) {
  const transfers = props.transfers ?? createFileTransfers()
  const [page, setPage] = createSignal<"menu" | "source" | "guest" | "usb-devices" | "usb-source" | "destination" | "name" | "transfer" | "records" | "record-destination" | "outcome" | "recover" | "discard">("menu")
  const [selected, setSelected] = createSignal(0)
  const [operation, setOperation] = createSignal<"import" | "export">("import")
  const [sources, setSources] = createSignal<string[]>([])
  const [destination, setDestination] = createSignal("")
  const [name, setName] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [reference, setReference] = createSignal<{ entry: FileReference; location: "recent" | "inventory" }>()
  const [recordsScope, setRecordsScope] = createSignal<"import" | "export" | "recent">("import")
  const [inventory, setInventory] = createSignal<FileInventory>()
  const [inventoryCursors, setInventoryCursors] = createSignal<string[]>([])
  const [inventoryDestination, setInventoryDestination] = createSignal<string>()
  const [inventoryBusy, setInventoryBusy] = createSignal(false)
  const [inventoryNeedsOpen, setInventoryNeedsOpen] = createSignal(false)
  const [observed, setObserved] = createSignal<FileOutcome>()
  const [confirmation, setConfirmation] = createSignal<FileOutcome>()
  const [working, setWorking] = createSignal(false)
  const [copyStage, setCopyStage] = createSignal<"preparing" | "review" | "copying" | "finalizing" | "cancelling" | "reconciling">()
  const [copyReview, setCopyReview] = createSignal<FileReview>()
  const [copyMappings, setCopyMappings] = createSignal<FileMappingEntry[]>([])
  const [copied, setCopied] = createSignal(0)
  const [devices, setDevices] = createSignal<LiveDevice[]>([])
  const [usb, setUsb] = createSignal<{ device: LiveDevice; opening: string; browser: UsbBrowser }>()
  let running: RunningFileCopy | undefined
  let decision: { requested: boolean } | undefined
  let copyEpoch = 0
  let inventoryEpoch = 0
  let stopped = false
  let reviewScroll: ScrollBoxRenderable | undefined
  const records = () => transfers.entries().filter((entry) => entry.safe === props.safe)
  const current = () => reference()?.entry
  const details = () => reference()?.location === "recent" ? records().find((entry) => entry.id === current()?.id && entry.opening === current()?.opening) : undefined
  const generation = createMemo(() => `${props.safe}/${props.opening ?? ""}`)
  const availability = createMemo(() => props.blocked)
  const recoverable = () => !!current() && !props.blocked && observed()?.state === "ready" && observed()?.can_recover
  const discardable = () => !!current() && !props.blocked && ["ready", "incomplete"].includes(observed()?.state ?? "") && observed()?.can_discard

  async function read(entry: FileReference) {
    const expected = generation()
    const state = await props.runtime.status()
    const opened = state.idle_lock.safes.find((safe) => safe.opening.safe_id === entry.safe && !safe.closing)?.opening
    if (stopped || !state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opened || props.opening && props.opening !== opened.nonce || expected !== generation()) throw new Error("Safe opening unavailable")
    const result = fileOutcome.parse(await props.runtime.query(["files", "status", "--safe", entry.safe, "--operation", entry.id, "--opening", opened.nonce,
      ...(entry.kind === "export" ? ["--destination", entry.destination] : []), "--json"]))
    if (expected !== generation() || entry.safe !== props.safe || result.operation_id !== entry.id || result.safe_id !== entry.safe || result.opening !== opened.nonce || result.source_opening && result.source_opening !== entry.opening) throw new Error("Copy identity changed")
    return result
  }

  async function listTransfers(kind: "import" | "export", cursors: string[] = []) {
    const expected = generation()
    const folder = inventoryDestination()
    const epoch = ++inventoryEpoch
    const after = cursors.at(-1)
    setRecordsScope(kind); setInventory(undefined); setInventoryCursors(cursors); setSelected(0); setInventoryBusy(true); setInventoryNeedsOpen(false); setNotice("")
    try {
      const state = await props.runtime.status()
      const opened = state.idle_lock.safes.find((safe) => safe.opening.safe_id === props.safe && !safe.closing)?.opening
      if (stopped || epoch !== inventoryEpoch || expected !== generation()) return
      if (!state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opened) {
        setInventoryNeedsOpen(state.app_open && !!state.idle_lock.host && !state.idle_lock.host.closing && !opened)
        throw new Error("Safe opening unavailable")
      }
      if (props.opening && props.opening !== opened.nonce || kind === "export" && !folder) throw new Error("Receiver unavailable")
      const result = fileInventory.parse(await props.runtime.query(["files", "transfers", "--safe", props.safe, "--opening", opened.nonce,
        ...(kind === "export" ? ["--destination", folder!] : []), ...(after ? ["--cursor", after] : []), "--limit", "8", "--json"]))
      if (stopped || epoch !== inventoryEpoch || expected !== generation()) return
      if (result.safe_id !== props.safe || result.opening !== opened.nonce || result.direction !== kind
        || after && (result.entries.some((entry) => entry.operation_id <= after) || result.next_cursor && result.next_cursor <= after)) throw new Error("Transfer inventory changed")
      setInventory(result)
    } catch {
      if (!stopped && epoch === inventoryEpoch && expected === generation()) setNotice(inventoryNeedsOpen() ? "Open this Safe to read its recorded transfers, then refresh." : "Receiver records are unavailable. Refresh before inspecting a transfer; no copy will be retried.")
    } finally { if (!stopped && epoch === inventoryEpoch) setInventoryBusy(false) }
  }

  function showTransfers(kind: "import" | "export" = "import") { setPage("records"); void listTransfers(kind) }
  function showRecent() { inventoryEpoch++; setInventoryBusy(false); setInventory(undefined); setInventoryCursors([]); setInventoryNeedsOpen(false); setNotice(""); setSelected(0); setRecordsScope("recent"); setPage("records") }
  function chooseExportReceiver() { inventoryEpoch++; setInventoryBusy(false); setInventory(undefined); setInventoryNeedsOpen(false); setNotice(""); setPage("record-destination") }
  async function openInventorySafe() {
    if (working()) return
    const expected = generation()
    setWorking(true)
    try { if (await props.run(["safe", "open", props.safe]) && !stopped && expected === generation()) await listTransfers(recordsScope() === "export" ? "export" : "import") }
    catch { if (!stopped && expected === generation()) setNotice("The Safe could not be opened. Reopen it before refreshing receiver records.") }
    finally { if (!stopped) setWorking(false) }
  }

  function inspectInventory(index: number) {
    const row = inventory()?.entries[index]
    const kind = recordsScope()
    if (!row || kind === "recent" || inventoryBusy()) return
    const destination = kind === "import" ? `workspace/${row.name}` : inventoryDestination()
    if (!destination) return
    void inspect({ id: row.operation_id, safe: props.safe, opening: row.source_opening, kind, name: row.name, destination }, "inventory")
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

  async function inspect(entry: FileReference, location: "recent" | "inventory" = "recent") {
    if (working()) return
    setReference({ entry, location }); setObserved(undefined); setConfirmation(undefined); setNotice(""); setPage("outcome")
    try {
      if (!await props.run(["safe", "open", props.safe])) { setNotice("Open this Safe to inspect the recorded outcome. No copy will be retried automatically."); return }
      await refresh()
    } catch { if (!stopped) setNotice("The Safe could not be opened. Keep the operation ID; no copy will be retried automatically.") }
  }

  async function finishCopy(copy: RunningFileCopy, entry: FileTransfer, approval: { requested: boolean }, epoch: number, fromUsb: boolean) {
    let beforeApproval: "cancelled-before-copy" | "interrupted" | undefined
    let usbUnconfirmed = fromUsb
    try {
      const finished = (await copy.done).finished
      usbUnconfirmed = fromUsb && (!finished || finished.outcome === "interrupted")
      if (!approval.requested && finished && finished.outcome !== "completed") beforeApproval = finished.outcome
    }
    catch {
      try { await copy.cancel() }
      catch { if (!stopped && epoch === copyEpoch) { setCopyStage("cancelling"); setNotice("Copy cleanup is not confirmed. No new copy can start; check the runtime before continuing.") }; return }
      if (!stopped && epoch === copyEpoch) setNotice("The copy result was lost. Checking its recorded outcome; no copy will be retried automatically.")
    }
    if (running === copy) running = undefined
    if (beforeApproval) transfers.forget(entry.id, entry.safe)
    if (stopped || epoch !== copyEpoch) return
    setCopyStage(undefined); setWorking(false)
    if (beforeApproval) {
      setReference(undefined); setObserved(undefined); setCopyReview(undefined); setSelected(0); setPage("menu")
      setNotice(beforeApproval === "cancelled-before-copy" ? "Cancelled before copying. No file contents were copied." : usbUnconfirmed ? "USB preparation stopped. Check the runtime before removing the device." : "Preparation stopped before approval. Check the source and destination.")
      return
    }
    setPage(current() ? "outcome" : "records")
    await refresh()
    if (!stopped && epoch === copyEpoch && usbUnconfirmed) setNotice("The USB transfer was interrupted. Check the recorded outcome and runtime before removing the device.")
  }

  async function cancelCopy() {
    const copy = running
    if (!copy) return
    setCopyStage("cancelling")
    try { await copy.cancel() }
    catch { if (!stopped) setNotice("Copy cleanup is not confirmed. Inspect the recorded outcome before another attempt.") }
  }

  async function beginCopy() {
    if (working() || copyStage() || props.blocked) return
    if (!sources().length || selectionError(sources())) return
    const safe = props.safe
    setNotice(""); setWorking(true)
    try {
      if (!await props.run(["safe", "open", safe]) || stopped || props.safe !== safe) return
      const expected = generation()
      const state = await props.runtime.status()
      if (stopped || expected !== generation()) return
      const opened = state.idle_lock.safes.find((entry) => entry.opening.safe_id === safe && !entry.closing)?.opening
      if (!state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opened) { setNotice("The Safe is no longer available. Reopen it before copying."); return }
      if (props.opening && props.opening !== opened.nonce) { setNotice("The Safe opening changed. Refresh Files and review the copy again."); return }
      const media = usb()
      if (media && media.opening !== opened.nonce) { setNotice("The Safe opening changed. Select the USB files again."); return }
      const entry: FileTransfer = { id: crypto.randomUUID().replaceAll("-", ""), safe, opening: opened.nonce, kind: operation(), name: name(), sources: sources(), destination: operation() === "import" ? `workspace/${name()}` : destination() }
      transfers.remember(entry)
      setReference({ entry, location: "recent" }); setObserved(undefined); setCopyReview(undefined); setCopyMappings([]); setCopied(0); setCopyStage("preparing"); setPage("transfer")
      const args = entry.kind === "import"
        ? ["files", "import", "--safe", entry.safe, ...(media ? ["--usb", media.device.id] : []), ...entry.sources.flatMap((source) => ["--source", source]), "--name", name()]
        : ["files", "export", "--safe", entry.safe, ...entry.sources.flatMap((source) => ["--path", source]), "--destination", entry.destination, "--name", name()]
      const epoch = ++copyEpoch
      const approval = { requested: false }
      decision = approval
      const copy = props.runtime.files.start({ args: [...args, "--operation", entry.id, "--opening", opened.nonce],
        identity: { operation_id: entry.id, safe_id: entry.safe, opening: entry.opening }, direction: entry.kind,
        name: name(), sources: entry.sources,
      }, (event) => {
        if (stopped || epoch !== copyEpoch) return
        if (event.event === "mapping") setCopyMappings((entries) => [...entries, ...event.entries])
        if (event.event === "review") { setCopyReview(event); setCopyStage("review") }
        if (event.event === "progress") { setCopied(event.bytes); setCopyStage(event.phase) }
        if (event.event === "finished") setCopyStage("reconciling")
      })
      running = copy
      void finishCopy(copy, entry, approval, epoch, !!media)
    } catch { if (!stopped) { setCopyStage(undefined); setNotice("The copy could not be prepared. Check the runtime before confirming again."); if (current()) { setPage("outcome"); } } }
    finally { if (!stopped) setWorking(false) }
  }

  async function approveCopy() {
    const copy = running
    const review = copyReview()
    const entry = current()
    const epoch = copyEpoch
    const approval = decision
    if (!copy || !review || !entry || !approval || working() || props.blocked || copyStage() !== "review") return
    let allowed = false
    setWorking(true)
    try {
      const state = await props.runtime.status()
      const opened = state.idle_lock.safes.find((safe) => safe.opening.safe_id === entry.safe && !safe.closing)?.opening
      if (stopped || epoch !== copyEpoch || running !== copy) return
      if (!state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opened || opened.nonce !== entry.opening || props.opening && props.opening !== opened.nonce) { void cancelCopy(); return }
      allowed = true
    } catch { void cancelCopy() }
    finally { if (!stopped && epoch === copyEpoch) setWorking(false) }
    if (!allowed || stopped || epoch !== copyEpoch || running !== copy) return
    setCopyStage("copying")
    approval.requested = true
    try { await copy.approve(review.summary.manifest_sha256) }
    catch { await cancelCopy() }
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
    finally { if (!stopped) { setWorking(false); await refresh(); if (reference()?.location === "inventory" && recordsScope() !== "recent") await listTransfers(recordsScope() === "export" ? "export" : "import", inventoryCursors()) } }
  }

  function back() {
    if (page() === "transfer" && running) { void cancelCopy(); return }
    if (working() || copyStage()) return
    if (page() === "usb-source") { void endUsb(false); return }
    if (page() === "menu") { props.back(); return }
    if (page() === "recover" || page() === "discard") { setConfirmation(undefined); setPage("outcome"); return }
    if (page() === "outcome") { setPage("records"); setSelected(0); return }
    if (page() === "record-destination") { setPage("records"); if (recordsScope() !== "recent") void listTransfers(recordsScope() === "export" ? "export" : "import"); return }
    if (page() === "records") { inventoryEpoch++; setInventoryBusy(false) }
    setPage("menu"); setSelected(0)
  }

  function continueSelection() {
    if (!sources().length) return
    setName(sources().length === 1 ? path.basename(sources()[0]!) : operation() === "import" ? "Imported files" : "Exported files")
    setPage(operation() === "import" || sources().length > 1 ? "name" : "destination")
  }

  async function refreshUsb() {
    if (working() || !props.runtime.usb) return
    setWorking(true); setSelected(0); setDevices([]); setNotice(""); setPage("usb-devices")
    try {
      const result = liveMedia.parse(await props.runtime.query(["runtime", "live-media", "--json"]))
      if (!stopped) setDevices(result.devices)
    } catch { if (!stopped) setNotice("USB media could not be inspected. Press R to retry.") }
    finally { if (!stopped) setWorking(false) }
  }

  async function openUsb(device: LiveDevice) {
    if (working() || props.blocked || !props.runtime.usb) return
    setWorking(true); setNotice("")
    try {
      if (!await props.run(["safe", "open", props.safe]) || stopped) return
      const state = await props.runtime.status()
      const opening = state.idle_lock.safes.find((entry) => entry.opening.safe_id === props.safe && !entry.closing)?.opening.nonce
      if (stopped) return
      if (!state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opening || props.opening && props.opening !== opening) throw new Error("The Safe is no longer open.")
      setUsb({ device, opening, browser: props.runtime.usb.open(props.safe, device.id, opening) })
      setOperation("import"); setSources([]); setPage("usb-source")
    } catch { if (!stopped) setNotice("The USB could not be opened for this Safe. Refresh media and retry.") }
    finally { if (!stopped) setWorking(false) }
  }

  async function endUsb(keepSelection: boolean) {
    const media = usb()
    if (!media || working()) return
    setWorking(true); setNotice("")
    try {
      await media.browser.close()
      if (stopped || usb() !== media) return
      if (keepSelection && !props.blocked && props.opening === media.opening) { continueSelection(); return }
      setUsb(undefined); setSources([]); setPage("usb-devices"); setSelected(0)
    } catch {
      if (!stopped && usb() === media) {
        setUsb(undefined); setSources([]); setPage("usb-devices"); setSelected(0)
        setNotice("USB removal was not confirmed. Check the runtime before continuing.")
      }
    } finally { if (!stopped) setWorking(false) }
  }

  const actions = () => [
    { name: "Import", description: "Choose local files or folders across directories. A verified copy is published into this Safe's writable workspace.", action: "Choose source", disabled: props.blocked, run: () => { setUsb(undefined); setOperation("import"); setSources([]); setPage("source") } },
    ...(props.runtime.usb ? [{ name: "Import from USB", description: "Open a separate USB device in an isolated transfer VM. Choose files to copy into this Safe's workspace.", action: "Choose USB", disabled: props.blocked, run: () => { setUsb(undefined); void refreshUsb() } }] : []),
    { name: "Export", description: "Choose files or folders under workspace and imports, then a destination on this computer.", action: "Choose Safe files", disabled: props.blocked, run: () => { void props.run(["safe", "open", props.safe]).then((ok) => { if (ok) { setUsb(undefined); setOperation("export"); setSources([]); setPage("guest") } }) } },
    { name: "Transfers and recovery", description: "Find receiver records after restarting this manager. Inspect current status before recovering or discarding; no copy is retried automatically.", action: "Inspect transfers", run: () => showTransfers() },
  ]
  const label = () => observed()?.state === "published" ? "Copy completed and verified."
    : observed()?.state === "ready" ? "Verified copy · publication unconfirmed"
    : observed()?.state === "incomplete" ? "Copy incomplete · inspect staging"
    : observed()?.state === "discarded" ? "Private staging discarded"
    : "Outcome unknown · inspect before another copy"
  const description = () => { const entry = current(); const device = page() === "transfer" ? usb()?.device : undefined; return entry ? `${entry.kind === "import" ? "Import" : "Export"} · ${props.name}${device ? ` · USB ${device.name}` : ""}\nOperation ${entry.id}` : "Choose a recorded operation." }

  createEffect(on([generation, availability], () => {
    const media = usb()
    if (page() === "usb-source" && media && (props.blocked || props.opening !== media.opening)) void endUsb(false)
    setObserved(undefined); setConfirmation(undefined)
    inventoryEpoch++; setInventory(undefined); setInventoryCursors([]); setInventoryDestination(undefined); setInventoryBusy(false); setInventoryNeedsOpen(false); setRecordsScope("import")
    if (reference()?.location === "inventory") { setReference(undefined); setSelected(0); if (["outcome", "recover", "discard", "record-destination"].includes(page())) setPage("records") }
    if (["recover", "discard"].includes(page())) setPage("outcome")
    const copy = running
    if (!copy) return
    const entry = details()
    const approval = decision
    running = undefined
    const epoch = ++copyEpoch
    setCopyStage("cancelling")
    void copy.cancel().catch(() => {}).then(async () => {
      if (entry && approval) { await finishCopy(copy, entry, approval, epoch, !!media); return }
      if (!stopped && epoch === copyEpoch) { setWorking(false); setCopyStage(undefined); setPage("records") }
    })
  }, { defer: true }))
  createEffect(() => { if (reference()?.location === "recent" && !details()) { setObserved(undefined); setConfirmation(undefined); setReference(undefined); setPage("records"); if (running) void cancelCopy() } })
  onCleanup(() => { stopped = true; copyEpoch++; inventoryEpoch++; void running?.cancel().catch(() => {}); void usb()?.browser.close().catch(() => {}) })
  useKeyboard((key) => {
    if (key.defaultPrevented) return
    if (page() === "transfer" && key.name === "escape") { key.preventDefault(); void cancelCopy(); return }
    if (page() === "transfer" && ["pageup", "pagedown", "home", "end"].includes(key.name)) {
      key.preventDefault()
      if (key.name === "home") reviewScroll?.scrollTo(0)
      if (key.name === "end") reviewScroll?.scrollTo(reviewScroll.scrollHeight)
      if (key.name === "pageup" || key.name === "pagedown") reviewScroll?.scrollBy((key.name === "pageup" ? -1 : 1) * Math.max(1, (reviewScroll?.viewport.height ?? 2) - 1))
      return
    }
    if (working()) return
    if (key.name === "escape" && ["menu", "records", "outcome"].includes(page())) { key.preventDefault(); back(); return }
    if (page() === "records") {
      if (key.name === "i") { key.preventDefault(); showTransfers(); return }
      if (key.name === "e") { key.preventDefault(); chooseExportReceiver(); return }
      if (key.name === "m") { key.preventDefault(); showRecent(); return }
      if (key.name === "o" && inventoryNeedsOpen()) { key.preventDefault(); void openInventorySafe(); return }
      if (recordsScope() === "recent") return
      const kind = recordsScope() === "export" ? "export" : "import"
      if (key.name === "r") { key.preventDefault(); void listTransfers(kind); return }
      if (inventoryBusy()) return
      if (key.name === "pagedown" && inventory()?.next_cursor) { key.preventDefault(); void listTransfers(kind, [...inventoryCursors(), inventory()!.next_cursor!]); return }
      if (key.name === "pageup" && inventoryCursors().length) { key.preventDefault(); void listTransfers(kind, inventoryCursors().slice(0, -1)); return }
    }
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
    <Show when={page() === "usb-devices"}><Menu title="Choose USB device" description={`Import into ${props.name} · The device will open in read-only mode.`}
      items={devices().map((device) => ({ name: device.name, badge: capacity(device.bytes), description: `Copy files from ${device.name} into the Safe workspace.`, action: "Browse files", disabled: props.blocked, run: () => {} }))}
      selected={selected()} change={setSelected} focused disabled={working()} choose={(index) => { const device = devices()[index]; if (device) void openUsb(device) }} back={back}
      toolbar={[{ title: "Refresh", key: "R", disabled: working(), run: () => { void refreshUsb() } }, { title: "Back", key: "Esc", run: back }]}
      empty={working() ? "Inspecting USB devices…" : "No available devices. Connect a separate USB drive and refresh."} />
    </Show>
    <Show when={page() === "records"}><Menu title="File transfers" description={recordsScope() === "recent" ? "Recent operations · The latest 32 references stay in this manager's RAM, including copies with an uncertain outcome."
      : recordsScope() === "import" ? `In this Safe · ${props.name}\nImports recorded in the encrypted volume. Choose an item to check its current outcome.`
      : `On this computer · ${inventoryDestination()}\nExports recorded in this folder. Choose an item to check its current outcome.`}
      items={recordsScope() === "recent" ? records().map((entry) => ({ name: `${entry.kind === "import" ? "Import" : "Export"} ${entry.name}`, badge: entry.id.slice(0, 8), description: `Operation ${entry.id}\nFrom ${entry.sources.join("\n")}\nTo ${entry.destination}`, action: "Inspect outcome", run: () => { void inspect(entry) } }))
        : (inventory()?.entries ?? []).map((entry) => ({ name: entry.name, badge: entry.operation_id.slice(0, 8), description: "Check the recorded outcome before recovering or discarding.", run: () => {} }))}
      selected={selected()} change={setSelected} focused disabled={working() || inventoryBusy()} details={recordsScope() === "recent"}
      choose={(index) => { if (recordsScope() !== "recent") { inspectInventory(index); return }; const entry = records()[index]; if (entry) void inspect(entry) }} back={back}
      toolbar={[
        { title: "In this Safe", key: "I", run: () => showTransfers() },
        { title: "Choose export folder", key: "E", run: chooseExportReceiver },
        { title: `Recent in RAM (${records().length})`, key: "M", run: showRecent },
        ...(recordsScope() !== "recent" ? [
          { title: "Refresh", key: "R", run: () => { void listTransfers(recordsScope() === "export" ? "export" : "import") } },
          ...(inventoryNeedsOpen() ? [{ title: "Open Safe", key: "O", run: () => { void openInventorySafe() } }] : []),
          { title: "Previous", key: "PageUp", disabled: !inventoryCursors().length || inventoryBusy(), run: () => { void listTransfers(recordsScope() === "export" ? "export" : "import", inventoryCursors().slice(0, -1)) } },
          { title: "Next", key: "PageDown", disabled: !inventory()?.next_cursor || inventoryBusy(), run: () => { void listTransfers(recordsScope() === "export" ? "export" : "import", [...inventoryCursors(), inventory()!.next_cursor!]) } },
        ] : []),
        { title: "Back", key: "Esc", run: back },
      ]}
      empty={recordsScope() === "recent" ? "No operations recorded in this manager yet." : inventoryBusy() ? "Reading receiver records…" : !inventory() ? "Refresh to read this receiver's records."
        : inventory()?.next_cursor ? "No records for this Safe on this page. Continue to the next page." : "No receiver records in this location."} />
      <Show when={inventory()?.skipped}><text flexShrink={0} fg={theme.feedback.info}>{inventory()!.skipped} receiver records skipped on this page.</text></Show>
    </Show>
    <Show when={page() === "record-destination"}><LocalChooser directoryOnly title="Find exported transfers" back={back} choose={(value) => { setInventoryDestination(value); showTransfers("export") }} /></Show>
    <Show when={page() === "outcome"}><PageHeader title="Copy outcome" description={description()} />
      <scrollbox flexGrow={1} minHeight={0}><box flexDirection="column" gap={1}>
        <text fg={observed()?.state === "published" ? theme.feedback.success : theme.feedback.warning}>{label()}</text>
        <Show when={details()}>{(entry) => <text fg={theme.text.muted}>{`From · ${entry().sources.join("\n")}`}</text>}</Show>
        <text fg={theme.text.muted}>{`Name · ${current()?.name}\nTo · ${current()?.kind === "export" ? path.join(current()!.destination, current()!.name) : current()?.destination}`}</text>
        <Show when={observed()?.receipt}>{(receipt) => <text fg={theme.text.muted}>{`Manifest entries · ${receipt().entries} · ${receipt().bytes.toLocaleString("en-US")} B\nSHA-256 ${receipt().manifest_sha256}`}</text>}</Show>
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
    <Show when={page() === "source" || page() === "destination"}><LocalChooser directoryOnly={page() === "destination"} back={back}
      selection={page() === "source" ? { paths: sources(), change: setSources, continue: continueSelection } : undefined} choose={(value) => {
      setDestination(value); void beginCopy()
    }} /></Show>
    <Show when={page() === "guest"}><GuestChooser safe={props.safe} runtime={props.runtime} back={back} selection={{ paths: sources(), change: setSources, continue: continueSelection }} /></Show>
    <Show when={page() === "usb-source" && !working() && usb()} keyed>{(media) => <GuestChooser safe={props.safe} runtime={props.runtime} media={media} back={back} selection={{ paths: sources(), change: setSources, continue: () => { void endUsb(true) } }} />}</Show>
    <Show when={page() === "usb-source" && working()}><BusyModal text="Disconnecting USB device" /></Show>
    <Show when={page() === "name"}><FormView form={{ title: sources().length > 1 ? "Name the collection" : "Name the imported copy", description: `${sources().length > 1 ? "One folder will contain all selected items. Destination names and overlaps are reviewed next.\n" : ""}${usb() ? `USB ${usb()!.device.name}` : operation() === "import" ? "Source on this computer" : "Source in the Safe"} · ${sources().join("\n")}`, fields: [{ id: "name", label: operation() === "import" ? "Workspace name" : "Export folder name", value: name(), validate: (value) => !value || unsafePathText.test(value) || value.includes("/") || value.includes("\\") || value === "." || value === ".." || Buffer.byteLength(value) > 255 ? "Choose a single file or folder name." : undefined }], submit: operation() === "import" ? "Review copy" : "Choose destination", run: async () => {} }} cancel={back} submit={(values) => { setName(values.name); if (operation() === "export") { setPage("destination"); return }; void beginCopy() }} /></Show>
    <Show when={page() === "transfer"}><PageHeader title={copyStage() === "review" ? operation() === "import" ? "Confirm import" : "Confirm export" : copyStage() === "copying" ? "Copying files" : copyStage() === "finalizing" ? "Finalizing copy" : copyStage() === "cancelling" ? "Cancelling copy" : "Preparing copy"} description={description()} />
      <Show when={copyStage() === "copying" || copyStage() === "finalizing"}><text flexShrink={0} fg={theme.feedback.info}>{`${copied().toLocaleString("en-US")} B / ${copyReview()?.summary.bytes.toLocaleString("en-US") ?? "?"} B transferred`}</text></Show>
      <Show when={copyStage() === "finalizing"}><text flexShrink={0} fg={theme.text.muted}>All payload bytes were sent. Verification and publication are still in progress.</text></Show>
      <scrollbox ref={(value: ScrollBoxRenderable) => { reviewScroll = value }} flexGrow={1} minHeight={0}><box flexDirection="column" gap={1}>
        <text fg={theme.text.muted}>{`From · ${sources().length === 1 ? details()?.sources[0] : `${sources().length} selected items`}\nTo · ${current()?.destination}`}</text>
        <Show when={copyReview() && copyStage() === "review"}><text fg={theme.text.base}><b>Destination names · PageUp / PageDown to scroll</b></text>
          <For each={copyMappings()}>{(mapping) => <text fg={mapping.covered_by === null ? theme.text.base : theme.text.muted}>{`${mapping.input_index + 1}. ${details()?.sources[mapping.input_index]}\n   → ${mapping.covered_by === null ? `${name()}${sources().length === 1 ? "" : `/${mapping.alias}`}` : `Included in selection ${mapping.covered_by + 1}`}`}</text>}</For>
        </Show>
        <Show when={copyReview()}>{(review) => <>
          <text fg={theme.text.base}>{`${review().summary.files.toLocaleString("en-US")} selected files · ${review().summary.directories.toLocaleString("en-US")} selected folders\n${review().summary.bytes.toLocaleString("en-US")} B total · ${review().summary.entries.toLocaleString("en-US")} manifest entries`}</text>
          <text fg={theme.text.muted}>{`Manifest SHA-256\n${review().summary.manifest_sha256}`}</text>
        </>}</Show>
        <Show when={copyStage() === "review"}><text fg={theme.feedback.info}>These counts cover the recursive selection. File contents are not transferred until you approve this manifest.</text></Show>
        <Show when={copyStage() === "review" && current()?.kind === "export"}><text fg={theme.text.muted}>Exported copies use the destination filesystem's protection.</text></Show>
        <Show when={copyStage() === "cancelling" || copyStage() === "reconciling"}><text fg={theme.feedback.warning}>Waiting for the owned copy process and checking its recorded outcome. A destination may already have been published.</text></Show>
      </box></scrollbox>
      <ActionBar focused disabled={working() || ["cancelling", "reconciling"].includes(copyStage() ?? "")} actions={[
        ...(copyStage() === "review" ? [{ title: "Approve copy", key: "Enter", run: () => { void approveCopy() } }] : []),
        { title: "Cancel copy", key: "Esc", run: () => { void cancelCopy() } },
      ]} />
    </Show>
    <Show when={props.blocked && page() !== "outcome"}><text flexShrink={0} fg={theme.feedback.warning}>{props.blocked}</text></Show>
    <Show when={notice()}><text flexShrink={0} fg={theme.feedback.warning}>{notice()}</text></Show>
    <Show when={working() || inventoryBusy() && page() === "records"}><BusyModal text={inventoryBusy() ? "Reading receiver records" : page() === "outcome" ? "Checking copy outcome" : "Checking Safe opening"} /></Show>
    <Show when={copyStage() === "preparing"}><BusyModal text="Preparing recursive copy review" cancellable cancel={() => { void cancelCopy() }} /></Show>
  </box>
}

export function LocalChooser(props: { directoryOnly: boolean; filesOnly?: boolean; title?: string; initialDirectory?: string; selection?: FileSelection; choose: (value: string) => void; back: () => void }) {
  const [current, setCurrent] = createSignal(props.initialDirectory ?? process.cwd())
  const [entries, setEntries] = createSignal<{ name: string; directory: boolean; bytes: number }[]>([])
  const [selected, setSelected] = createSignal(0)
  const [offset, setOffset] = createSignal(0)
  const [total, setTotal] = createSignal(0)
  const [error, setError] = createSignal("")
  const [working, setWorking] = createSignal(false)
  const [view, setView] = createSignal<"browse" | "path" | "review" | "basket">("browse")
  const [entered, setEntered] = createSignal("")
  const [candidates, setCandidates] = createSignal<{ path: string; directory: boolean; bytes: number }[]>([])
  const candidate = () => candidates().length === 1 ? candidates()[0] : undefined
  let stopped = false

  function parentDir() { const parent = path.dirname(current()); return parent === current() ? null : parent }
  function enterPath() { setError(""); setView("path") }
  function cancelPath() { setCandidates([]); setError(""); setView("browse") }
  function browseCandidate() { const value = candidate(); if (!value?.directory || working()) return; cancelPath(); void load(value.path) }
  function updateSelection(paths: string[]) {
    const error = selectionError(paths)
    if (error) { setError(error); return false }
    props.selection?.change(paths); setError(""); return true
  }
  function toggle(value: string) {
    const selection = props.selection
    if (!selection) { props.choose(value); return true }
    return updateSelection(selection.paths.includes(value) ? selection.paths.filter((path) => path !== value) : [...selection.paths, value])
  }
  function useCandidates() {
    if (working() || !candidates().length || props.filesOnly && candidate()?.directory) return
    const selection = props.selection
    if (!selection) { const value = candidate(); if (value) props.choose(value.path); return }
    if (updateSelection([...new Set([...selection.paths, ...candidates().map((value) => value.path)])])) cancelPath()
  }

  async function inspect(value: string, drop = false) {
    if (working()) return
    const from = view()
    if (!drop) setEntered(value)
    setWorking(true)
    setError("")
    try {
      const selected = await inspectLocalPaths(value, current(), drop)
      if (stopped || view() !== from) return
      if (selected.some(({ info }) => info.isSymbolicLink() || !info.isDirectory() && !info.isFile())) { setError("Choose a regular local file or directory. Symbolic links are not selectable."); return }
      if (props.directoryOnly && selected.some(({ info }) => !info.isDirectory())) { setError("This operation requires a directory. Choose a local folder."); return }
      setCandidates(selected.map(({ path, info }) => ({ path, directory: info.isDirectory(), bytes: info.size })))
      setView("review")
    } catch {
      if (!stopped && view() === from) setError(drop
        ? "Could not read the dropped paths. Drop existing local files or use Enter path to inspect one path at a time."
        : "Enter one existing local path or local file:// URL. Controls, remote authorities and multiple paths are not accepted.")
    }
    finally { if (!stopped) setWorking(false) }
  }

  function choose(index: number) {
    if (working()) return
    const entry = entries()[index]
    if (!entry) return
    if (entry.directory) { void load(path.join(current(), entry.name)); return }
    toggle(path.join(current(), entry.name))
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
    if (event.defaultPrevented) return
    const drop = view() === "browse" && !!props.selection
    if (!drop && view() !== "path") return
    if (drop && working()) { event.preventDefault(); return }
    if (event.bytes.length > maximumPathBytes) { event.preventDefault(); setError("Pasted paths exceed 64 KiB."); return }
    try {
      const value = new TextDecoder("utf-8", { fatal: true }).decode(event.bytes)
      if (!unsafePathText.test(value)) {
        if (drop) { event.preventDefault(); void inspect(value, true) }
        return
      }
    } catch { /* Invalid UTF-8 cannot name a selectable path. */ }
    event.preventDefault()
    setError(drop ? "Drop paths without control characters or line breaks." : "Paste one path without control characters or line breaks.")
  })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (view() === "path") return
    if (view() === "basket") return
    if (view() === "review") {
      if (candidates().length > 1) {
        if (key.name === "escape") { key.preventDefault(); cancelPath() }
        if (key.name === "return") { key.preventDefault(); useCandidates() }
        return
      }
      if (key.name === "b" && candidate()?.directory) { key.preventDefault(); browseCandidate() }
      return
    }
    if (key.name === "escape") { key.preventDefault(); props.back(); return }
    if (key.name === "p") { key.preventDefault(); enterPath(); return }
    if (key.name === "b" && props.selection) { key.preventDefault(); setView("basket"); return }
    if (key.name === "c" && props.selection?.paths.length) { key.preventDefault(); props.selection.continue(); return }
    if (key.name === "backspace") { key.preventDefault(); void load(path.dirname(current())); return }
    if (key.name === "." && props.directoryOnly) { key.preventDefault(); props.choose(current()); return }
    if (key.name === "." && props.selection) { key.preventDefault(); toggle(current()); return }
    if (key.name === "space" && !props.selection) { key.preventDefault(); const entry = entries()[selected()]; if (entry && (!props.filesOnly || !entry.directory)) props.choose(path.join(current(), entry.name)); return }
    if (key.name === "pagedown" && offset() + 100 < total()) { key.preventDefault(); void load(current(), offset() + 100) }
    if (key.name === "pageup" && offset()) { key.preventDefault(); void load(current(), Math.max(0, offset() - 100)) }
  })
  return <box flexGrow={1} minHeight={0} flexDirection="column">
    <Show when={view() === "basket" && props.selection}><SelectionBasket selection={props.selection!} back={() => setView("browse")} /></Show>
    <Show when={view() === "path"}><FormView form={{ title: "Enter local path", description: "Type, paste or drop one local path. A local file:// URL also works.",
      fields: [{ id: "path", label: "File or directory on this computer", value: entered(), validate: (value) => !value || unsafePathText.test(value) ? "Enter one path without control characters or line breaks." : undefined }],
      submit: "Inspect path", run: async () => {} }} cancel={cancelPath} submit={(values) => { void inspect(values.path) }} /></Show>
    <Show when={view() === "review" && candidate()}><FormView form={{ title: "Review local path", description: `${candidate()?.path}\n${candidate()?.directory ? "Directory" : `Regular file · ${candidate()?.bytes.toLocaleString("en-US")} B`}\n${props.filesOnly && candidate()?.directory ? "This operation accepts files. Browse this folder to choose one." : props.selection ? "Add this path to the import selection." : "Choose this path to continue to the operation's review."}`,
      fields: [], submit: props.filesOnly && candidate()?.directory ? "Browse folder" : props.selection ? "Add to selection" : candidate()?.directory ? "Choose folder" : "Choose file", run: async () => {} }} cancel={cancelPath} submit={() => { if (props.filesOnly && candidate()?.directory) { browseCandidate(); return }; useCandidates() }} /></Show>
    <Show when={view() === "review" && candidate()?.directory && !props.filesOnly}><ActionBar actions={[{ title: "Browse folder", key: "B", disabled: working(), run: browseCandidate }]} /></Show>
    <Show when={view() === "review" && candidates().length > 1}>
      <PageHeader title="Review dropped paths" description={`${candidates().length} local files and folders to add to the import selection.`} />
      <scrollbox flexGrow={1} minHeight={1} focused>
        <For each={candidates()}>{(value) => <box flexDirection="column" paddingBottom={1}>
          <text fg={theme.text.base}>{value.path}</text>
          <text fg={theme.text.muted}>{value.directory ? "Directory" : `Regular file · ${value.bytes.toLocaleString("en-US")} B`}</text>
        </box>}</For>
      </scrollbox>
      <ActionBar actions={[
        { title: "Add to selection", key: "Enter", run: useCandidates },
        { title: "Cancel", key: "Esc", run: cancelPath },
      ]} />
    </Show>
    <Show when={view() === "browse" && props.selection}><PageHeader title="Choose local files" description="Drop or paste paths in a supported terminal. Enter opens folders. Space selects." />
      <FilePicker currentDir={current()} parentDir={parentDir()} entries={entries().map((entry) => ({ ...entry, path: path.join(current(), entry.name) }))} selected={props.selection!.paths} focused busy={working()}
        next={offset() + 100 < total()} previous={offset() > 0} onNavigate={(next) => { void load(next) }} onChange={updateSelection}
        onNext={() => { void load(current(), offset() + 100) }} onPrevious={() => { void load(current(), Math.max(0, offset() - 100)) }} onBack={props.back} />
      <ActionBar actions={[
        { title: "Enter path", key: "P", run: enterPath },
        { title: `Selected items (${props.selection!.paths.length})`, key: "B", run: () => setView("basket") },
        { title: "Select this folder", key: ".", run: () => toggle(current()) },
        { title: "Continue", key: "C", disabled: !props.selection!.paths.length, run: props.selection!.continue },
      ]} />
    </Show>
    <Show when={view() === "browse" && !props.selection}><Menu title={props.title ?? (props.directoryOnly ? "Choose destination directory" : "Choose a local file or folder")} description={`${current()}\n${props.filesOnly ? "Space chooses a file" : "Space chooses an entry"} · Enter opens folders · ${total()} entries`} selected={selected()} change={setSelected} focused disabled={working()}
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

export function GuestChooser(props: { safe: string; runtime: NativeRuntime; media?: { device: LiveDevice; browser: UsbBrowser }; selection: FileSelection; back: () => void }) {
  const [page, setPage] = createSignal<z.infer<typeof directory>>({ path: "", entries: [], next_cursor: null })
  const [cursors, setCursors] = createSignal<string[]>([])
  const [working, setWorking] = createSignal(false)
  const [error, setError] = createSignal("")
  const [basket, setBasket] = createSignal(false)
  let stopped = false
  function parentDir() { if (!page().path) return null; const parent = path.posix.dirname(page().path); return parent === "." ? "" : parent }
  async function load(path: string, history: string[] = []) {
    if (working()) return
    setWorking(true)
    try {
      const cursor = history.at(-1)
      const next = directory.parse(await (props.media ? props.media.browser.page(path, cursor)
        : props.runtime.query(["files", "list", "--safe", props.safe, ...(path ? [path] : []), "--json", ...(cursor ? ["--cursor", cursor] : [])])))
      if (!stopped) { setPage(next); setCursors(history); setError("") }
    } catch { if (!stopped) setError(props.media ? "This USB folder is unavailable. Return to the device list to retry." : "Safe files are unavailable. Return and reopen Files to retry.") }
    finally { if (!stopped) setWorking(false) }
  }
  onMount(() => { void load("") })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented) return
    if (props.media && working() && key.name === "escape") { key.preventDefault(); props.back(); return }
    if (working() || basket()) return
    if (key.name === "b") { key.preventDefault(); setBasket(true) }
    if (key.name === "c" && props.selection.paths.length) { key.preventDefault(); props.selection.continue() }
  })
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={basket()}><SelectionBasket selection={props.selection} back={() => setBasket(false)} /></Show>
    <Show when={!basket()}><PageHeader title={props.media ? `Browse USB ${props.media.device.name}` : "Choose Safe files"} description={props.media ? "Read-only USB · Space selects files or folders. Continue when your selection is ready." : "Select files or folders across workspace and imports. Space selects; continue when your selection is ready."} />
    <FilePicker currentDir={`/${page().path}`} parentDir={parentDir()} entries={page().entries.map((entry) => ({ ...entry, directory: entry.kind === "directory" }))} selected={props.selection.paths} focused busy={working()}
      next={!!page().next_cursor} previous={!!cursors().length} onNavigate={(path) => { void load(path) }} onChange={(paths) => { const error = selectionError(paths); if (error) { setError(error); return }; props.selection.change(paths); setError("") }}
      onNext={() => { const cursor = page().next_cursor; if (cursor) void load(page().path, [...cursors(), cursor]) }}
      onPrevious={() => { void load(page().path, cursors().slice(0, -1)) }} onBack={props.back} />
    <ActionBar actions={[{ title: `Selected items (${props.selection.paths.length})`, key: "B", run: () => setBasket(true) }, { title: "Continue", key: "C", disabled: !props.selection.paths.length, run: props.selection.continue }]} /></Show>
    <Show when={error()}><text fg={theme.feedback.warning}>{error()}</text></Show>
    <Show when={working()}><BusyModal text={props.media ? "Reading USB files" : "Reading Safe files"} /></Show>
  </box>
}
