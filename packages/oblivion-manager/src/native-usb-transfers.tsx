import { useKeyboard } from "@opentui/solid"
import { createEffect, createSignal, on, onCleanup, onMount, Show } from "solid-js"
import { z } from "zod"
import { ActionBar } from "./action-bar"
import { BusyModal } from "./busy-modal"
import { FormView } from "./form"
import { Menu } from "./menu"
import { capacity, type NativeRuntime } from "./native-control"
import { fileReceipt } from "./native-file-transfers"
import { liveMedia, type LiveDevice } from "./native-usb"
import { PageHeader } from "./page-header"
import { theme } from "./theme"

const id = z.string().regex(/^[0-9a-f]{32}$/)
const digest = z.string().regex(/^[0-9a-f]{64}$/)
const inventory = z.object({ result: z.literal("inventory"), operations: z.array(id).max(8), next_cursor: id.nullable() }).strict().refine((value) =>
  value.operations.every((operation, index) => index === 0 || operation > value.operations[index - 1]!)
  && (!value.next_cursor || value.next_cursor === value.operations.at(-1)))
const status = z.object({ operation_id: id, state: z.enum(["unknown", "incomplete", "ready", "published", "discarded"]), receipt: fileReceipt.nullable(), review_sha256: digest.nullable() }).strict().refine((value) =>
  (value.receipt === null || value.receipt.id === value.operation_id)
  && !!value.receipt === (value.state === "ready" || value.state === "published")
  && !!value.review_sha256 === (value.state === "ready" || value.state === "incomplete"))
const statusResponse = z.object({ result: z.literal("status"), status }).strict()
type UsbStatus = z.infer<typeof status>
type Binding = { device: LiveDevice; opening: string }
type Change = "recover" | "discard"

const labels: Record<UsbStatus["state"], string> = {
  unknown: "No verifiable export record found on this USB.",
  incomplete: "Incomplete staging",
  ready: "Staging verified against the USB manifest",
  published: "Published and verified against the USB manifest",
  discarded: "Staging discarded",
}

export function NativeUsbTransfers(props: {
  safe: string; name: string; opening?: string; blocked?: string; operation?: string; expectedManifest?: string
  runtime: NativeRuntime; run: (args: string[]) => Promise<boolean>; back: () => void
}) {
  const [page, setPage] = createSignal<"devices" | "inventory" | "outcome" | "confirm">("devices")
  const [devices, setDevices] = createSignal<LiveDevice[]>([])
  const [binding, setBinding] = createSignal<Binding>()
  const [operations, setOperations] = createSignal<z.infer<typeof inventory>>()
  const [cursors, setCursors] = createSignal<string[]>([])
  const [selected, setSelected] = createSignal(0)
  const [operation, setOperation] = createSignal<string>()
  const [observed, setObserved] = createSignal<UsbStatus>()
  const [confirmation, setConfirmation] = createSignal<{ action: Change; review: string }>()
  const [busy, setBusy] = createSignal<string>()
  const [notice, setNotice] = createSignal("")
  let task: AbortController | undefined
  let disposed = false

  async function perform(label: string, action: (signal: AbortSignal) => Promise<void>) {
    if (task || disposed || props.blocked) return
    const current = new AbortController()
    task = current
    setBusy(label); setNotice("")
    try { await action(current.signal) }
    catch {
      if (!disposed) setNotice(current.signal.aborted ? "Operation cancelled. Check the USB state before retrying." : "The USB operation could not be confirmed. Recheck the selected device and operation.")
    } finally {
      if (task === current) { task = undefined; if (!disposed) setBusy(undefined) }
    }
  }

  function refreshDevices() {
    return perform("Inspecting USB devices", async (signal) => {
      const result = liveMedia.parse(await props.runtime.query(["runtime", "live-media", "--json"]))
      if (!signal.aborted) { setDevices(result.devices); setSelected(0) }
    })
  }

  async function request(current: Binding, signal: AbortSignal, args: string[]) {
    const execute = props.runtime.usb?.operate
    if (!execute || signal.aborted || props.blocked) throw new Error("USB operation unavailable")
    return execute([...args, "--safe", props.safe, "--opening", current.opening, "--usb", current.device.id], signal)
  }

  async function inventoryPage(current: Binding, signal: AbortSignal, history: string[]) {
    const after = history.at(-1)
    const result = inventory.parse(await request(current, signal, ["transfers", "--limit", "8", ...(after ? ["--cursor", after] : [])]))
    if (after && result.operations.some((operation) => operation <= after)) throw new Error("USB inventory changed")
    if (!signal.aborted) { setOperations(result); setCursors(history); setPage("inventory"); setSelected(0) }
  }

  async function readStatus(current: Binding, signal: AbortSignal, id: string) {
    const result = statusResponse.parse(await request(current, signal, ["status", "--operation", id])).status
    if (result.operation_id !== id) throw new Error("USB operation changed")
    if (!signal.aborted) { setObserved(result); setOperation(id); setPage("outcome") }
  }

  function chooseDevice(device: LiveDevice) {
    return perform("Opening USB read-only", async (signal) => {
      if (!props.opening && !await props.run(["safe", "open", props.safe])) throw new Error("Open the Safe to inspect USB operations")
      const state = await props.runtime.status()
      const opening = state.idle_lock.safes.find((entry) => entry.opening.safe_id === props.safe && !entry.closing)?.opening.nonce
      if (!state.app_open || !state.idle_lock.host || state.idle_lock.host.closing || !opening || props.opening && props.opening !== opening) throw new Error("Safe opening changed")
      if (signal.aborted) return
      const current = { device, opening }
      setBinding(current); setOperations(undefined); setObserved(undefined)
      if (props.operation) await readStatus(current, signal, props.operation)
      else await inventoryPage(current, signal, [])
    })
  }

  function loadInventory(history: string[] = []) {
    const current = binding()
    if (current) void perform("Reading USB export records", (signal) => inventoryPage(current, signal, history))
  }

  function inspect(id: string) {
    const current = binding()
    if (current) void perform("Verifying USB operation", (signal) => {
      setObserved(undefined)
      return readStatus(current, signal, id)
    })
  }

  const digestChanged = () => !!props.expectedManifest && !!observed()?.receipt && observed()?.receipt?.manifest_sha256 !== props.expectedManifest
  const writable = () => !!binding() && !binding()?.device.read_only && !props.blocked
    && (!props.expectedManifest || observed()?.receipt?.manifest_sha256 === props.expectedManifest)

  function prepare(action: Change) {
    const snapshot = observed()
    if (!writable() || busy() || !snapshot?.review_sha256 || action === "recover" && snapshot.state !== "ready") return
    setConfirmation({ action, review: snapshot.review_sha256 }); setPage("confirm")
  }

  function apply() {
    const current = binding()
    const change = confirmation()
    const snapshot = observed()
    if (!current || !change || !snapshot || !writable() || snapshot.review_sha256 !== change.review || busy()) return
    setConfirmation(undefined); setObserved(undefined); setPage("outcome")
    void perform(change.action === "recover" ? "Verifying and publishing USB staging" : "Discarding USB staging", async (signal) => {
      const result = statusResponse.parse(await request(current, signal, [change.action, "--operation", snapshot.operation_id, "--confirmed-state", change.review])).status
      if (result.operation_id !== snapshot.operation_id || result.state !== (change.action === "recover" ? "published" : "discarded")
        || change.action === "recover" && result.receipt?.manifest_sha256 !== snapshot.receipt?.manifest_sha256) throw new Error("USB outcome changed")
      if (!signal.aborted) setObserved(result)
    })
  }

  function back() {
    if (busy()) { task?.abort(); return }
    setNotice("")
    if (page() === "confirm") { setConfirmation(undefined); setPage("outcome"); return }
    if (page() === "outcome" && !props.operation) { setPage("inventory"); setSelected(0); return }
    if (page() !== "devices") { setPage("devices"); setBinding(undefined); setSelected(0); return }
    props.back()
  }

  onMount(() => { void refreshDevices() })
  onCleanup(() => { disposed = true; task?.abort() })
  createEffect(on([() => props.opening, () => props.blocked], () => {
    if (!binding() || !props.blocked && props.opening === binding()?.opening) return
    task?.abort(); setBinding(undefined); setOperations(undefined); setObserved(undefined); setConfirmation(undefined); setPage("devices")
    setNotice("The Safe opening changed. Select a USB again.")
  }, { defer: true }))
  useKeyboard((key) => {
    if (key.defaultPrevented) return
    if (key.name === "escape" && page() !== "confirm") { key.preventDefault(); back(); return }
    if (busy() || props.blocked) return
    const current = page()
    if (key.name === "r") {
      if (current === "confirm") return
      key.preventDefault()
      if (current === "devices") void refreshDevices()
      if (current === "inventory") loadInventory(cursors())
      if (current === "outcome" && operation()) inspect(operation()!)
    }
    if (current === "inventory" && key.name === "pageup" && cursors().length) { key.preventDefault(); loadInventory(cursors().slice(0, -1)) }
    if (current === "inventory" && key.name === "pagedown" && operations()?.next_cursor) { key.preventDefault(); loadInventory([...cursors(), operations()!.next_cursor!]) }
    if (current === "outcome" && key.name === "c" && writable()) { key.preventDefault(); prepare("recover") }
    if (current === "outcome" && key.name === "d" && writable()) { key.preventDefault(); prepare("discard") }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={page() === "devices"}><Menu title="Inspect USB exports" description={`${props.name} · Select the device currently connected. Inspection uses read-only access.`}
      items={devices().map((device) => ({ name: device.name, badge: capacity(device.bytes), description: device.read_only ? "Read-only device" : "Review operation records before any changes.", action: "Inspect", run: () => {} }))}
      selected={selected()} change={setSelected} focused disabled={!!busy() || !!props.blocked} choose={(index) => { const device = devices()[index]; if (device) void chooseDevice(device) }}
      toolbar={[{ title: "Refresh", key: "R", run: () => { void refreshDevices() } }, { title: "Back", key: "Esc", run: back }]} empty="No available USB devices." /></Show>
    <Show when={page() === "inventory"}><Menu title="USB export operations" description={`USB ${binding()?.device.name} · Select an operation to verify its current state.`}
      items={(operations()?.operations ?? []).map((id) => ({ name: `Oblivion-${id}`, description: "Check the files and manifest recorded on this USB.", action: "Verify operation", run: () => {} }))}
      selected={selected()} change={setSelected} focused disabled={!!busy() || !!props.blocked} choose={(index) => { const id = operations()?.operations[index]; if (id) inspect(id) }}
      toolbar={[{ title: "Refresh", key: "R", run: () => loadInventory(cursors()) },
        { title: "Previous", key: "PageUp", disabled: !cursors().length, run: () => loadInventory(cursors().slice(0, -1)) },
        { title: "Next", key: "PageDown", disabled: !operations()?.next_cursor, run: () => { const next = operations()?.next_cursor; if (next) loadInventory([...cursors(), next]) } },
        { title: "Back", key: "Esc", run: back }]} empty="No recorded exports on this USB." /></Show>
    <Show when={page() === "outcome"}><PageHeader title="USB export outcome" description={`USB ${binding()?.device.name} · Oblivion-${operation()}`} />
      <text fg={theme.text.base}>{observed() ? labels[observed()!.state] : "Outcome unconfirmed"}</text>
      <Show when={observed()?.receipt}>{(receipt) => <text fg={theme.text.muted}>{`${receipt().entries} entries · ${receipt().bytes.toLocaleString("en-US")} B\nManifest SHA-256 ${receipt().manifest_sha256}`}</text>}</Show>
      <Show when={digestChanged()}><text fg={theme.feedback.warning}>The USB manifest differs from the receipt recorded by this manager.</text></Show>
      <Show when={props.expectedManifest && observed()?.state === "incomplete"}><text fg={theme.feedback.warning}>This staging could not be matched to the receipt from this manager.</text></Show>
      <Show when={observed()?.receipt}><text fg={theme.text.muted}>Verification covers the files and manifest on this USB.</text></Show>
      <Show when={observed()}><text fg={theme.text.muted}>USB released by the runtime.</text></Show>
      <box flexGrow={1} /><ActionBar focused disabled={!!busy()} actions={[
        { title: "Recheck", key: "R", run: () => { const id = operation(); if (id) inspect(id) } },
        ...(writable() && observed()?.state === "ready" ? [{ title: "Publish verified copy", key: "C", run: () => prepare("recover") }] : []),
        ...(writable() && observed()?.review_sha256 ? [{ title: "Discard staging", key: "D", run: () => prepare("discard") }] : []),
        { title: "Back", key: "Esc", run: back },
      ]} /></Show>
    <Show when={page() === "confirm"}><FormView form={{ title: confirmation()?.action === "recover" ? "Publish verified USB staging?" : "Discard USB staging?",
      description: `USB ${binding()?.device.name} · Oblivion-${operation()}\n${confirmation()?.action === "recover" ? "Publish the reviewed staging without copying the Safe files again." : "Remove the reviewed staging folder. Published exports are kept."}`,
      fields: [], submit: confirmation()?.action === "recover" ? "Publish on USB" : "Discard staging", run: async () => {} }} cancel={back} submit={apply} /></Show>
    <Show when={props.blocked || notice()}><text fg={theme.feedback.warning}>{props.blocked || notice()}</text></Show>
    <Show when={busy()}>{(text) => <BusyModal text={text()} />}</Show>
  </box>
}
