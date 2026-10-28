import { useKeyboard } from "@opentui/solid"
import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { z } from "zod"
import { BusyModal } from "./busy-modal"
import { ControlError, type Request } from "./control"
import { FormView } from "./form"
import { OnionShare } from "./onion-share"
import { Picker } from "./picker"
import { capacity } from "./state"
import { connectTransfer, devicesSchema, type Offer, type Transfer } from "./transfer"
import { theme } from "./theme"

const started = z.object({ id: z.string().regex(/^[a-f0-9]{32}$/), bytes: z.number().int().min(32 * 1024 ** 2).max(1024 ** 4) })

export function SessionBackup(props: { id: string; title: string; request: (request: Request) => Promise<string>; back: () => void }) {
  const [devices, setDevices] = createSignal<z.infer<typeof devicesSchema>["sources"]>([])
  const [onion, setOnion] = createSignal(false)
  const [target, setTarget] = createSignal<z.infer<typeof devicesSchema>["sources"][number]>()
  const [offer, setOffer] = createSignal<Offer>()
  const [saved, setSaved] = createSignal("")
  const [busy, setBusy] = createSignal("")
  const [error, setError] = createSignal("")
  const [cleanupRequired, setCleanupRequired] = createSignal(false)
  let transfer: Transfer | undefined
  let active = false
  let disposed = false
  let stopping: Promise<void> | undefined
  let preparing: Promise<z.infer<typeof started>> | undefined
  let cancelling = false

  async function command(value: object, timeoutMs?: number) {
    const payload = new TextEncoder().encode(JSON.stringify(value))
    try { return await props.request({ operation: "transfers", payload, timeoutMs }) }
    finally { payload.fill(0) }
  }
  async function stop() {
    transfer?.close(); transfer = undefined
    if (stopping) return stopping
    if (!active) return
    const pending = preparing
    stopping = (async () => {
      // Cleanup must follow the preparation reply, even if this view unmounts
      // while the controller is still opening/closing its offline VM.
      await pending?.catch(() => undefined)
      await command({ operation: "cancel" })
      active = false
    })()
    try { await stopping }
    finally { stopping = undefined }
  }
  async function run(label: string, action: () => Promise<void>) {
    if (busy()) return
    setBusy(label); setError("")
    try { await action() }
    catch (failure) {
      try { await stop() }
      catch { if (!disposed) setCleanupRequired(true); return }
      if (cancelling) return
      if (!disposed) {
        setOffer(undefined)
        setError(failure instanceof ControlError ? `Backup stopped (${failure.code}). Your original session is preserved.` : "Could not prepare or copy the backup. Check the session password, destination and free space. Your original session is preserved.")
      }
    } finally { if (!disposed) setBusy("") }
  }
  async function list() {
    const result = devicesSchema.parse(JSON.parse(await command({ operation: "list" })))
    if (result.active) throw new ControlError("transfer_already_running")
    if (!disposed) setDevices(result.sources.filter((device) => !device.read_only))
  }
  async function prepare(password: string) {
    // A failed controller start may still need mapping cleanup. The caller's
    // normal error path therefore cancels even before an operation ID arrives.
    active = true
    const pending = command({ operation: "backup", id: props.id, target: target()!.id, password }, 360_000).then((value) => started.parse(JSON.parse(value)))
    preparing = pending
    const result = await pending.finally(() => { if (preparing === pending) preparing = undefined })
    if (disposed) { await stop(); return }
    transfer = await connectTransfer(result.id, undefined, { entries: 1, bytes: result.bytes, budgetMs: 3_600_000 })
    if (disposed) { await stop(); return }
    const manifest = await transfer.offer(["session.oblivion"])
    if (manifest.entries.length !== 1 || manifest.entries[0].kind !== "file" || manifest.entries[0].path !== "session.oblivion" || manifest.bytes !== result.bytes) throw new ControlError("invalid_manifest")
    if (!disposed) setOffer(manifest)
  }
  async function copy() {
    const receipt = await transfer!.approve(offer()!)
    await stop()
    if (!disposed) { setSaved(`Oblivion-${receipt.id}/files/session.oblivion`); setOffer(undefined) }
  }
  async function cancel() {
    if (cancelling) return
    cancelling = true
    setBusy("Stopping backup and releasing media")
    try { await stop(); if (!disposed) props.back() }
    catch { if (!disposed) setCleanupRequired(true) }
    finally { cancelling = false; if (!disposed) setBusy("") }
  }
  useKeyboard((key) => {
    if (key.name === "escape" && busy() && transfer) { key.preventDefault(); key.stopPropagation(); void cancel(); return }
    if (key.ctrl && key.name === "r" && !busy() && !target()) { key.preventDefault(); key.stopPropagation(); void run("Refreshing destinations", list) }
  })
  onMount(() => { void run("Reading backup destinations", list) })
  onCleanup(() => { disposed = true; transfer?.close(); if (active) void stop().catch(() => {}) })

  return <Show when={onion()} fallback={<box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={!busy()}><Show when={!cleanupRequired()} fallback={<FormView form={{ title: "Backup cleanup required", description: "Cleanup has not been verified. Return to the manager and lock Oblivion to complete recovery before opening another session.", fields: [], submit: "Return to manager", run: async () => props.back() }} cancel={props.back} submit={props.back} />}>
      <Show when={!saved()} fallback={<FormView form={{ title: "Encrypted backup saved", description: `Destination: ${target()?.name}\n${saved()}\nThe session password is still required to unlock this file. The storage worker has stopped and the destination has been flushed.`, fields: [], submit: "Back to sessions", run: async () => props.back() }} cancel={props.back} submit={props.back} />}>
        <Show when={!offer()} fallback={<FormView form={{ title: "Copy encrypted backup", description: `${props.title}\nDestination: ${target()?.name} · ${capacity(offer()!.bytes)}\nAll chats, documents and session metadata stay encrypted with the session password. API keys in the general vault are excluded. The original session remains locked.`, fields: [], submit: "Copy backup", run: copy }} cancel={() => { void cancel() }} submit={() => { void run("Copying encrypted volume · waiting for verification and media flush", copy) }} />}>
          <Show when={target()} fallback={<>
            <Picker title="Back up session / Destination" description={devices().length ? `${props.title}\nSelect writable USB or prepared virtual media. The Oblivion boot drive is excluded.` : "Attach writable USB or prepared virtual media. Ctrl+R refreshes the list."}
              choices={[...devices().map((device) => ({ value: device.id, label: `${device.name} · ${device.kind === "virtual" ? "Virtual media" : "USB"}`, description: capacity(device.bytes) })), { value: "tor", label: "Share encrypted backup over Tor", description: "Private expiring download; no destination drive required." }]}
              back={props.back} choose={(id) => { if (id === "tor") { setOnion(true); return }; setTarget(devices().find((device) => device.id === id)) }} />
            <text fg={theme.text.action} onMouseDown={() => { void run("Refreshing destinations", list) }}>Refresh Ctrl+R</text>
          </>}>
            <FormView form={{ title: "Prepare encrypted backup", description: `${props.title}\nDestination: ${target()?.name}\nThis authorizes writing a new backup folder on the selected medium. Mounting may update its filesystem metadata. Oblivion briefly opens your session offline to save its title, then stops the VM and locks the volume before copying. Existing destination files are preserved.`,
              fields: [{ id: "password", label: "Session password", secret: true, validate: (value) => value ? undefined : "Enter the session password." }], submit: "Authorize and prepare", run: async (values) => prepare(values.password),
            }} cancel={() => setTarget(undefined)} submit={(values) => { void run("Preparing session offline and locking its volume", () => prepare(values.password)) }} />
          </Show>
        </Show>
      </Show>
    </Show></Show>
    <Show when={error()}><text fg={theme.feedback.error}>{error()}</text></Show>
    <Show when={busy()}><BusyModal text={busy()} cancellable={!!transfer} /></Show>
  </box>}><OnionShare paths={[]} backup={{ id: props.id, title: props.title }} request={props.request} back={() => setOnion(false)} /></Show>
}
