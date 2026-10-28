import { useKeyboard, useTerminalDimensions } from "@opentui/solid"
import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { SelectList } from "@opencode/tui-kit"
import { BusyModal } from "./busy-modal"
import { ControlError, type Request } from "./control"
import { createOnionRecipient, onionAccess, onionCopySocket, onionStatus, onionVerified, type OnionStatus } from "./onion"
import { FormView } from "./form"
import { capacity } from "./state"
import { PageHeader } from "./page-header"
import { palette, theme } from "./theme"
import { connectTransfer, type Offer, type Transfer } from "./transfer"

export function OnionShare(props: {
  request: (value: Request) => Promise<string>
  connect?: (id: string) => Promise<Transfer>
  paths: string[]
  backup?: { id: string; title: string }
  back: () => void
}) {
  const dimensions = useTerminalDimensions()
  const spacious = () => dimensions().width >= 110 && dimensions().height >= 32
  const recipient = createOnionRecipient()
  const [status, setStatus] = createSignal<OnionStatus>()
  const [offer, setOffer] = createSignal<Offer>()
  const [address, setAddress] = createSignal("")
  const [reveal, setReveal] = createSignal(false)
  const [busy, setBusy] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [observedAt, setObservedAt] = createSignal(0)
  const [clock, setClock] = createSignal(performance.now())
  let preparation: Promise<OnionStatus> | undefined
  let closing: Promise<void> | undefined
  let transfer: Transfer | undefined
  let id: string | undefined
  let owned = false
  let staging = false
  let connected = false
  let approved = false
  let publishing = false
  let checking = false
  let cancelled = false
  let disposed = false

  function cleanup() {
    recipient.dispose(); setReveal(false); setAddress("")
    transfer?.close(); transfer = undefined
    closing ??= (async () => {
      await preparation?.catch(() => undefined)
      if (!owned) return
      await onionStatus(props.request, { action: "cancel" })
      owned = false
    })().finally(() => { closing = undefined })
    return closing
  }
  async function failed(error: unknown) {
    if (disposed || cancelled) return
    setNotice(error instanceof ControlError ? `Sharing stopped (${error.code}).` : "Sharing stopped. Its status could not be verified.")
    setStatus(undefined); setBusy("Closing the stopped transfer")
    await cleanup().catch(() => setNotice("Cleanup required. Close and lock the session before continuing."))
  }
  async function update(value: OnionStatus) {
    if (disposed || cancelled) return
    if (!value.active || value.id !== id) throw new ControlError("onion_closed")
    setObservedAt(performance.now()); setStatus(value)
    if (value.phase === "ready" && value.tor_ready && !staging && !props.backup) {
      staging = true
      await update(await onionStatus(props.request, { action: "stage" }))
    }
    if (value.phase === "staging" && !connected) {
      connected = true; setBusy("Reading and hashing the selected documents")
      transfer = await (props.connect ? props.connect(id!) : connectTransfer(id!, onionCopySocket))
      const paths = props.paths.filter((path, index, all) => !all.some((parent, other) => other !== index && path.startsWith(parent+"/")))
      const manifest = await transfer.offer(paths)
      if (!disposed && !cancelled) setOffer(manifest)
    }
    if (value.phase === "staged" && approved && !publishing) {
      publishing = true
      await update(await onionStatus(props.request, { action: "share", client_auth: recipient.publicKey }))
    }
    if (value.phase === "sharing" && value.tor_ready && !address()) setAddress(await onionAccess(props.request))
  }
  async function run(label: string, task: () => Promise<void>) {
    if (busy()) return
    setBusy(label)
    try { await task() }
    catch (error) { await failed(error) }
    finally { if (!disposed) setBusy("") }
  }
  async function poll() {
    if (checking || busy() || !owned || disposed || cancelled) return
    checking = true
    try { await update(await onionStatus(props.request, { action: "status" })) }
    catch (error) { await failed(error) }
    finally { checking = false; if (!disposed) setBusy("") }
  }
  async function cancel() {
    if (cancelled) return
    cancelled = true; setBusy("Revoking sharing and closing the private transfer")
    try { await cleanup(); props.back() }
    catch { cancelled = false; setNotice("Cleanup required. Close and lock the session before continuing.") }
    finally { if (!disposed) setBusy("") }
  }
  async function confirm() {
    await run("Copying and sealing the approved documents", async () => {
      await transfer!.approve(offer()!)
      transfer!.close(); transfer = undefined
      approved = true; setOffer(undefined)
      await update(await onionStatus(props.request, { action: "status" }))
    })
  }
  const loading = () => {
    if (busy()) return busy()
    if (status()?.phase === "connecting" || (status()?.phase === "ready" && !props.backup)) return `Connecting to Tor · ${status()?.tor_progress ?? 0}%`
    if (status()?.phase === "preparing-share") return "Preparing the isolated sharing copy"
    if (status()?.phase === "staged" || status()?.phase === "starting") return "Publishing the approved private share"
    return ""
  }
  const verified = () => { const value = status(); return !!value && onionVerified(value, Math.max(0, clock()-observedAt())) }
  useKeyboard((key) => { if (key.name === "escape") { key.preventDefault(); void cancel() } })
  const timer = setInterval(() => { setClock(performance.now()); void poll() }, 1000)
  async function prepare(password?: string) { await run("Preparing a private Tor share", async () => {
    if (!props.backup && !props.paths.length) throw new ControlError("no_documents_selected")
    preparation = onionStatus(props.request, props.backup ? { action: "prepare-backup", id: props.backup.id, password: password!, ttl_seconds: 3600 } : { action: "prepare", ttl_seconds: 3600 }).then((value) => { owned = value.active; id = value.id ?? undefined; return value })
    await update(await preparation)
  }) }
  onMount(() => { if (!props.backup) void prepare() })
  onCleanup(() => { disposed = true; clearInterval(timer); void cleanup().catch(() => undefined) })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={spacious() ? 1 : 0}>
    <Show when={!props.backup}><PageHeader title={offer() ? "Review Tor share" : "Share over Tor"} description="Only an approved copy enters the separate sharing VM. Your session filesystem is never exposed." /></Show>
    <Show when={props.backup && !status() && !notice()}><FormView form={{ title: "Share encrypted backup over Tor", description: `${props.backup?.title}\nOblivion opens the session offline to checkpoint metadata, then closes and locks it. Only the read-only LUKS2 ciphertext enters the sharing VM. API keys are excluded.`, fields: [{ id: "password", label: "Session password", secret: true, validate: (value) => value ? undefined : "Enter the session password." }], submit: "Prepare encrypted backup", run: async (values) => prepare(values.password) }} cancel={() => { void cancel() }} submit={(values) => { void prepare(values.password) }} /></Show>
    <Show when={props.backup && status()?.phase === "ready"}><FormView form={{ title: "Review encrypted backup share", description: `${props.backup?.title} · ${capacity(status()?.progress?.bytes ?? 0)}\nThe original session stays locked. The recipient needs this temporary address, its access key, and the separate session password to restore it. Sharing expires within one hour.`, fields: [], submit: "Confirm and start sharing", run: async () => update(await onionStatus(props.request, { action: "share", client_auth: recipient.publicKey })) }} cancel={() => { void cancel() }} submit={() => { void run("Publishing the encrypted backup", async () => update(await onionStatus(props.request, { action: "share", client_auth: recipient.publicKey }))) }} /></Show>
    <Show when={offer()}>{(value) => <>
      <text fg={theme.text.base}>{value().entries.length} entries · {value().bytes.toLocaleString("en-US")} bytes</text>
      <SelectList theme={palette} focused={false} items={value().entries.map((entry) => ({ title: `${entry.kind === "directory" ? "/" : " "} ${entry.path}` }))} />
      <text fg={theme.text.muted}>Confirming publishes readable copies to people who receive the temporary address and access key.</text>
      <SelectList theme={palette} height={2} focused={!loading()} items={[{ title: "Confirm and start sharing" }, { title: "Cancel" }]} onSelect={(index) => { void (index === 0 ? confirm() : cancel()) }} />
    </>}</Show>
    <Show when={status()?.phase === "sharing"}>
      <Show when={props.backup}><PageHeader title="Encrypted backup over Tor" description={`${props.backup?.title} · the original session remains locked.`} /></Show>
      <text fg={verified() ? theme.feedback.success : theme.feedback.warning}>{verified() ? props.backup ? "Tor verified · encrypted backup is shared" : "Tor verified · approved files are shared" : "Waiting for verified Tor status"}</text>
      <Show when={verified() && address()}>
        <text fg={theme.text.muted}>Temporary address</text><text fg={theme.text.base} wrapMode="char">{address()}</text>
        <text fg={theme.text.muted}>Access key</text><text fg={theme.text.base} wrapMode="char">{reveal() ? recipient.reveal() : "Hidden · choose Show access key"}</text>
      </Show>
      <text fg={theme.text.muted}>{(status()?.progress?.transferred_bytes ?? 0).toLocaleString("en-US")} bytes served · expires within one hour</text>
      <box flexGrow={1} />
      <SelectList theme={palette} height={2} focused={!loading()} items={[{ title: "Stop sharing and return" }, { title: reveal() ? "Hide access key" : "Show access key" }]} onSelect={(index) => { if (index === 0) { void cancel(); return }; setReveal((value) => !value) }} />
    </Show>
    <Show when={!offer() && status()?.phase !== "sharing" && (!props.backup || !!notice())}><box flexGrow={1} /><SelectList theme={palette} height={1} focused={!loading()} items={[{ title: props.backup ? "Back to destinations" : "Back to Documents" }]} onSelect={() => { void cancel() }} /></Show>
    <text fg={notice() ? theme.feedback.error : theme.text.muted}>{notice() || "↑↓ Select · Enter Confirm · Esc Cancel"}</text>
    <Show when={loading()}><BusyModal text={loading()} cancellable /></Show>
  </box>
}
