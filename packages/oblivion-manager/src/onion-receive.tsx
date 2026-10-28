import { useKeyboard, useTerminalDimensions } from "@opentui/solid"
import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { SelectList } from "@opencode/tui-kit"
import { BusyModal } from "./busy-modal"
import { ControlError, type Request } from "./control"
import { createOnionRecipient, onionAccess, onionStatus, onionVerified, type OnionStatus } from "./onion"
import { PageHeader } from "./page-header"
import { palette, theme } from "./theme"

export function OnionReceive(props: {
  request: (value: Request) => Promise<string>
  back: () => void
  import: (id: string) => Promise<void>
}) {
  const dimensions = useTerminalDimensions()
  const spacious = () => dimensions().height >= 32 && dimensions().width >= 110
  const recipient = createOnionRecipient()
  const [status, setStatus] = createSignal<OnionStatus>()
  const [address, setAddress] = createSignal("")
  const [reveal, setReveal] = createSignal(false)
  const [busy, setBusy] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [observedAt, setObservedAt] = createSignal(0)
  const [clock, setClock] = createSignal(performance.now())
  let preparation: Promise<OnionStatus> | undefined
  let closing: Promise<void> | undefined
  let id: string | undefined
  let owned = false
  let started = false
  let handedOff = false
  let checking = false
  let disposed = false
  let cancelled = false

  function cleanup() {
    recipient.dispose(); setReveal(false); setAddress("")
    closing ??= (async () => {
      await preparation?.catch(() => undefined)
      if (!owned) return
      await onionStatus(props.request, { action: "cancel" })
      owned = false
    })().finally(() => { closing = undefined })
    return closing
  }

  async function failed(error: unknown) {
    if (disposed) return
    setNotice(error instanceof ControlError ? `Transfer stopped (${error.code}).` : "Transfer stopped. Its status could not be verified.")
    setStatus(undefined); setBusy("Closing the stopped transfer")
    await cleanup().catch(() => setNotice("Cleanup required. Close and lock the session before continuing."))
  }

  async function update(value: OnionStatus) {
    if (cancelled || disposed) return
    if (!value.active || value.id !== id) throw new ControlError("onion_closed")
    setObservedAt(performance.now())
    setStatus(value)
    if (value.phase === "ready" && value.tor_ready && !started) {
      started = true; setBusy("Starting the private receiver")
      await update(await onionStatus(props.request, { action: "receive", client_auth: recipient.publicKey }))
    }
    if (value.phase === "receiving" && value.tor_ready && !address()) setAddress(await onionAccess(props.request))
    if (value.phase === "copying" && !handedOff) {
      handedOff = true; owned = false; recipient.dispose()
      await props.import(id!)
    }
  }

  async function run(label: string, task: () => Promise<void>) {
    if (busy()) return
    setBusy(label)
    try { await task() }
    catch (error) { await failed(error) }
    finally { if (!disposed) setBusy("") }
  }

  async function poll() {
    if (checking || busy() || !owned || cancelled || disposed || handedOff) return
    checking = true
    try { await update(await onionStatus(props.request, { action: "status" })) }
    catch (error) { await failed(error) }
    finally { checking = false; if (!disposed) setBusy("") }
  }

  async function cancel() {
    if (cancelled) return
    cancelled = true; setBusy("Closing the private transfer")
    try { await cleanup(); props.back() }
    catch { cancelled = false; setNotice("Cleanup required. Close and lock the session before continuing.") }
    finally { if (!disposed) setBusy("") }
  }

  const loading = () => {
    if (cancelled) return "Closing the private transfer"
    if (busy()) return busy()
    if (status()?.phase === "connecting" || status()?.phase === "ready") return status()?.tor_progress === null ? "Waiting for verified Tor status" : `Connecting to Tor · ${status()?.tor_progress ?? 0}%`
    if (status()?.phase === "starting") return "Starting the private receiver"
    if (status()?.phase === "freezing") return "Revoking access and preparing file review"
    if (status()?.phase === "preparing-import") return "Preparing the secure import channel"
    return ""
  }
  const verified = () => { const value = status(); return !!value && onionVerified(value, Math.max(0, clock() - observedAt())) }
  const actions = () => status()?.phase === "receiving" ? [
    { title: "Stop receiving and review", run: () => run("Revoking access and preparing file review", async () => { recipient.dispose(); setReveal(false); setAddress(""); await update(await onionStatus(props.request, { action: "freeze" })) }) },
    { title: reveal() ? "Hide access key" : "Show access key", run: () => setReveal((value) => !value) },
    { title: "Cancel transfer", run: cancel },
  ] : status()?.phase === "review" ? [
    { title: "Choose files to import", run: () => run("Preparing the secure import channel", async () => update(await onionStatus(props.request, { action: "import" }))) },
    { title: "Discard received files", run: cancel },
  ] : [{ title: "Back to Documents", run: cancel }]

  useKeyboard((key) => { if (key.name === "escape") { key.preventDefault(); void cancel() } })
  const timer = setInterval(() => { setClock(performance.now()); void poll() }, 1000)
  onMount(() => { void run("Preparing a private Tor transfer", async () => {
    preparation = onionStatus(props.request, { action: "prepare", ttl_seconds: 3600 }).then((value) => { owned = value.active; id = value.id ?? undefined; return value })
    await update(await preparation)
  }) })
  onCleanup(() => { disposed = true; clearInterval(timer); recipient.dispose(); if (!handedOff) void cleanup().catch(() => undefined) })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={spacious() ? 1 : 0}>
    <PageHeader title="Receive over Tor" description="Files stay in a separate temporary VM until you review and approve an import." />
    <Show when={status()?.phase === "receiving"}>
      <text fg={verified() ? theme.feedback.success : theme.feedback.warning}>{verified() ? "Tor verified · private receiver published" : "Waiting for verified Tor status"}</text>
      <Show when={verified() && address()}>
        <box flexShrink={0} flexDirection="column" gap={spacious() ? 1 : 0} paddingLeft={1} paddingRight={1} paddingTop={spacious() ? 1 : 0} paddingBottom={spacious() ? 1 : 0} border borderColor={theme.border.base}>
          <text fg={theme.text.muted}>Temporary address</text>
          <text fg={theme.text.base} wrapMode="char">{address()}</text>
          <text fg={theme.text.muted}>Access key</text>
          <text fg={theme.text.base} wrapMode="char">{reveal() ? recipient.reveal() : "Hidden · choose Show access key"}</text>
        </box>
        <text fg={theme.text.muted}>Open the address in Tor Browser and enter the access key when asked.</text>
      </Show>
      <text fg={theme.text.muted}>{status()?.progress?.files ?? 0} files · {(status()?.progress?.bytes ?? 0).toLocaleString("en-US")} bytes received</text>
      <text fg={theme.text.muted}>Up to 256 MiB / 1,024 entries · expires within one hour.</text>
    </Show>
    <Show when={status()?.phase === "review"}>
      <text fg={theme.feedback.success}>Receiving stopped · Tor address revoked</text>
      <text fg={theme.text.muted}>The intake is sealed. Choose files, review their manifest, then confirm the copy into session imports.</text>
    </Show>
    <box flexGrow={1} />
    <SelectList theme={palette} height={actions().length} items={actions().map((action) => ({ title: action.title }))} focused={!loading() && !cancelled} disabled={!!loading()} onSelect={(index) => { void actions()[index]?.run() }} />
    <text fg={notice() ? theme.feedback.error : theme.text.muted}>{notice() || "↑↓ Select · Enter Open · Esc Cancel"}</text>
    <Show when={loading()}><BusyModal text={loading()} cancellable /></Show>
  </box>
}
