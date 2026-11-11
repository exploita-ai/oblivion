import path from "node:path"
import { createEffect, createMemo, createSignal, on, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard } from "@opentui/solid"
import { z } from "zod"
import { FormView } from "./form"
import { LocalChooser } from "./native-files"
import { Menu } from "./menu"
import { BusyModal } from "./busy-modal"
import { capacity, type NativeRuntime } from "./native-control"
import { theme } from "./theme"

const identifier = z.string().regex(/^[a-f0-9]{32}$/)
export const backupStatus = z.object({ transactions: z.array(z.object({
  transaction: identifier, slot: z.number().int().min(0).max(31), kind: z.enum(["export", "import"]),
  safe_id: identifier.nullable(), bytes: z.number().int().min(32 * 1024 ** 2).max(1024 ** 4).nullable(),
  outcome: z.enum(["prepared", "copying", "copied", "committed", "recovery-required", "cancelled"]), active: z.boolean(),
}).strict()).max(1024) }).strict().refine((value) => new Set(value.transactions.map((entry) => entry.transaction)).size === value.transactions.length
  && value.transactions.every((entry) => (!entry.active || entry.outcome === "copying")
    && (entry.outcome !== "committed" || entry.kind === "import" && entry.safe_id !== null)), "Invalid backup status")

export function NativeBackups(props: {
  runtime: NativeRuntime; writable: boolean; opening?: string; blocked?: string
  safe?: { id: string; name: string; persistent: boolean; closed: boolean }
  run: (args: string[]) => Promise<number>; back: () => void; initialDirectory?: string
}) {
  const [page, setPage] = createSignal<"menu" | "choose" | "name" | "review" | "records" | "record" | "discard" | "result">("menu")
  const [selected, setSelected] = createSignal(0)
  const [selection, setSelection] = createSignal<{ operation: "import" } | { operation: "export"; safe: string; name: string }>()
  const [directory, setDirectory] = createSignal(props.initialDirectory ?? process.cwd())
  const [source, setSource] = createSignal("")
  const [filename, setFilename] = createSignal("")
  const [transaction, setTransaction] = createSignal<string>()
  const [observed, setObserved] = createSignal<{ opening: string; received: number; records: z.infer<typeof backupStatus>["transactions"] }>()
  const [now, setNow] = createSignal(performance.now())
  const [loading, setLoading] = createSignal(false)
  const [working, setWorking] = createSignal(false)
  const [error, setError] = createSignal("")
  const [result, setResult] = createSignal<{ operation: "export" | "import" | "finish" | "discard"; code: number }>()
  const records = createMemo(() => observed()?.opening === props.opening ? observed()?.records ?? [] : [])
  const current = createMemo(() => records().find((entry) => entry.transaction === transaction()))
  const exportTarget = createMemo(() => { const target = selection(); return target?.operation === "export" ? target : undefined })
  const fresh = () => !!observed() && observed()?.opening === props.opening && !error() && now() - observed()!.received < 10_000
  const exportBlocked = () => !props.safe?.persistent ? "Choose a persistent Safe in Safes first." : !props.safe.closed ? "Close and lock the selected Safe before backing it up." : props.blocked
  const available = () => props.writable && !!props.opening
  const flowAvailable = () => available() && !props.blocked && (selection()?.operation === "import"
    || !!exportTarget() && props.safe?.id === exportTarget()?.safe && !exportBlocked())
  const canFinish = () => available() && fresh() && !props.blocked && current()?.kind === "import" && current()?.outcome === "copied" && !current()?.active
  const canDiscard = () => available() && fresh() && !!current() && current()?.outcome !== "committed" && !current()?.active
  const output = () => path.join(directory(), filename())
  let pending = false
  let stopped = false

  async function refresh() {
    const opening = props.opening
    if (pending || working() || !props.writable || !opening) return
    pending = true; setLoading(true)
    const selectedId = page() === "records" ? records()[selected()]?.transaction : transaction()
    try {
      const next = backupStatus.parse(await props.runtime.query(["backup", "status", "--json"]))
      if (stopped || props.opening !== opening || !props.writable) return
      setObserved({ opening, received: performance.now(), records: next.transactions })
      if (page() === "records") setSelected(Math.max(0, next.transactions.findIndex((entry) => entry.transaction === selectedId)))
      setError("")
    } catch { if (!stopped && props.opening === opening) setError("Backup status is unavailable. Refresh before taking another action.") }
    finally { pending = false; if (!stopped) setLoading(false) }
  }

  async function execute(operation: "export" | "import" | "finish" | "discard") {
    if (working() || !available()) return
    if (operation === "finish" ? !canFinish() : operation === "discard" ? !canDiscard() : !flowAvailable()) return
    const target = selection()
    if (operation === "export" && target?.operation !== "export" || (operation === "finish" || operation === "discard") && !current()) return
    const opening = props.opening
    const args = operation === "export" && target?.operation === "export" ? ["backup", "export", "--safe", target.safe, output()]
      : operation === "import" ? ["backup", "import", source()]
      : ["backup", operation, current()!.transaction]
    setWorking(true)
    try {
      const code = await props.run(args)
      if (!stopped && opening === props.opening) { setResult({ operation, code }); setPage("result") }
    } catch { if (!stopped && opening === props.opening) { setResult({ operation, code: 1 }); setPage("result") } }
    finally { if (!stopped) { setWorking(false); await refresh() } }
  }

  function start(operation: "export" | "import") {
    if (!available() || props.blocked || operation === "export" && exportBlocked()) return
    if (operation === "export" && props.safe) {
      setSelection({ operation, safe: props.safe.id, name: props.safe.name })
      setFilename(`oblivion-${props.safe.id.slice(0, 8)}.luks`)
    } else { setSelection({ operation: "import" }); setSource("") }
    setPage("choose")
  }

  function history() { setPage("records"); setSelected(Math.max(0, records().findIndex((entry) => entry.transaction === transaction()))); void refresh() }
  const label = (outcome: z.infer<typeof backupStatus>["transactions"][number]["outcome"]) => ({
    prepared: "Prepared", copying: "Copy in progress", copied: "Ciphertext verified", committed: "Safe restored", "recovery-required": "Recovery required", cancelled: "Copy stopped",
  })[outcome]
  const menu = () => [
    { name: "Create personal backup", description: props.safe ? `Complete encrypted volume of ${props.safe.name}, including saved logins and installed software. Keep its original Safe password.` : "Choose a persistent Safe first. This copies its complete encrypted volume, including saved logins.", action: "Choose destination", disabled: exportBlocked(), run: () => start("export") },
    { name: "Restore personal backup", description: "Choose a LUKS2 backup and restore its original Safe with its original password. Existing identities are never replaced. The restored Safe starts Offline.", action: "Choose backup file", disabled: props.blocked, run: () => start("import") },
    { name: "Transfer history and recovery", description: "Inspect verified copies, interrupted work and restored Safes. Finish a verified import after correcting its password, or discard incomplete data explicitly.", action: "Inspect transfers", run: history },
  ]
  const recordActions = () => [
    { name: "Finish restore", description: "Use this verified ciphertext copy without uploading it again. Enter the original Safe password privately in the terminal.", disabled: !canFinish() ? current()?.outcome === "committed" ? "This Safe was already restored. Do not restore it again." : props.blocked || "Only an inactive, verified import from this unlocked opening can be finished." : undefined, action: "Enter original password", run: () => { void execute("finish") } },
    { name: "Discard incomplete transfer", description: "Remove this transaction's unpublished data. Existing Safes and committed restores cannot be deleted by this action.", disabled: !canDiscard() ? current()?.outcome === "committed" ? "Committed restores are read-only." : "Refresh status and stop any active copy before discarding." : undefined, action: "Review discard", run: () => { if (canDiscard()) setPage("discard") } },
  ]

  onMount(() => {
    const timer = setInterval(() => { if (["records", "record", "discard"].includes(page())) void refresh() }, 5000)
    const clock = setInterval(() => setNow(performance.now()), 1000)
    onCleanup(() => { clearInterval(timer); clearInterval(clock) })
  })
  createEffect(on(() => props.opening, () => {
    setObserved(undefined); setSelection(undefined); setTransaction(undefined); setResult(undefined)
    setSource(""); setFilename(""); setError(""); setSelected(0); setPage("menu")
  }, { defer: true }))
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (key.name === "r" && ["records", "record", "discard"].includes(page())) { key.preventDefault(); void refresh(); return }
    if (key.name === "escape" && page() === "menu") { key.preventDefault(); props.back() }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={available()} fallback={<FormView form={{ title: "Personal backups", description: "Unlock writable encrypted storage to create, restore or inspect personal backups. RAM-only work cannot be backed up as a persistent volume.", fields: [], submit: "Back to Settings", run: async () => {} }} cancel={props.back} submit={props.back} />}>
      <Show when={page() === "menu"}><Menu title="Personal backups" description="Full encrypted recovery copies. Use Share to exclude saved provider login stores."
        items={menu()} selected={selected()} change={setSelected} focused choose={(index) => { const item = menu()[index]; if (item && !item.disabled) item.run() }} back={props.back} /></Show>
      <Show when={["choose", "name", "review"].includes(page())}>
        <Show when={flowAvailable()} fallback={<FormView form={{ title: "Backup cannot start", description: props.blocked || exportBlocked() || "The selected Safe or storage opening changed. No copy was started.", fields: [], submit: "Back to backups", run: async () => {} }} cancel={() => setPage("menu")} submit={() => setPage("menu")} />}>
          <Show when={page() === "choose"}><LocalChooser title={selection()?.operation === "export" ? "Choose backup destination" : "Choose a personal LUKS2 backup"} directoryOnly={selection()?.operation === "export"} filesOnly={selection()?.operation === "import"} initialDirectory={directory()} back={() => setPage("menu")} choose={(value) => {
            if (selection()?.operation === "import") { setSource(value); setDirectory(path.dirname(value)); setPage("review"); return }
            setDirectory(value); setPage("name")
          }} /></Show>
          <Show when={page() === "name"}><FormView form={{ title: "Name the personal backup", description: `Destination on this computer · ${directory()}`, fields: [{ id: "filename", label: "Backup filename", value: filename(), validate: (value) => !value || value === "." || value === ".." || /[/\\\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value) || Buffer.byteLength(value) > 255 ? "Choose a single filename of at most 255 UTF-8 bytes." : undefined }], submit: "Review backup", run: async () => {} }} cancel={() => setPage("choose")} submit={(values) => { setFilename(values.filename); setPage("review") }} /></Show>
          <Show when={page() === "review"}><FormView form={{ title: selection()?.operation === "export" ? "Review personal backup" : "Review personal restore", description: selection()?.operation === "export"
            ? `Safe · ${exportTarget()?.name}\nDestination · ${output()}\nComplete encrypted volume: chats, files, saved logins and installed software.\nKeep the original Safe password. Existing output files are never replaced.\nNext: enter the Safe password privately in the terminal.`
            : `Source · ${source()}\nRestores the original Safe identity and saved logins.\nAn existing Safe with that identity is never replaced.\nThe restored Safe starts Offline.\nNext: verify the copy and enter its original Safe password privately.`, fields: [], submit: selection()?.operation === "export" ? "Create encrypted backup" : "Restore original Safe", run: async () => {} }} cancel={() => setPage(selection()?.operation === "export" ? "name" : "choose")} submit={() => { void execute(selection()?.operation === "export" ? "export" : "import") }} /></Show>
        </Show>
      </Show>
      <Show when={page() === "records"}><Menu title="Personal backup transfers" description={`${records().length} record(s). A verified export stream alone does not prove publication of its chosen output file.`}
        items={records().map((entry) => ({ name: `${entry.kind === "export" ? "Backup" : "Restore"} ${entry.transaction.slice(0, 8)}`, badge: fresh() ? label(entry.outcome) : "Status unknown", description: `${entry.transaction}${entry.bytes ? ` · ${capacity(entry.bytes)}` : ""}${entry.safe_id ? `\nSafe · ${entry.safe_id}` : ""}`, action: "Inspect transfer", run: () => { setTransaction(entry.transaction); setSelected(0); setPage("record") } }))}
        selected={selected()} change={setSelected} focused disabled={loading()} choose={(index) => { const entry = records()[index]; if (entry) { setTransaction(entry.transaction); setSelected(0); setPage("record") } }}
        toolbar={[{ title: "Refresh", key: "R", run: () => { void refresh() } }]} empty={error() || "No personal backup transfers."} back={() => { setSelected(0); setPage("menu") }} /></Show>
      <Show when={page() === "record"}><Menu title={current()?.outcome === "committed" ? "Restored · read-only" : "Personal backup transfer"} description={current()
        ? `Transaction · ${current()!.transaction}\n${fresh() ? label(current()!.outcome) : "Status unknown · refresh before acting"}${current()!.bytes ? ` · ${capacity(current()!.bytes!)}` : ""}${current()!.safe_id ? `\nSafe · ${current()!.safe_id}` : ""}`
        : "This transaction is no longer available in the current unlocked opening. Refresh the list."} items={recordActions()} selected={selected()} change={setSelected} focused choose={(index) => { const item = recordActions()[index]; if (item && !item.disabled) item.run() }} toolbar={[{ title: "Refresh", key: "R", run: () => { void refresh() } }]} back={history} /></Show>
      <Show when={page() === "discard"}><FormView form={{ title: "Discard incomplete backup transfer?", description: `Transaction · ${transaction()}\nRemove this transaction's unpublished copy and recovery record.\nExisting Safes and committed restores are preserved. An external partial file is not deleted here.\nNext: confirm DISCARD privately in the terminal.`, fields: [], submit: "Continue to discard", run: async () => {} }} cancel={() => setPage("record")} submit={() => { void execute("discard") }} /></Show>
      <Show when={page() === "result" && result()} keyed>{(outcome) => <FormView form={{ title: outcome.code === 0 ? outcome.operation === "export" ? "Personal backup saved" : outcome.operation === "discard" ? "Incomplete transfer discarded" : "Safe restored Offline" : "Check the transfer outcome", description: outcome.code === 0
        ? outcome.operation === "export" ? `Destination · ${output()}\nThe CLI verified the copy and published the output file. Keep its original Safe password.` : outcome.operation === "discard" ? "Unpublished data was removed. Existing Safes were preserved." : "The original Safe was restored. Open Safes to review it before enabling network access."
        : "The command was interrupted, cancelled or did not complete. Inspect transfer history before retrying. A missing reply or exit code 130 does not prove that a restore was unpublished.", fields: [], submit: "Inspect transfer history", run: async () => {} }} cancel={() => { setSelected(0); setPage("menu") }} submit={history} />}</Show>
    </Show>
    <Show when={error() && ["records", "record", "discard"].includes(page())}><text flexShrink={0} fg={theme.feedback.warning}>{error()}</text></Show>
    <Show when={loading() || working()}><BusyModal text={working() ? "Preparing personal backup operation" : "Reading backup transfers"} /></Show>
  </box>
}
