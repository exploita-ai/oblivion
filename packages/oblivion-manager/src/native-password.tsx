import { useKeyboard } from "@opentui/solid"
import { createEffect, createMemo, createSignal, onCleanup, onMount, Show, untrack } from "solid-js"
import { z } from "zod"
import { BusyModal } from "./busy-modal"
import { FormView } from "./form"
import { Menu } from "./menu"
import { theme } from "./theme"
import type { NativeRuntime } from "./native-control"

const identity = z.string().regex(/^[a-f0-9]{32}$/)
const members = z.array(z.object({ safe_id: identity, title: z.string().refine((value) => !!value.trim() && value.trim() === value && Buffer.byteLength(value) <= 256 && Array.from(value).length <= 80 && !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value)) }).strict()).min(1).max(256)
  .refine((value) => new Set(value.map((member) => member.safe_id)).size === value.length)
const planSchema = z.object({ host_opening: identity, family_id: identity, members, sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict()
const entrySchema = z.object({ transaction: identity, family_id: identity, members, outcome: z.enum(["pending", "complete", "rolled-back"]) }).strict()
const statusSchema = z.object({ host_opening: identity, transactions: z.array(entrySchema).max(128).refine((value) => new Set(value.map((entry) => entry.transaction)).size === value.length) }).strict()
type Confirmation = { kind: "change"; plan: z.infer<typeof planSchema> } | { kind: "complete" | "rollback"; entry: z.infer<typeof entrySchema> }

export function NativePassword(props: {
  safe?: { id: string; name: string; persistent: boolean; closed: boolean }
  opening?: string
  openIds: string[]
  writable: boolean
  blocked?: string
  runtime: NativeRuntime
  run: (args: string[]) => Promise<number>
  back: () => void
}) {
  const [plan, setPlan] = createSignal<z.infer<typeof planSchema>>()
  const [status, setStatus] = createSignal<z.infer<typeof statusSchema>>()
  const [page, setPage] = createSignal<"family" | "recovery" | "members" | "confirm">("family")
  const [transaction, setTransaction] = createSignal<string>()
  const [confirmation, setConfirmation] = createSignal<Confirmation>()
  const [selected, setSelected] = createSignal(0)
  const [area, setArea] = createSignal<"list" | "actions">("list")
  const [loading, setLoading] = createSignal(true)
  const [working, setWorking] = createSignal(false)
  const [received, setReceived] = createSignal(0)
  const [now, setNow] = createSignal(performance.now())
  const [error, setError] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const generation = createMemo(() => props.opening ? `${props.opening}/${props.safe?.id ?? ""}` : undefined)
  const current = () => status()?.transactions.find((entry) => entry.transaction === transaction())
  const fresh = () => !!status() && status()!.host_opening === props.opening && !error() && now() - received() <= 10_000
  const pendingFamily = () => status()?.transactions.some((entry) => entry.outcome === "pending" && entry.members.some((member) => member.safe_id === props.safe?.id))
  let pending = false
  let stopped = false

  function barrier(affected?: z.infer<typeof members>) {
    if (!props.opening) return "Unlock Oblivion before changing a family password."
    if (!props.writable) return "Writable encrypted storage is required. These records are read-only."
    if (props.blocked) return props.blocked
    if (affected?.some((member) => props.openIds.includes(member.safe_id))) return "Close every listed family member before continuing. Other families can stay open."
    return undefined
  }

  const changeBlocked = () => barrier(plan()?.members) ?? (!props.safe?.persistent ? "Choose a persistent Safe. RAM-only Safes have no saved family password."
    : !props.safe.closed ? "Close the selected Safe and every other member of its family first."
    : pendingFamily() ? "This family has a pending password update. Open Recovery to complete or roll it back."
    : !fresh() || !plan() ? "Refresh the family review before continuing."
    : undefined)
  const recoveryBlocked = () => barrier(current()?.members) ?? (!fresh() ? "Refresh password status before continuing."
    : current()?.outcome !== "pending" ? "This finished transaction is read-only."
    : undefined)

  async function read(includePlan: boolean) {
    const expected = generation()
    if (!expected) throw new Error("No current opening")
    const value = statusSchema.parse(await props.runtime.query(["safe", "password", "status", "--json"]))
    if (expected !== generation() || value.host_opening !== props.opening) throw new Error("Opening changed")
    const next = includePlan && props.safe?.persistent && props.safe.closed && props.writable && !value.transactions.some((entry) => entry.outcome === "pending" && entry.members.some((member) => member.safe_id === props.safe?.id))
      ? planSchema.parse(await props.runtime.query(["safe", "password", "preview", props.safe.id, "--json"])) : undefined
    if (expected !== generation() || next && (next.host_opening !== props.opening || !next.members.some((member) => member.safe_id === props.safe?.id))) throw new Error("Family review changed")
    return { status: value, plan: next }
  }

  async function refresh(includePlan = page() === "family") {
    const expected = generation()
    if (pending || working() || !expected) return undefined
    pending = true
    try {
      const value = await read(includePlan)
      if (stopped || expected !== generation()) return undefined
      setStatus(value.status)
      if (includePlan) setPlan(value.plan)
      setReceived(performance.now())
      setError("")
      setSelected((before) => Math.min(before, Math.max(0, items().length - 1)))
      return value
    } catch {
      if (!stopped && expected === generation()) {
        setPlan(undefined)
        setStatus(undefined)
        setConfirmation(undefined)
        if (page() === "confirm") setPage("family")
        setError("Password information is unavailable or changed. Close family members and refresh; Recovery can read transaction status separately.")
      }
      return undefined
    } finally { pending = false; if (!stopped) setLoading(false) }
  }

  async function prepare(kind: Confirmation["kind"]) {
    if (working() || loading() || (kind === "change" ? changeBlocked() : recoveryBlocked())) return
    const previous = kind === "change" ? plan()?.sha256 : JSON.stringify(current())
    setLoading(true)
    setNotice("")
    const value = await refresh(kind === "change")
    if (!value || stopped) return
    if (kind === "change") {
      if (changeBlocked() || !value.plan) return
      if (value.plan.sha256 !== previous) {
        setNotice("The family review changed. Review the current members before continuing.")
        return
      }
      setConfirmation({ kind, plan: value.plan })
    } else {
      if (recoveryBlocked() || !current()) return
      if (JSON.stringify(current()) !== previous) {
        setNotice("The recorded transaction changed. Review its current state before continuing.")
        return
      }
      setConfirmation({ kind, entry: current()! })
    }
    setPage("confirm")
  }

  async function execute() {
    const reviewed = confirmation()
    if (!reviewed || working() || loading()) return
    if (reviewed.kind === "change" ? changeBlocked() : recoveryBlocked()) { setNotice("The reviewed operation is no longer available. Refresh before continuing."); return }
    setLoading(true)
    const value = await refresh(reviewed.kind === "change")
    if (!value || stopped) return
    if (reviewed.kind === "change" ? changeBlocked() || value.plan?.sha256 !== reviewed.plan.sha256 : recoveryBlocked() || JSON.stringify(current()) !== JSON.stringify(reviewed.entry)) {
      setConfirmation(undefined)
      setPage(reviewed.kind === "change" ? "family" : "members")
      setNotice("The reviewed operation changed. Review the current members and status before continuing.")
      return
    }
    const expected = generation()
    setWorking(true)
    setConfirmation(undefined)
    setPage("recovery")
    setSelected(0)
    setArea("list")
    try {
      const code = await props.run(reviewed.kind === "change" ? ["safe", "password", props.safe!.id, "--confirmed-plan", reviewed.plan.sha256]
        : ["safe", "password", "recover", reviewed.entry.transaction, reviewed.kind === "complete" ? "--complete" : "--rollback"])
      if (!stopped && expected === generation()) setNotice(code === 0 ? "The command returned. Review the recorded outcome below."
        : "The command was interrupted or not completed. Check its recorded outcome before another attempt.")
    } catch {
      if (!stopped && expected === generation()) setNotice("The command result was lost. Check recorded status; no operation will be retried automatically.")
    } finally {
      if (!stopped) { setWorking(false); await refresh(false) }
    }
  }

  function recovery() {
    setPage("recovery")
    setConfirmation(undefined)
    setSelected(0)
    setArea("list")
    setLoading(true)
    void refresh(false)
  }

  function back() {
    const kind = confirmation()?.kind
    setConfirmation(undefined)
    if (page() === "confirm") { setPage(kind === "change" ? "family" : "members"); return }
    if (page() === "members") { recovery(); return }
    if (page() === "recovery") { setTransaction(undefined); setPage("family"); setSelected(0); setLoading(true); void refresh(true); return }
    props.back()
  }

  const label = (outcome: z.infer<typeof entrySchema>["outcome"]) => outcome === "pending" ? "Pending · recovery required" : outcome === "complete" ? "Complete · read-only" : "Rolled back · read-only"
  const confirmationCount = () => { const value = confirmation(); return value?.kind === "change" ? value.plan.members.length : value?.entry.members.length ?? 0 }
  const shownMembers = () => page() === "members" ? current()?.members ?? [] : plan()?.members ?? []
  const items = () => page() === "recovery" ? (status()?.transactions ?? []).map((entry) => ({
    name: `Password update ${entry.transaction.slice(0, 8)}`, badge: label(entry.outcome), description: `Transaction ${entry.transaction}\n${entry.members.length} affected local Safe(s). ${entry.outcome === "pending" ? "Inspect all members before completing or rolling back." : "This recorded outcome cannot be changed."}`, action: "Review members",
    run: () => { setTransaction(entry.transaction); setPage("members"); setSelected(0); setArea("list") },
  })) : shownMembers().map((member) => ({
    name: member.title, badge: props.openIds.includes(member.safe_id) ? "Open · must close" : "Closed",
    description: `Safe ${member.safe_id}\n${props.openIds.includes(member.safe_id) ? "Close this member before changing or recovering the family's password." : "This local Safe is included in the whole-family password update."}`, run: () => {},
  }))
  const toolbar = () => page() === "members" ? [
    ...(current()?.outcome === "pending" ? [{ title: "Complete", key: "C", disabled: !!recoveryBlocked(), run: () => { void prepare("complete") } }, { title: "Roll back", key: "B", disabled: !!recoveryBlocked(), run: () => { void prepare("rollback") } }] : []),
    { title: "Refresh", key: "R", run: () => { void refresh(false) } }, { title: "Back", key: "Esc", run: back },
  ] : page() === "recovery" ? [{ title: "Refresh", key: "R", run: () => { void refresh(false) } }, { title: "Back", key: "Esc", run: back }] : [
    { title: "Change password", key: "C", disabled: !!changeBlocked(), run: () => { void prepare("change") } }, { title: "Recovery", key: "T", run: recovery },
    { title: "Refresh", key: "R", run: () => { void refresh(true) } }, { title: "Back", key: "Esc", run: back },
  ]

  createEffect(() => {
    const expected = generation()
    setPlan(undefined); setStatus(undefined); setConfirmation(undefined); setTransaction(undefined)
    setPage("family"); setSelected(0); setNotice("")
    if (!expected) { setLoading(false); setError("Unlock Oblivion before reviewing family passwords."); return }
    setError(""); setLoading(true)
    untrack(() => { void refresh(true) })
  })
  onMount(() => {
    const timer = setInterval(() => { void refresh() }, 5000)
    const clock = setInterval(() => setNow(performance.now()), 1000)
    onCleanup(() => { clearInterval(timer); clearInterval(clock) })
  })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || working() || loading() || page() === "confirm") return
    if (key.name === "escape") { key.preventDefault(); back(); return }
    if (key.name === "tab") { key.preventDefault(); setArea((value) => value === "list" ? "actions" : "list"); return }
    if (key.name === "r") { key.preventDefault(); void refresh(); return }
    if (key.name === "t" && page() === "family") { key.preventDefault(); recovery(); return }
    if (key.name === "c" && page() !== "recovery") { key.preventDefault(); void prepare(page() === "members" ? "complete" : "change"); return }
    if (key.name === "b" && page() === "members") { key.preventDefault(); void prepare("rollback") }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={page() === "confirm" && confirmation()} fallback={<Menu title={page() === "recovery" ? "Password recovery" : page() === "members" ? `Password update · ${current() ? label(current()!.outcome) : "Unavailable"}` : "Family password"}
      description={page() === "recovery" ? "Inspect a recorded update. Finished transactions are read-only; pending updates require an explicit decision."
        : page() === "members" ? `Transaction ${transaction()}\n${shownMembers().length} affected local Safe(s). Every listed member must stay closed.`
        : `${props.safe?.name ?? "Choose a persistent Safe"} · ${shownMembers().length} local family member(s)\nChanging this password affects every listed local Safe. External backups retain their previous password.`}
      items={items()} selected={selected()} change={setSelected} focused={area() === "list"} disabled={working() || loading()}
      choose={(index) => items()[index]?.run()} toolbar={toolbar()} actionsFocused={area() === "actions"} focusActions={() => setArea("actions")} focus={() => setArea("list")}
      actions={page() === "recovery"} empty={page() === "recovery" ? "No password change transactions recorded." : "No verified family review is available."} />}>
      <FormView form={{ title: confirmation()?.kind === "change" ? "Change family password?" : confirmation()?.kind === "complete" ? "Complete password update?" : "Roll back password update?",
        description: `${confirmationCount()} reviewed local Safe(s) · all must remain closed.\n${confirmation()?.kind === "change" ? "The private terminal will request CHANGE, the current password and the new password. This rewraps the family password; it does not replace data keys or revoke old headers and backups." : confirmation()?.kind === "complete" ? "Continue the recorded update to its new password wrapper. Confirm COMPLETE privately in the terminal." : "Restore the recorded previous password wrapper for the whole family. Confirm ROLLBACK privately in the terminal."}\nNo password is collected by this screen.`,
        fields: [], submit: "Continue privately", run: async () => {} }} cancel={back} submit={() => { void execute() }} />
    </Show>
    <Show when={error() || notice() || (page() === "family" ? changeBlocked() : page() === "members" ? recoveryBlocked() : barrier())}><text flexShrink={0} fg={error() ? theme.feedback.warning : theme.text.muted}>{error() || notice() || (page() === "family" ? changeBlocked() : page() === "members" ? recoveryBlocked() : barrier())}</text></Show>
    <Show when={loading() || working()}><BusyModal text={working() ? "Updating family password" : "Reading password information"} /></Show>
  </box>
}
