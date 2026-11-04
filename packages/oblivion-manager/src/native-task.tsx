import { ScrollBoxRenderable } from "@opentui/core"
import { useKeyboard } from "@opentui/solid"
import { createEffect, createMemo, createSignal, onCleanup, onMount, Show, untrack } from "solid-js"
import { z } from "zod"
import { ActionBar } from "./action-bar"
import { BusyModal } from "./busy-modal"
import { FormView } from "./form"
import { Menu } from "./menu"
import { PageHeader } from "./page-header"
import { requestedAgentName } from "./safe-inspector"
import { theme } from "./theme"
import type { NativeRuntime, NativeStatus } from "./native-control"

const identity = z.string().regex(/^[a-f0-9]{32}$/)
const agent = z.enum(["codex", "claude", "opencode2"])
const job = z.object({
  job_id: identity, request_id: identity, agent,
  state: z.enum(["queued", "running", "completed", "failed", "cancelled"]),
  native_chat_id: z.string().max(256).nullable(),
  reason: z.enum(["needs-auth", "needs-input", "timeout", "output-limit", "interrupted", "agent-exit", "startup-failed", "cleanup-required"]).nullable(),
}).strict().refine((value) => (value.state === "failed") === (value.reason !== null)
  && (value.native_chat_id === null || (value.agent === "opencode2" ? /^ses_[A-Za-z0-9_-]{1,128}$/.test(value.native_chat_id) : /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value.native_chat_id))), "Invalid managed job outcome")

export const taskStatus = z.object({
  version: z.literal(1), safe_id: identity, agent, request_id: identity,
  attempt_request_id: identity.nullable(), attempts: z.number().int().min(0).max(16), attempt_limit: z.literal(16),
  phase: z.enum(["not-started", "submitted", "unknown"]), job: job.nullable(),
  can_start: z.boolean(), can_retry: z.boolean(), can_cancel: z.boolean(), blocked: z.string().max(256).nullable(),
}).strict().refine((value) => (value.attempts === 0) === (value.attempt_request_id === null)
  && (value.phase !== "not-started" || value.attempts === 0 && value.job === null)
  && (value.phase !== "submitted" || value.attempts > 0 && value.job !== null)
  && (value.phase !== "unknown" || value.attempts > 0 && value.job === null)
  && (!value.job || value.job.request_id === value.attempt_request_id && value.job.agent === value.agent)
  && (!value.can_retry || value.job?.state === "failed" || value.job?.state === "cancelled")
  && (!value.can_cancel || value.job?.state === "queued" || value.job?.state === "running"), "Inconsistent saved task state")

const taskReview = z.object({ status: taskStatus, task: z.string().refine((value) => value.trim().length > 0 && Buffer.byteLength(value) <= 16384 && !value.includes("\0"), "Invalid saved task") }).strict()

export function NativeTask(props: { runtime: NativeRuntime; state: NativeStatus; safe: string; name: string; policy?: NativeStatus["safe_access"]["current"]; blocked?: string; run: (args: string[]) => Promise<number>; back: () => void }) {
  const [status, setStatus] = createSignal<z.infer<typeof taskStatus>>()
  const [task, setTask] = createSignal("")
  const [reviewed, setReviewed] = createSignal<string>()
  const [selected, setSelected] = createSignal(0)
  const [page, setPage] = createSignal<"overview" | "review" | "retry" | "cancel" | "details">("overview")
  const [area, setArea] = createSignal<"text" | "actions">("text")
  const [loading, setLoading] = createSignal(true)
  const [working, setWorking] = createSignal(false)
  const [error, setError] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const record = () => props.state.agent_safes.find((entry) => entry.id === props.safe)
  const opening = () => props.state.idle_lock.safes.find((entry) => entry.opening.safe_id === props.safe)
  const active = () => props.state.open_sessions.find((entry) => entry.id === props.safe)
  const authority = createMemo(() => props.state.app_open && props.state.idle_lock.host && !props.state.recovery_required && !props.blocked && !props.state.idle_lock.host!.closing
    && opening() && !opening()!.closing && active() && !active()!.recovery_required && active()!.slot === opening()!.opening.slot
    && record()?.state === "awaiting-start" ? `${props.state.idle_lock.host!.nonce}/${props.safe}/${opening()!.opening.nonce}` : undefined)
  const allowed = () => !!authority() && !error() && !working() && !loading() && !!status()
  let pending = false
  let stopped = false
  let scroll: ScrollBoxRenderable | undefined

  function clearReview() {
    setTask("")
    setReviewed(undefined)
  }

  function back() {
    clearReview()
    props.back()
  }

  function accept(value: z.infer<typeof taskStatus>) {
    if (value.safe_id !== props.safe || value.agent !== record()?.agent) throw new Error("Saved task identity changed")
    if (status()?.request_id !== value.request_id) clearReview()
    setStatus(value)
    setSelected((before) => Math.min(before, Math.max(0, items().length - 1)))
  }

  async function refresh() {
    const generation = authority()
    if (pending || working() || !generation) return
    pending = true
    try {
      const value = taskStatus.parse(await props.runtime.query(["safe", "task", "status", props.safe, "--json"]))
      if (stopped || generation !== authority()) return
      accept(value)
      setError("")
    } catch {
      if (!stopped && generation === authority()) {
        clearReview()
        setStatus(undefined)
        setPage("overview")
        setError("Saved task status is unavailable. Refresh before taking another action.")
      }
    } finally { pending = false; if (!stopped) setLoading(false) }
  }

  async function review() {
    const generation = authority()
    if (!allowed() || !generation) return
    setWorking(true)
    setTask("")
    try {
      const value = taskReview.parse(await props.runtime.query(["safe", "task", "review", props.safe, "--json"]))
      if (stopped || generation !== authority()) return
      accept(value.status)
      setTask(value.task)
      setReviewed(value.status.request_id)
      setArea("text")
      setPage("review")
    } catch {
      if (!stopped && generation === authority()) {
        clearReview()
        setStatus(undefined)
        setPage("overview")
        setError("The saved task could not be reviewed. Refresh before continuing.")
      }
    } finally { if (!stopped) setWorking(false) }
  }

  async function execute(operation: "start" | "retry" | "cancel" | "login") {
    const current = status()
    if (!allowed() || !current || operation !== "login" && current.blocked) return
    if (operation === "start" && !current.can_start || operation === "retry" && !current.can_retry || operation === "cancel" && !current.can_cancel) return
    if ((operation === "start" || operation === "retry") && reviewed() !== current.request_id) { await review(); return }
    setTask("")
    setPage("overview")
    setWorking(true)
    setNotice("")
    try {
      const code = await props.run(operation === "login" ? ["run", "--safe", props.safe, current.agent]
        : ["safe", "task", operation, props.safe, "--request", current.request_id, "--json"])
      if (!stopped) setNotice(code === 0 ? operation === "login" ? "Client closed. Authentication is checked by the native client when the task runs." : "Command returned. Checking the task's actual state."
        : "Command interrupted or not completed. Checking the actual state before any retry.")
    } catch {
      if (!stopped) setNotice("The command could not be confirmed. Check the actual task state before retrying.")
    } finally {
      if (!stopped) { setWorking(false); await refresh() }
    }
  }

  async function retry() {
    if (!allowed() || !status()?.can_retry) return
    if (reviewed() !== status()?.request_id) { await review(); return }
    setTask("")
    setPage("retry")
  }

  const outcome = () => status()?.job ? `Task · ${status()!.job!.state}${status()!.job!.reason ? ` · ${status()!.job!.reason}` : ""}`
    : status()?.phase === "not-started" ? "Task · not started" : "Task · outcome not yet observed"
  const items = () => [
    { name: "Review saved task", description: "Read the exact saved task after unlocking this Safe. No task is submitted by opening this page.", action: "Review task", disabled: !allowed() ? "A fresh status and an open Safe are required." : undefined, run: () => { void review() } },
    { name: "Open requested agent", description: "Open the Safe's native client or resume picker. Native login controls are available if needed; this action sends no saved task.", action: "Open client", disabled: !allowed() ? "An open Safe and a fresh status are required." : undefined, run: () => { void execute("login") } },
    { name: status()?.phase === "unknown" ? "Start or reconcile saved task" : "Start requested task", description: "Review the task first. Start reuses its current attempt identity; an uncertain response does not allocate another attempt.", action: reviewed() === status()?.request_id ? "Start task" : "Review before starting", disabled: !allowed() || !status()?.can_start ? status()?.blocked ? taskBlock(status()!.blocked!) : "This task cannot start in its current state." : undefined, run: () => { void execute("start") } },
    ...(status()?.can_retry ? [{ name: "Retry failed task", description: "Create a new attempt only after the previous task is confirmed failed or cancelled. Existing file changes remain.", action: "Review retry", run: () => { void retry() } }] : []),
    ...(status()?.can_cancel ? [{ name: "Cancel task", description: "Request cancellation of this managed task and verify its final state. Other interactive clients can remain open.", action: "Review cancellation", run: () => { if (allowed()) { setTask(""); setPage("cancel") } } }] : []),
  ]
  const reviewActions = () => [
    { title: "Back", key: "Esc", run: () => { setTask(""); setPage("overview") } },
    { title: status()?.can_retry ? "Retry task" : "Start task", key: "S", disabled: !allowed() || !(status()?.can_start || status()?.can_retry), run: () => { if (status()?.can_retry) { void retry(); return }; void execute("start") } },
    { title: "Open client", key: "A", disabled: !allowed(), run: () => { void execute("login") } },
  ]

  createEffect(() => {
    const generation = authority()
    clearReview()
    setStatus(undefined)
    setPage("overview")
    setSelected(0)
    if (!generation) {
      setLoading(false)
      setError(props.blocked ?? "This Safe is locked or its opening changed. Reopen it before reviewing the task.")
      return
    }
    setLoading(true)
    setError("")
    untrack(() => { void refresh() })
  })
  onMount(() => {
    const timer = setInterval(() => { void refresh() }, 3000)
    onCleanup(() => clearInterval(timer))
  })
  onCleanup(() => { stopped = true; clearReview() })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (key.name === "escape") {
      key.preventDefault()
      if (page() !== "overview") { setTask(""); setPage("overview"); return }
      back(); return
    }
    if (key.name === "r") { key.preventDefault(); void refresh(); return }
    if (key.name === "j" && page() === "overview" && status()?.job) { key.preventDefault(); setPage("details"); return }
    if (page() !== "review") return
    if (key.name === "tab") { key.preventDefault(); setArea((value) => value === "text" ? "actions" : "text"); return }
    if (key.name === "s") { key.preventDefault(); if (status()?.can_retry) { void retry(); return }; void execute("start"); return }
    if (key.name === "a") { key.preventDefault(); void execute("login"); return }
    if (area() !== "text") return
    if (["up", "down", "pageup", "pagedown", "home", "end"].includes(key.name)) {
      key.preventDefault()
      if (key.name === "home") scroll?.scrollTo(0)
      else if (key.name === "end") scroll?.scrollTo(scroll.scrollHeight)
      else scroll?.scrollBy((key.name === "up" || key.name === "pageup" ? -1 : 1) * (key.name === "pageup" || key.name === "pagedown" ? Math.max(1, (scroll?.viewport.height ?? 2) - 1) : 1))
    }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={page() === "details"}>
      <PageHeader title={`Managed job · ${props.name}`} description="Current controller observation. This view does not open task output or start a network connection." />
      <scrollbox flexGrow={1} minHeight={0}>
        <text fg={theme.text.base}>{[
          `Agent: ${status()?.job?.agent ?? "Unavailable"}`,
          `State: ${status()?.job?.state ?? "Unavailable"}`,
          `Job: ${status()?.job?.job_id ?? "Unavailable"}`,
          `Request: ${status()?.job?.request_id ?? "Unavailable"}`,
          `Native chat: ${status()?.job?.native_chat_id ?? "Not reported"}`,
          `Reason: ${status()?.job?.reason ?? "None"}`,
        ].join("\n")}</text>
      </scrollbox>
      <ActionBar actions={[{ title: "Back", key: "Esc", run: () => setPage("overview") }]} />
    </Show>
    <Show when={page() !== "details"}>
    <Show when={page() === "review"} fallback={<Show when={page() === "retry" || page() === "cancel"} fallback={<Menu title={`Saved task · ${props.name}`} description={[
      record() ? `${requestedAgentName(record()!.agent)} · /vault/workspace` : "Requested client unavailable",
      outcome(),
      ...(status() ? [`Attempt ${status()!.attempts}/${status()!.attempt_limit}${status()!.job?.native_chat_id ? ` · Native chat ${status()!.job!.native_chat_id}` : ""}`] : []),
    ].join("\n")} items={items()} selected={selected()} change={setSelected} focused disabled={working() || loading()} choose={(index) => { const item = items()[index]; if (item && !item.disabled) item.run() }} toolbar={[{ title: "Refresh", key: "R", run: () => { void refresh() } }, ...(status()?.job ? [{ title: "Job details", key: "J", run: () => setPage("details") }] : [])]} back={back} />}>
      <FormView form={{ title: page() === "retry" ? "Retry saved task?" : "Cancel running task?", description: page() === "retry" ? "The previous attempt must be confirmed failed or cancelled. A new attempt may repeat earlier work; existing file changes remain. An unknown outcome must be reconciled first." : "Request cancellation of this managed task. Cancellation is shown only after its actual final state is observed. Existing file changes remain.", fields: [], submit: page() === "retry" ? "Retry task" : "Cancel task", run: async () => {} }} cancel={() => setPage("overview")} submit={() => { void execute(page() === "retry" ? "retry" : "cancel") }} />
    </Show>}>
      <PageHeader title={`Review saved task · ${props.name}`} description={`${status() ? requestedAgentName(status()!.agent) : "Requested client"} · /vault/workspace · Policy ${props.policy === "open" ? "Open Internet" : props.policy === "offline" ? "Offline" : props.policy === "strict" ? "Strict" : "unknown"}\nText is shown literally; control and direction characters are escaped.`} />
      <scrollbox ref={(value) => { scroll = value }} flexGrow={1} minHeight={0} border borderColor={area() === "text" ? theme.border.focused : theme.border.base} padding={1} contentOptions={{ minHeight: 0 }}>
        <text fg={theme.text.base} wrapMode="word">{literalTask(task())}</text>
      </scrollbox>
      <text flexShrink={0} fg={theme.text.muted}>{area() === "text" ? "↑ ↓ / PgUp PgDn scroll · Tab actions" : "Tab task text · ← → select action"}</text>
      <ActionBar actions={reviewActions()} focused={area() === "actions"} />
    </Show>
    </Show>
    <Show when={status()?.blocked || error() || notice()}><text flexShrink={0} fg={error() || status()?.blocked ? theme.feedback.warning : theme.feedback.info}>{error() || (status()?.blocked ? taskBlock(status()!.blocked!) : notice())}</text></Show>
    <Show when={loading() || working()}><BusyModal text={working() ? "Checking saved task" : "Reading saved task status"} /></Show>
  </box>
}

function literalTask(value: string) {
  return value.replace(/[\x00-\x09\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`)
}

function taskBlock(value: string) {
  if (value === "task_status_unavailable") return "The current task outcome is unavailable. Refresh before retrying."
  if (value === "recovery_required") return "Task cleanup requires recovery before more work can start."
  if (value === "task_attempt_limit") return "The saved task has reached its attempt limit. Review the earlier result in the native client."
  return "The controller has blocked this task. Refresh its state before continuing."
}
