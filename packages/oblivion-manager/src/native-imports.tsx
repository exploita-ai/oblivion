import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard } from "@opentui/solid"
import { z } from "zod"
import { Menu } from "./menu"
import { FormView } from "./form"
import { BusyModal } from "./busy-modal"
import { theme } from "./theme"
import type { NativeRuntime } from "./native-control"

const imports = z.array(z.object({
  transaction: z.string().regex(/^[a-f0-9]{32}$/),
  package_id: z.string().regex(/^[a-f0-9]{32}$/).nullable(),
  outcome: z.enum(["pending", "committed", "recovery-required"]),
  safes: z.number().int().nonnegative(),
  ready: z.number().int().nonnegative(),
  openings: z.array(z.object({ slot: z.number().int().nonnegative() })),
})).max(1024)

export function NativeImports(props: { runtime: NativeRuntime; writable: boolean; run: (args: string[]) => Promise<number>; back: () => void }) {
  const [records, setRecords] = createSignal<z.infer<typeof imports>>([])
  const [selected, setSelected] = createSignal(0)
  const [review, setReview] = createSignal<string>()
  const [loading, setLoading] = createSignal(true)
  const [working, setWorking] = createSignal(false)
  const [error, setError] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const current = () => records().find((record) => record.transaction === review())
  const canDiscard = () => props.writable && !error() && !!current() && current()!.outcome !== "committed"
  let pending = false
  let stopped = false

  async function refresh() {
    if (pending || working()) return
    pending = true
    const selectedId = records()[selected()]?.transaction
    try {
      const next = imports.parse(await props.runtime.query(["share", "imports", "--json"]))
      if (stopped) return
      setRecords(next)
      setSelected(Math.max(0, next.findIndex((record) => record.transaction === selectedId)))
      setError("")
    } catch {
      if (!stopped) setError("Import status is unavailable. Refresh before discarding anything.")
    } finally {
      pending = false
      if (!stopped) setLoading(false)
    }
  }

  async function discard() {
    const transaction = current()?.transaction
    if (working() || !canDiscard() || !transaction) return
    setWorking(true)
    setNotice("")
    try {
      const code = await props.run(["share", "discard", transaction])
      if (stopped) return
      setNotice(code === 0 ? "Incomplete import discarded. Existing Safes were preserved."
        : code === 130 ? "Discard interrupted or cancelled. Refresh the import list to check its current state."
        : "Discard did not complete. Review the terminal output. Close or lock any still-active import before retrying cleanup.")
      setReview(undefined)
    } finally {
      setWorking(false)
      if (!stopped) await refresh()
    }
  }

  const label = (outcome: z.infer<typeof imports>[number]["outcome"]) => outcome === "committed" ? "Imported" : outcome === "recovery-required" ? "Recovery required" : "Pending · not published"
  const items = () => records().map((record) => ({
    name: `Import ${record.transaction.slice(0, 8)}`,
    badge: label(record.outcome),
    description: `${record.ready}/${record.safes} Safes ready${record.openings.length ? ` · ${record.openings.length} recorded transfer environment(s)` : ""}. ${record.outcome === "committed" ? "Published Safes are available in Safes. This record is read-only and cannot be discarded."
      : record.outcome === "recovery-required" ? "The interrupted import requires explicit cleanup. It cannot resume or publish from this screen."
      : "This import has not been published. If it is still active elsewhere, close or lock that work before cleanup."}`,
    action: "Inspect import",
    run: () => { setReview(record.transaction); setNotice("") },
  }))

  onMount(() => {
    void refresh()
    const timer = setInterval(() => { void refresh() }, 5000)
    onCleanup(() => clearInterval(timer))
  })
  onCleanup(() => { stopped = true })
  useKeyboard((key) => {
    if (key.defaultPrevented || working()) return
    if (key.name === "r") { key.preventDefault(); void refresh(); return }
    if (key.name === "escape" && !review()) { key.preventDefault(); props.back() }
  })

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={review()} fallback={<Menu title="Share imports" description={`${records().length} import record(s) · Completed imports are read-only.`}
      items={items()} selected={selected()} change={setSelected} focused disabled={working() || loading()} choose={(index) => items()[index]?.run()}
      toolbar={[{ title: "Refresh", key: "R", run: () => { void refresh() } }]} empty={error() || "No Share import records."} back={props.back} />}>
      <Show when={canDiscard()} fallback={<FormView form={{ title: current()?.outcome === "committed" ? "Imported · read-only" : "Import cannot be discarded", description: current()?.outcome === "committed"
        ? `Transaction · ${review()}\n${current()!.safes} Safes were published. Committed imports cannot be removed here. Open Safes to work with them.`
        : !props.writable ? "Unlock writable encrypted storage to discard an incomplete import. No cleanup was started."
        : error() || "This import record is no longer available. Refresh the list before taking another action.", fields: [], submit: "Back to imports", run: async () => {} }} cancel={() => setReview(undefined)} submit={() => setReview(undefined)} />}>
        <FormView form={{ title: "Discard incomplete import?", description: `Transaction · ${review()}\n${current()?.ready}/${current()?.safes} staged Safes ready · ${current() ? label(current()!.outcome) : ""}\nRemove this unpublished import's staged data. This cannot be undone.\nExisting Safes and committed imports cannot be removed by this action.\nIf the import is still active, close or lock that work first. This screen does not close Safes automatically.\nNext: confirm DISCARD privately in the terminal.`, fields: [], submit: "Continue to discard", run: async () => {} }}
          cancel={() => setReview(undefined)} submit={() => { void discard() }} />
      </Show>
    </Show>
    <Show when={error() || notice()}><text flexShrink={0} fg={error() ? theme.feedback.warning : theme.feedback.info}>{error() || notice()}</text></Show>
    <Show when={loading() || working()}><BusyModal text={working() ? "Discarding incomplete import" : "Reading Share imports"} /></Show>
  </box>
}
