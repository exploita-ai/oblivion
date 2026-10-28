import { createSignal, onMount, Show } from "solid-js"
import { z } from "zod"
import { BusyModal } from "./busy-modal"
import { ControlError, type Request } from "./control"
import { FormView } from "./form"
import { Picker } from "./picker"
import { theme } from "./theme"

const chats = z.object({
  result: z.literal("chats"),
  entries: z.array(z.object({ id: z.string().regex(/^ses_[A-Za-z0-9_-]{1,128}$/), title: z.string().max(400).refine((value) => [...value].length <= 200) })).max(50),
  next: z.string().max(1024).nullable(),
})
const exported = z.object({
  result: z.literal("exported"),
  path: z.string().regex(/^workspace\/chat-exports\/[a-f0-9]{32}\.(md|json)$/),
  bytes: z.number().int().positive().max(64 * 1024 * 1024),
})

export function ChatExport(props: {
  request: (request: Request) => Promise<string>
  back: () => void
  saved: (path: string) => Promise<void>
}) {
  const [page, setPage] = createSignal<z.infer<typeof chats>>({ result: "chats", entries: [], next: null })
  const [cursors, setCursors] = createSignal<(string | null)[]>([null])
  const [selected, setSelected] = createSignal<{ id: string; title: string }>()
  const [format, setFormat] = createSignal<"markdown" | "json">()
  const [busy, setBusy] = createSignal("")
  const [error, setError] = createSignal("")

  function command(payload: object) {
    return props.request({ operation: "chat-export", payload: new TextEncoder().encode(JSON.stringify(payload)) })
  }
  async function run(label: string, action: () => Promise<void>) {
    if (busy()) return
    setBusy(label); setError("")
    try { await action() }
    catch (error) { setError(error instanceof ControlError ? `Export stopped (${error.code}). Your chat is preserved.` : "Could not export this chat. Your chat is preserved.") }
    finally { setBusy("") }
  }
  async function list(cursor: string | null = null, direction: "first" | "next" | "previous" = "first") {
    setPage(chats.parse(JSON.parse(await command({ action: "list", cursor }))))
    setCursors((values) => direction === "next" ? [...values, cursor] : direction === "previous" ? values.slice(0, -1) : [null])
  }
  async function save() {
    const result = exported.parse(JSON.parse(await command({ action: "export", id: selected()!.id, format: format()! })))
    await props.saved(result.path)
  }
  onMount(() => { void run("Reading chat list", () => list()) })

  return <box flexGrow={1} minHeight={0} flexDirection="column">
    <Show when={!busy()}><Show when={!format()} fallback={<FormView form={{
      title: "Export chat", description: `${selected()?.title} · ${format() === "markdown" ? "Markdown" : "OpenCode JSON"}\nCreates a readable transcript in this session's encrypted workspace. Use Documents / Export selected to send it to external media. It may include prompts, tool output and attached file data. In-progress responses are omitted; this is not a session backup.`,
      fields: [], submit: "Create transcript", run: save,
    }} cancel={() => setFormat(undefined)} submit={() => { void run("Exporting settled chat messages", save) }} />}>
      <Show when={!selected()} fallback={<Picker title="Export chat / Format" description={selected()?.title ?? ""} choices={[
        { value: "markdown", label: "Markdown", description: "Readable conversation, reasoning and tool output." },
        { value: "json", label: "OpenCode JSON", description: "Structured transcript with original chat and message IDs." },
      ]} back={() => setSelected(undefined)} choose={(value) => setFormat(value as "markdown" | "json")} />}>
        <Picker title="Export chat / Choose a chat" description={page().entries.length ? "Only chats in the current protected session are listed." : "No chats yet. Start a chat, then return here to export it."} choices={[
          ...page().entries.map((entry) => ({ value: entry.id, label: entry.title || "Untitled chat", description: entry.id })),
          ...(cursors().length > 1 ? [{ value: "previous", label: "Previous page" }] : []),
          ...(page().next ? [{ value: "next", label: "Next page" }] : []),
        ]} back={props.back} choose={(id) => {
          if (id === "next") { void run("Reading next chats", () => list(page().next, "next")); return }
          if (id === "previous") { void run("Reading previous chats", () => list(cursors().at(-2) ?? null, "previous")); return }
          setSelected(page().entries.find((entry) => entry.id === id))
        }} />
      </Show>
    </Show></Show>
    <Show when={error()}><text fg={theme.feedback.error}>{error()}</text></Show>
    <Show when={busy()}><BusyModal text={busy()} /></Show>
  </box>
}
