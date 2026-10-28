import { useKeyboard } from "@opentui/solid"
import { SelectList } from "@opencode/tui-kit"
import { createSignal, For, onMount, Show } from "solid-js"
import { z } from "zod"
import { BusyModal } from "./busy-modal"
import { ControlError, type Request } from "./control"
import { PageHeader } from "./page-header"
import { palette, theme } from "./theme"

const report = z.object({
  version: z.literal(1), controller_version: z.string().regex(/^\d{1,5}\.\d{1,5}\.\d{1,5}$/),
  architecture: z.enum(["aarch64", "x86_64", "unknown"]), cpu_cores: z.number().int().min(1).max(4096),
  memory_mib: z.number().int().nonnegative().max(1024 ** 3), ephemeral: z.boolean(), general_open: z.boolean(),
  session: z.enum(["locked", "documents", "chat", "starting", "recovery"]),
  transport: z.enum(["not_started", "connecting", "tor", "socks5", "offline", "unknown"]),
  direct_access_blocked: z.boolean(), observation_age_ms: z.number().int().nonnegative(),
  tor_bootstrap: z.number().int().min(0).max(100).nullable(), laboratory: z.boolean(),
}).strict()
const exported = z.object({
  result: z.literal("exported"), path: z.string().regex(/^workspace\/diagnostics\/[a-f0-9]{32}\.json$/),
  bytes: z.number().int().positive().max(4096),
})

export function Diagnostics(props: {
  request: (request: Request) => Promise<string>
  back: () => void
  saved: (path: string) => Promise<void>
}) {
  const [preview, setPreview] = createSignal<z.infer<typeof report>>()
  const [focus, setFocus] = createSignal<"report" | "actions">("actions")
  const [busy, setBusy] = createSignal("")
  const [error, setError] = createSignal("")
  function command(action: "preview" | "export") {
    return props.request({ operation: "diagnostics", payload: new TextEncoder().encode(JSON.stringify({ action })) })
  }
  async function run(label: string, task: () => Promise<void>) {
    if (busy()) return
    setBusy(label); setError("")
    try { await task() }
    catch (error) { setError(error instanceof ControlError ? `Diagnostics stopped (${error.code}).` : "Diagnostics could not be created.") }
    finally { setBusy("") }
  }
  onMount(() => { void run("Reading diagnostic status", async () => { setPreview(report.parse(JSON.parse(await command("preview")))) }) })
  useKeyboard((key) => {
    if (key.defaultPrevented || busy()) return
    if (key.name === "escape") { key.preventDefault(); props.back() }
    if (key.name === "tab") { key.preventDefault(); setFocus((value) => value === "report" ? "actions" : "report") }
  })
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <PageHeader title="Export diagnostics / Review" description="Only the fields below are included. Live state is refreshed when you create the report." />
    <scrollbox flexGrow={1} minHeight={0} focused={focus() === "report" && !busy()}>
      <For each={Object.entries(preview() ?? {})}>{(entry) => <text fg={theme.text.base}>{entry[0]}: {String(entry[1] ?? "unavailable")}</text>}</For>
    </scrollbox>
    <text fg={theme.text.muted}>No chat text, file names, paths, keys, IP addresses, access URLs or logs.</text>
    <Show when={error()}><text fg={theme.feedback.error}>{error()}</text></Show>
    <SelectList theme={palette} height={2} items={[...(preview() ? [{ title: "Create JSON report in session" }] : []), { title: "Back" }]}
      focused={focus() === "actions" && !busy()} disabled={!!busy()} onFocus={() => setFocus("actions")}
      onSelect={(index) => {
        if (!preview() || index === 1) { props.back(); return }
        void run("Creating diagnostic report", async () => { await props.saved(exported.parse(JSON.parse(await command("export"))).path) })
      }} />
    <Show when={busy()}><BusyModal text={busy()} /></Show>
  </box>
}
