import path from "node:path"
import { createSignal, Show } from "solid-js"
import { useTerminalDimensions } from "@opentui/solid"
import { FormView } from "./form"
import { LocalChooser } from "./native-files"
import { PageHeader } from "./page-header"
import { Menu } from "./menu"
import { BusyModal } from "./busy-modal"
import { theme } from "./theme"

export type ShareSelection = { operation: "import" }
  | { operation: "export"; scope: "safe"; safe: string; name: string; closed: boolean; branch?: { count: number; closed: boolean } }
  | { operation: "export"; scope: "all"; count: number; closed: boolean }

export function NativeShare(props: { selection: ShareSelection; run: (args: string[]) => Promise<number>; back: () => void; initialDirectory?: string }) {
  const dimensions = useTerminalDimensions()
  const [page, setPage] = createSignal<"scope" | "choose" | "name" | "review" | "result">(props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch ? "scope" : "choose")
  const [scope, setScope] = createSignal<"safe" | "branch">("safe")
  const [selectedScope, setSelectedScope] = createSignal(0)
  const [directory, setDirectory] = createSignal(props.initialDirectory ?? process.cwd())
  const [source, setSource] = createSignal("")
  const [filename, setFilename] = createSignal(props.selection.operation === "export" ? props.selection.scope === "all" ? "oblivion-all.oblivion-share" : `oblivion-${props.selection.safe.slice(0, 8)}.oblivion-share` : "")
  const [working, setWorking] = createSignal(false)
  const [exitCode, setExitCode] = createSignal<number>()
  const [applySettings, setApplySettings] = createSignal(false)
  const available = () => props.selection.operation === "import" || props.selection.closed && (props.selection.scope === "all" || scope() !== "branch" || !!props.selection.branch?.closed)
  const sourceLabel = () => props.selection.operation === "import" ? ""
    : props.selection.scope === "all" ? `All ${props.selection.count} persistent Safes`
    : scope() === "branch" ? `Branch ${props.selection.name} · ${props.selection.branch?.count} Safes`
    : `Safe ${props.selection.name} (${props.selection.safe.slice(0, 8)})`
  const scopes = () => props.selection.operation === "export" && props.selection.scope === "safe" ? [
    { name: "This Safe only", description: `Export ${props.selection.name} without its descendants.`, action: "Choose destination", run: () => { setScope("safe"); setPage("choose") } },
    { name: "Safe and descendants", description: `Export this branch of ${props.selection.branch?.count} persistent Safes. Every included Safe must be closed.`, disabled: !props.selection.branch?.closed ? "Close the included descendant Safes first." : undefined, action: "Choose destination", run: () => { if (props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch?.closed) { setScope("branch"); setPage("choose") } } },
  ] : []
  const output = () => path.join(directory(), filename())

  async function confirm() {
    if (working() || !available()) return
    setWorking(true)
    try {
      const code = await props.run(props.selection.operation === "export"
        ? ["share", "export", ...(props.selection.scope === "all" ? ["--all"] : [scope() === "branch" ? "--branch" : "--safe", props.selection.safe]), output()]
        : ["share", "import", source(), ...(applySettings() ? ["--apply-settings"] : [])])
      setExitCode(code)
      setPage("result")
    } finally { setWorking(false) }
  }

  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <Show when={available()} fallback={<FormView form={{ title: "Close this Safe before Share", description: "An included Safe is open in another terminal. Close and lock the selected Safe or branch before exporting. Other Safes can keep working.", fields: [], submit: "Back to Safes", run: async () => {} }} cancel={props.back} submit={props.back} />}>
      <Show when={page() === "scope"}><Menu title="Choose Share scope" description="Export this Safe alone or include its persistent descendants. Provider login stores are excluded."
        items={scopes()} selected={selectedScope()} change={setSelectedScope} focused choose={(index) => { const item = scopes()[index]; if (item && !item.disabled) item.run() }} back={props.back} /></Show>
      <Show when={page() === "choose"}><LocalChooser
        title={props.selection.operation === "export" ? "Choose Share destination" : "Choose an encrypted Share file"}
        directoryOnly={props.selection.operation === "export"} filesOnly={props.selection.operation === "import"}
        initialDirectory={directory()} back={() => { if (props.selection.operation === "export" && props.selection.scope === "safe" && props.selection.branch) { setPage("scope"); return }; props.back() }} choose={(value) => {
          if (props.selection.operation === "import") { setSource(value); setDirectory(path.dirname(value)); setPage("review"); return }
          setDirectory(value); setPage("name")
        }} /></Show>
      <Show when={page() === "name"}><FormView form={{
        title: "Name the encrypted Share", description: `Destination on this computer · ${directory()}`,
        fields: [{ id: "filename", label: "Share filename", value: filename(), validate: (value) => !value || value === "." || value === ".." || /[/\\\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value) || Buffer.byteLength(value) > 255 ? "Choose a single filename of at most 255 UTF-8 bytes." : undefined }],
        submit: "Review Share", run: async () => {},
      }} cancel={() => setPage("choose")} submit={(values) => { setFilename(values.filename); setPage("review") }} /></Show>
      <Show when={page() === "review"}><box flexGrow={1} minHeight={0} alignItems="center" justifyContent="center"><box width="100%" maxWidth={104} height={Math.min(22, dimensions().height - 7)} maxHeight="100%" minHeight={0} padding={1} border borderColor={theme.border.base} backgroundColor={theme.background.panel}><FormView form={{
        title: props.selection.operation === "export" ? "Review Share export" : "Review Share import",
        description: props.selection.operation === "export"
          ? `Source · ${sourceLabel()}\nPer Safe: workspace, imports and portable chat history.\nDestination · ${output()}\nProvider login stores are excluded. Content scan is best effort; it does not guarantee removal of secrets.\nNext: inspect the detailed CLI review and choose a separate Share password.`
          : `Source · ${source()}\nNew encrypted Safes; existing Safes are not replaced. Safes import offline.\nProvider login stores are excluded. Authenticate agents separately.\nContent scan is best effort; it does not guarantee removal of secrets.\nPasswords and shared timer values are reviewed privately in the terminal.`,
        fields: props.selection.operation === "export" ? [] : [{ id: "settings", label: "Apply shared automatic-lock settings (if included)", checkbox: true, value: String(applySettings()) }], submit: props.selection.operation === "export" ? "Continue to export" : "Continue to import", run: async () => {},
      }} cancel={() => setPage(props.selection.operation === "export" ? "name" : "choose")} submit={(values) => { if (props.selection.operation === "import") setApplySettings(values.settings === "true"); void confirm() }} /></box></box></Show>
      <Show when={page() === "result"}><PageHeader title={exitCode() === 0 ? props.selection.operation === "export" ? "Share exported" : "Share imported" : exitCode() === 130 ? "Share cancelled" : props.selection.operation === "import" && exitCode() === 2 ? "Safes imported · settings not applied" : "Share did not complete"}
        description={exitCode() === 0 ? props.selection.operation === "export" ? "The encrypted Share was verified and saved. Send its password through a separate channel." : "New encrypted Safes were published offline. Open them to review their contents and authenticate agents separately." : exitCode() === 130 ? props.selection.operation === "import" ? "Operation cancelled. Check Share imports and your Safes before retrying an import." : "Operation cancelled. Check the destination before retrying an export." : props.selection.operation === "import" && exitCode() === 2 ? "The Safes were already imported. Do not import the Share again. Review your Safes and configure Automatic lock in Settings." : "Review the terminal output and check your Safes before retrying an import."} />
        <FormView form={{ title: props.selection.operation === "export" ? "Share export" : "Share import", description: props.selection.operation === "export" ? `Destination · ${output()}` : `Source · ${source()}`, fields: [], submit: "Back to Safes", run: async () => {} }} cancel={props.back} submit={props.back} />
      </Show>
    </Show>
    <Show when={working()}><BusyModal text="Preparing Share" /></Show>
  </box>
}
