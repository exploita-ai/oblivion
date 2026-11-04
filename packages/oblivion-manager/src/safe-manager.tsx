import { createMemo, createSignal, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard, useTerminalDimensions } from "@opentui/solid"
import { ActionBar } from "./action-bar"
import { BusyModal } from "./busy-modal"
import { Menu, type MenuItem } from "./menu"
import { FormView } from "./form"
import { theme } from "./theme"
import { capacity } from "./state"
import type { NativeRuntime, NativeStatus } from "./native-control"

const agents = [
  { id: "codex", name: "Codex", description: "Open the official Codex CLI. Its login, tools and conversation history stay inside this Safe." },
  { id: "claude", name: "Claude Code", description: "Open the official Claude Code CLI with this Safe's files and native conversation history." },
  { id: "opencode2", name: "OpenCode 2", description: "Open the official OpenCode 2 TUI and choose your provider inside this Safe." },
] as const

export function SafeManager(props: { runtime: NativeRuntime; initial?: NativeStatus; preview?: boolean }) {
  const size = useTerminalDimensions()
  const [state, setState] = createSignal(props.initial)
  const [error, setError] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [busy, setBusy] = createSignal(!props.initial)
  const [attached, setAttached] = createSignal(false)
  const [selected, setSelected] = createSignal(0)
  const [area, setArea] = createSignal<"list" | "actions">("list")
  const [page, setPage] = createSignal<"safes" | "name" | "agents" | "lock">("safes")
  const [target, setTarget] = createSignal<string>()
  const [safeName, setSafeName] = createSignal<string>()
  const [ephemeral, setEphemeral] = createSignal(false)
  const [quitAfterLock, setQuitAfterLock] = createSignal(false)
  const active = () => state()?.open_sessions.filter((safe) => safe.id) ?? []
  const safeIds = createMemo(() => Array.from(new Set([...(state()?.general_readonly ? [] : state()?.sessions ?? []), ...active().flatMap((safe) => safe.id ? [safe.id] : [])])))
  const selectedId = () => page() === "safes" ? safeIds()[selected()] : undefined
  const selectedOpen = () => active().find((safe) => safe.id === selectedId())
  const spacious = () => size().width >= 110 && size().height >= 32
  let refreshInFlight = false
  let stopped = false

  async function refresh() {
    if (refreshInFlight || attached()) return
    refreshInFlight = true
    try {
      const next = await props.runtime.status()
      if (stopped) return
      setState(next)
      setError("")
      setSelected((before) => Math.min(before, Math.max(0, items().length - 1)))
    } catch {
      if (!stopped) setError("The Oblivion runtime is unavailable. Press R to retry.")
    } finally {
      refreshInFlight = false
      if (!stopped) setBusy(false)
    }
  }

  async function execute(args: string[], message?: string) {
    if (attached() || busy()) return
    setAttached(true)
    setError("")
    setNotice("")
    try {
      const code = await props.runtime.run(args)
      if (code !== 0) setNotice(`The command ended with status ${code}.`)
      else if (message) setNotice(message)
    } catch {
      setNotice("The command could not be started. Check the Oblivion runtime.")
    } finally {
      setAttached(false)
      setPage("safes")
      setSelected(0)
      await refresh()
    }
  }

  function chooseAgent(id?: string, temporary = false, name?: string) {
    if (state()?.recovery_required) return
    setTarget(id)
    setSafeName(name)
    setEphemeral(temporary)
    setSelected(0)
    setArea("list")
    setPage("agents")
  }

  function newSafe(temporary = false) {
    if (state()?.recovery_required) return
    if (temporary || state()?.general_readonly) { chooseAgent(undefined, true); return }
    setPage("name")
    setArea("list")
  }

  async function leave() {
    try { await props.runtime.exit() }
    catch { setNotice("Oblivion could not lock cleanly. Check the runtime before exiting.") }
  }

  function lock(quit = false) {
    if (!state()?.general_open) { if (quit) void leave(); return }
    setQuitAfterLock(quit)
    setPage("lock")
    setSelected(0)
    setArea("list")
  }

  const items = createMemo<MenuItem[]>(() => {
    if (page() === "lock") return [
      { name: "Keep working", description: "Return to your Safes.", run: () => { setPage("safes"); setSelected(0) } },
      { name: quitAfterLock() ? "Lock and exit" : "Lock Oblivion", description: `Close ${active().length} active Safe(s), stop their agents and lock encrypted storage.`, run: () => {
        void execute(["lock"]).then(() => { if (quitAfterLock() && !state()?.general_open) void leave() })
      } },
    ]
    if (page() === "agents") return agents.map((agent) => ({
      name: agent.name,
      description: agent.description,
      action: "Open agent",
      run: () => { void execute(["run", ...(target() ? ["--safe", target()!] : safeName() ? ["--name", safeName()!] : []), ...(ephemeral() ? ["--ephemeral"] : []), agent.id]) },
    }))
    if (!state()?.general_open) return [
      {
        name: state()?.general_present ? "Unlock Oblivion" : "Create encrypted storage",
        badge: "Saved encrypted",
        description: "Keep Safes, files and agent logins in encrypted storage. Each Safe has its own password and isolated virtual machine.",
        action: state()?.general_present ? "Unlock" : "Set up",
        run: () => { void execute([state()?.general_present ? "unlock" : "init"], state()?.general_present ? undefined : "Storage created. Unlock Oblivion to begin.") },
      },
      { name: "Ephemeral mode", badge: "RAM only", description: "Work in RAM for this run. New Safes and files are discarded when they close or the computer restarts.", action: "Enter ephemeral mode", run: () => { void execute(["ephemeral"]) } },
    ]
    return safeIds().map((id) => {
      const opened = active().find((safe) => safe.id === id)
      return {
        name: state()?.session_titles[id] ?? `Safe ${id.slice(0, 8)}`,
        badge: opened ? opened.recovery_required ? "Recovery required" : "Open" : "Locked",
        description: `${id.slice(0, 8)} · ${state()?.session_sizes?.[id] ? capacity(state()!.session_sizes![id]) + " · " : ""}${opened ? "Open another agent in this Safe's VM. All agents in this Safe share its files." : "Unlock this Safe and open an agent in its isolated VM."}`,
        action: "Choose agent",
        disabled: state()?.recovery_required || opened?.recovery_required ? "Recovery is required before this Safe can open." : undefined,
        run: () => chooseAgent(id),
      }
    })
  })

  const toolbar = () => state()?.general_open && page() === "safes" ? [
    { title: "New Safe", key: "N", disabled: state()?.recovery_required, run: () => newSafe() },
    { title: "Ephemeral Safe", key: "E", disabled: state()?.recovery_required, run: () => newSafe(true) },
    { title: "Refresh", key: "R", run: () => { void refresh() } },
  ] : []

  onMount(() => {
    if (!props.initial) void refresh()
    const timer = setInterval(() => { void refresh() }, 5000)
    onCleanup(() => clearInterval(timer))
  })
  onCleanup(() => { stopped = true })

  useKeyboard((key) => {
    if (key.defaultPrevented || attached() || busy()) return
    if (key.ctrl && key.name === "q") { key.preventDefault(); lock(); return }
    if (key.name === "escape") {
      key.preventDefault()
      if (page() !== "safes") { setPage("safes"); setSelected(0); return }
      lock(true)
      return
    }
    if (page() === "name") return
    if (key.name === "r" && page() === "safes") { key.preventDefault(); void refresh(); return }
    if (key.name === "tab" && toolbar().length) { key.preventDefault(); setArea((value) => value === "list" ? "actions" : "list"); return }
    if (page() === "safes" && state()?.general_open) {
      if (key.name === "n") { key.preventDefault(); newSafe(); return }
      if (key.name === "e") { key.preventDefault(); newSafe(true); return }
      if (key.name === "l") {
        key.preventDefault()
        const id = selectedId()
        if (id && active().some((safe) => safe.id === id)) void execute(["close", id], "Safe closed and locked.")
      }
    }
  })

  return <box width="100%" height="100%" flexDirection="column" backgroundColor={theme.background.base}>
    <box flexShrink={0} flexDirection="row" justifyContent="space-between" paddingLeft={2} paddingRight={2} paddingTop={spacious() ? 1 : 0} paddingBottom={1} border={["bottom"]} borderColor={theme.border.base}>
      <text fg={theme.text.brand}><b>OBLIVION</b></text>
      <text fg={theme.text.muted}>{props.preview ? "Preview" : state()?.general_open ? state()?.general_readonly ? "Ephemeral mode" : `${active().length} active Safe(s)` : "Privacy layer"}</text>
    </box>
    <box flexGrow={1} minHeight={0} flexDirection="column" paddingLeft={spacious() ? 5 : 2} paddingRight={spacious() ? 5 : 2} paddingTop={spacious() ? 2 : 1} paddingBottom={1}>
      <Show when={page() === "name"} fallback={<Menu title={page() === "lock" ? "Close and lock" : page() === "agents" ? "Choose an agent" : state()?.general_open ? "Your Safes" : "Welcome to Oblivion"}
        description={page() === "agents" ? target() ? `${state()?.session_titles[target()!] ?? target()!.slice(0, 8)} · Shared files, independent agent conversations` : ephemeral() ? "Create an isolated Safe in RAM. Its contents are discarded when closed." : `${safeName() ?? "New Safe"} · Separate password, encrypted files and virtual machine.` : page() === "lock" ? "Active work stops when its Safe is locked." : state()?.general_open ? "Choose a Safe to continue, or create a separate environment." : "Run your coding agent in an isolated VM. Choose how to keep your work."}
        items={items()} selected={selected()} change={setSelected} focused={area() === "list"} disabled={attached() || busy() || !!error()}
        choose={(index) => { const item = items()[index]; if (item && !item.disabled) item.run() }}
        toolbar={toolbar()} actionsFocused={area() === "actions"} focusActions={() => setArea("actions")} focus={() => setArea("list")}
        empty="No Safes yet. Press N to create your first Safe." back={page() !== "safes" ? () => { setPage("safes"); setSelected(0) } : undefined} />}>
        <FormView form={{ title: "New Safe", description: "Give this isolated environment a name. Its password is requested securely in the terminal.", submit: "Choose agent", fields: [{ id: "name", label: "Safe name", validate: (value) => value.trim() !== value || !value || Array.from(value).length > 80 || Buffer.byteLength(value) > 256 || /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value) ? "Use 1–80 characters without leading or trailing spaces." : undefined }], run: async () => {} }}
          cancel={() => { setPage("safes"); setSelected(0) }} submit={(values) => chooseAgent(undefined, false, values.name)} />
      </Show>
      <Show when={state()?.recovery_required}><text fg={theme.feedback.warning}>Recovery is required. Close and lock Oblivion before opening more Safes.</text></Show>
      <Show when={error() || notice()}><text flexShrink={0} fg={error() ? theme.feedback.error : theme.feedback.info}>{error() || notice()}</text></Show>
    </box>
    <box flexShrink={0} flexDirection="row" justifyContent="space-between" paddingLeft={2} paddingRight={2} paddingTop={spacious() ? 1 : 0} paddingBottom={spacious() ? 1 : 0} border={["top"]} borderColor={theme.border.base}>
      <text fg={theme.text.muted}>{page() === "safes" ? "↑↓ Select · Enter Open" : "↑↓ Select · Enter Confirm · Esc Back"}</text>
      <ActionBar actions={state()?.general_open ? [
        { title: "Lock Safe", key: "L", disabled: !selectedOpen(), run: () => {
          const id = selectedOpen()?.id
          if (id) void execute(["close", id], "Safe closed and locked.")
        } },
        { title: "Lock Oblivion", key: "Ctrl+Q", run: () => lock() },
      ] : [{ title: "Exit", key: "Esc", run: () => { void leave() } }]} disabled={attached() || busy()} />
    </box>
    <Show when={busy()}><BusyModal text="Opening Oblivion" /></Show>
  </box>
}
