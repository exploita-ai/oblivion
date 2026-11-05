import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js"
import { useKeyboard, usePaste, useRenderer, useTerminalDimensions } from "@opentui/solid"
import { ActionItem } from "@oblivion/tui-kit"
import { ActionBar } from "./action-bar"
import { BusyModal } from "./busy-modal"
import { Menu, type MenuItem } from "./menu"
import { FormView } from "./form"
import { palette, theme } from "./theme"
import { capacity, nativeStatus, type NativeOverlay, type NativeRuntime, type NativeStatus } from "./native-control"
import { NativeNetwork, NativeNetworkIndicator, NativeSystem, scopedNetworkObservation, type NetworkObservation } from "./native-network"
import { NativeFiles } from "./native-files"
import { createFileTransfers } from "./native-file-transfers"
import { NativeIdle } from "./native-idle"
import { NativeStorage, storageUnavailable } from "./native-storage"
import { NativeShare, type ShareSelection } from "./native-share"
import { NativeImports } from "./native-imports"
import { requestedAgentName, SafeInspector } from "./safe-inspector"
import { NativeTask } from "./native-task"
import { NativeBackups } from "./native-backups"
import { NativePassword } from "./native-password"
import { conversationArgs } from "./native-conversation"

const agents = [
  { id: "codex", name: "Codex", description: "Official Codex. First login: choose Sign in with Device Code for ChatGPT, then open its link outside the Safe. Its browser callback stays inside." },
  { id: "claude", name: "Claude Code", description: "Open the official Claude Code CLI with this Safe's files and native conversation history." },
  { id: "opencode2", name: "OpenCode 2", description: "Open the official OpenCode 2 TUI and choose your provider inside this Safe." },
] as const

export function SafeManager(props: { runtime: NativeRuntime; initial?: NativeStatus; initialReceived?: number; initialError?: string; preview?: boolean; overlay?: NativeOverlay; liveStorage?: "persistent" | "ephemeral" }) {
  const size = useTerminalDimensions()
  const clock = useRenderer().clock
  const fileTransfers = createFileTransfers()
  const [state, setState] = createSignal(props.initial)
  const [error, setError] = createSignal(props.initialError ?? "")
  const [notice, setNotice] = createSignal("")
  const [busy, setBusy] = createSignal(!props.initial && !props.initialError)
  const [attached, setAttached] = createSignal(false)
  const [selected, setSelected] = createSignal(0)
  const [area, setArea] = createSignal<"list" | "actions">("list")
  const [page, setPage] = createSignal<"safes" | "name" | "agents" | "lock" | "settings" | "system" | "network" | "files" | "rename" | "grow" | "idle" | "storage" | "share" | "imports" | "backups" | "password" | "inspect" | "task">(props.overlay?.page ?? "safes")
  const [sharing, setSharing] = createSignal<ShareSelection>()
  const [storageReview, setStorageReview] = createSignal<{ bytes: number; reset: boolean }>()
  const [context, setContext] = createSignal<string | undefined>(props.overlay?.safe)
  const [observed, setObserved] = createSignal<NetworkObservation>()
  const [now, setNow] = createSignal(performance.now())
  const [hostReceived, setHostReceived] = createSignal(props.initial ? props.initialReceived ?? performance.now() : 0)
  const [target, setTarget] = createSignal<string>()
  const [safeName, setSafeName] = createSignal<string>()
  const [ephemeral, setEphemeral] = createSignal(false)
  const [quitAfterLock, setQuitAfterLock] = createSignal(false)
  const active = () => state()?.open_sessions.filter((safe) => safe.id) ?? []
  createEffect(() => { if (state()?.app_open === false) fileTransfers.clear() })
  const safeRows = createMemo(() => {
    const ids = Array.from(new Set([...(state()?.app_mode !== "persistent" ? [] : state()?.sessions ?? []),
      ...(state()?.app_open ? state()?.agent_safes.filter((entry) => entry.ephemeral || state()?.app_mode === "persistent").map((entry) => entry.id) ?? [] : []),
      ...active().flatMap((safe) => safe.id ? [safe.id] : [])]))
    const parents = new Map(state()?.safe_parents.map((entry) => [entry.id, entry.parent]))
    state()?.agent_safes.filter((entry) => entry.ephemeral).forEach((entry) => parents.set(entry.id, entry.parent))
    const known = new Set(ids)
    const seen = new Set<string>()
    const children = new Map<string, string[]>()
    ids.forEach((id) => { const parent = parents.get(id); if (parent) children.set(parent, [...children.get(parent) ?? [], id]) })
    const rows: { id: string; depth: number }[] = []
    function visit(id: string, depth: number) {
      if (seen.has(id)) return
      seen.add(id); rows.push({ id, depth })
      children.get(id)?.forEach((child) => visit(child, depth + 1))
    }
    ids.filter((id) => !known.has(parents.get(id) ?? "")).forEach((id) => visit(id, 0))
    ids.forEach((id) => visit(id, 0))
    return rows
  })
  const safeIds = () => safeRows().map((row) => row.id)
  const selectedId = () => page() === "safes" ? safeIds()[selected()] : undefined
  const safe = () => selectedId() ?? context()
  const safeTitle = () => safe() ? state()?.session_titles[safe()!] ?? `Safe ${safe()!.slice(0, 8)}` : "Choose a Safe"
  const selectedOpen = () => active().find((opened) => opened.id === safe())
  const hostClosing = () => state()?.idle_lock.host?.closing ?? false
  const safeClosing = (id: string | undefined) => state()?.idle_lock.safes.some((entry) => entry.opening.safe_id === id && entry.closing) ?? false
  const agentRecord = (id: string | undefined) => state()?.agent_safes.find((entry) => entry.id === id)
  const openingBlocked = (id: string) => !state()?.app_open ? "Unlock Oblivion before opening this Safe."
    : error() ? "Runtime status is unavailable. Press R to refresh before opening."
    : !state()?.sessions.includes(id) && !agentRecord(id) && !active().some((entry) => entry.id === id) ? "This Safe is no longer present. Return to Safes."
    : hostClosing() || safeClosing(id) ? "This Safe is closing and locking."
    : state()?.family_password_pending.includes(id) ? "Complete or roll back this family's pending password change in Settings before opening this Safe."
    : state()?.recovery_required || active().some((entry) => entry.id === id && entry.recovery_required) || agentRecord(id)?.state === "recovery-required" ? "Recovery is required before this Safe can open."
    : agentRecord(id)?.state === "failed" ? "This Safe's creation failed. No interactive client can start from this record."
    : agentRecord(id)?.ephemeral && !active().some((entry) => entry.id === id)
      && (!active().some((entry) => entry.id === agentRecord(id)!.parent) || safeClosing(agentRecord(id)!.parent)) ? "The parent Safe must stay open to unlock this RAM child."
    : undefined
  const spacious = () => size().width >= 110 && size().height >= 32
  let refreshInFlight = false
  let awaitingInitialRetry = !!props.initialError
  let stopped = false
  let activityAt = -Infinity
  let activityInFlight = false

  function activity() {
    const host = state()?.idle_lock.host
    if (attached() || !host || host.closing || activityInFlight || performance.now() - activityAt < 1000) return
    const opening = state()!.idle_lock.safes.find((entry) => entry.opening.safe_id === safe() && !entry.closing)?.opening ?? null
    activityAt = performance.now()
    activityInFlight = true
    void props.runtime.activity({ host: host.nonce, safe: opening }).catch(() => {}).finally(() => { activityInFlight = false })
  }
  usePaste(() => activity())

  async function refresh() {
    if (refreshInFlight || attached()) return
    refreshInFlight = true
    awaitingInitialRetry = false
    const beforeId = selectedId()
    try {
      const next = await props.runtime.status()
      if (stopped) return
      setState(next)
      setHostReceived(performance.now())
      setError("")
      setSelected((before) => page() === "safes" && beforeId ? Math.max(0, safeIds().indexOf(beforeId)) : Math.min(before, Math.max(0, items().length - 1)))
      if (!context() && next.sessions[0]) setContext(next.sessions[0])
      const id = safe()
      if (page() !== "network" && id && next.open_sessions.some((opened) => opened.id === id)) {
        try {
          const observation = nativeStatus.safeParse(await props.runtime.query(["network", "status", "--safe", id, "--json"]))
          if (!stopped) setObserved(observation.success ? { safe: id, state: observation.data, received: performance.now() } : undefined)
        } catch { if (!stopped) setObserved(undefined) }
      } else if (!id || !next.open_sessions.some((opened) => opened.id === id)) setObserved(undefined)
    } catch {
      awaitingInitialRetry = !state()
      if (!stopped) setError("The Oblivion runtime is unavailable. In Safes, press R to retry.")
    } finally {
      refreshInFlight = false
      if (!stopped) setBusy(false)
    }
  }

  async function execute(args: string[], message?: string, returnToSafes = true): Promise<number> {
    if (attached() || busy()) return 1
    setAttached(true)
    setObserved(undefined)
    setError("")
    setNotice("")
    try {
      const code = await props.runtime.run(args)
      if (code !== 0) setNotice(`The command ended with status ${code}.`)
      else if (message) setNotice(message)
      return code
    } catch {
      setNotice("The command could not be started. Check the Oblivion runtime.")
      return 1
    } finally {
      setAttached(false)
      if (returnToSafes && !props.overlay) { setPage("safes"); setSelected(0) }
      await refresh()
    }
  }

  function section(next: "safes" | "settings" | "system" | "network" | "files" | "rename" | "grow" | "idle" | "imports" | "backups" | "password") {
    if (attached() || busy()) return
    if (selectedId()) setContext(selectedId())
    if (["network", "files", "rename", "grow"].includes(next) && !safe()) return
    setPage(next)
    setSelected(next === "safes" ? Math.max(0, safeIds().indexOf(context() ?? "")) : 0)
    setArea("list")
  }

  function chooseAgent(id?: string, temporary = false, name?: string) {
    if (id ? openingBlocked(id) : state()?.recovery_required || hostClosing()) return
    setTarget(id)
    setSafeName(name)
    setEphemeral(temporary)
    setSelected(0)
    setArea("list")
    setPage("agents")
  }

  function inspect(id: string) {
    if (attached() || busy()) return
    setContext(id); setPage("inspect"); setArea("list"); setSelected(0)
  }

  async function reviewTask(id: string) {
    if (openingBlocked(id) || attached() || busy()) return
    setContext(id)
    // Explicit offline ownership keeps the Safe open when the login client
    // exits; merely switching pages never submits the saved task.
    const code = await execute(["safe", "open", id], undefined, false)
    if (code === 0 && !openingBlocked(id)) { setPage("task"); setSelected(0); setArea("list") }
  }

  function backFromAgents() {
    if (target() && agentRecord(target())) { inspect(target()!); return }
    section("safes")
  }

  function continueLatest() {
    const agent = agents[selected()]
    const id = target()
    if (page() !== "agents" || !state()?.app_open || !id || !agent || openingBlocked(id) || attached() || busy()) return
    void execute(["run", "--safe", id, agent.id, ...conversationArgs(agent.id, "latest")])
  }

  function newSafe() {
    if (state()?.recovery_required || hostClosing()) return
    if (state()?.app_mode !== "persistent") { chooseAgent(undefined, true); return }
    setPage("name")
    setArea("list")
  }

  function workspace() {
    const id = selectedId()
    if (!id || openingBlocked(id)) return
    void execute(["shell", "--safe", id])
  }

  function share(operation: "import" | "export") {
    if (attached() || busy() || state()?.recovery_required || hostClosing()) return
    if (state()?.app_mode !== "persistent") { setNotice("Share requires writable encrypted storage. Lock Oblivion and unlock persistent mode first."); return }
    const id = selectedId()
    if (operation === "export") {
      if (!id || safeClosing(id)) return
      if (!state()?.sessions.includes(id)) { setNotice("Only published persistent Safes can be shared."); return }
      if (active().some((safe) => safe.id === id)) { setNotice("Close and lock this Safe before Share. Other Safes can keep working."); return }
      setContext(id)
      const branch = branchMembers(id)
      setSharing({ operation, scope: "safe", safe: id, name: state()?.session_titles[id] ?? `Safe ${id.slice(0, 8)}`, closed: true,
        branch: branch.length > 1 ? { count: branch.length, closed: !active().some((safe) => branch.includes(safe.id!)) } : undefined })
    } else {
      setContext(undefined)
      setSharing({ operation })
    }
    setNotice(""); setArea("list"); setPage("share")
  }

  function branchMembers(id: string) {
    const seen = new Set([id])
    const known = new Set(state()?.sessions ?? [])
    function visit(parents: string[]) {
      const children = (state()?.safe_parents ?? []).filter((record) => known.has(record.id) && parents.includes(record.parent) && !seen.has(record.id)).map((record) => record.id)
      children.forEach((child) => seen.add(child))
      if (children.length) visit(children)
    }
    visit([id])
    return Array.from(seen)
  }

  function shareAll() {
    if (attached() || busy() || state()?.app_mode !== "persistent" || state()?.recovery_required || hostClosing() || !state()?.sessions.length) return
    if (active().length) { setNotice("Close the included Safes before Share all."); return }
    setContext(undefined)
    setSharing({ operation: "export", scope: "all", count: state()!.sessions.length, closed: true })
    setNotice(""); setArea("list"); setPage("share")
  }

  function reviewStorage(reset: boolean) {
    if (storageUnavailable(state())) return
    setStorageReview({ bytes: state()!.general_bytes, reset })
    setPage("storage")
  }

  async function leave() {
    try { await props.runtime.exit() }
    catch { setNotice(props.overlay ? "The Safe panel could not close. Try again." : "Oblivion could not lock cleanly. Check the runtime before exiting.") }
  }

  const canChooseLiveStorage = () => !!props.liveStorage && !props.overlay && !!props.runtime.chooseLiveStorage
    && !!state() && !state()!.app_open && state()!.app_mode === "locked" && !state()!.general_open
    && !active().length && !state()!.recovery_required && !hostClosing()
    && !state()!.idle_lock.safes.some((entry) => entry.closing) && !error()

  async function chooseStorage() {
    if (!canChooseLiveStorage() || attached() || busy()) return
    setAttached(true)
    setNotice("")
    awaitingInitialRetry = true
    try {
      await props.runtime.chooseLiveStorage!()
    } catch {
      setError("Live storage selection could not be prepared. In Safes, press R to inspect the runtime.")
    } finally {
      // A status request can start the runtime. After stopping, only an explicit
      // retry may do that; the successful path exits to the display's R prompt.
      setAttached(false)
    }
  }

  function lock(quit = false) {
    if (!state()?.app_open) { if (quit) void leave(); return }
    setQuitAfterLock(quit)
    setPage("lock")
    setSelected(0)
    setArea("list")
  }

  const items = createMemo<MenuItem[]>(() => {
    if (page() === "settings") return [...(safe() ? [
      { name: "Network", description: `Change ${safeTitle()}'s gateway policy and inspect its verified route.`, action: "Open network settings", run: () => section("network") },
      { name: "Rename Safe", description: "Change this Safe's title while preserving its files and conversations.", action: "Rename", run: () => section("rename") },
      { name: "Increase storage", description: "Increase the encrypted capacity of a closed Safe. This requires its password.", disabled: selectedOpen() ? "Close this Safe before increasing its storage." : undefined, action: "Increase storage", run: () => section("grow") },
    ] : []),
      { name: "Automatic lock", description: "Set inactivity timers for every Safe and Oblivion. Only human input keeps work open.", action: "Configure automatic lock", run: () => section("idle") },
      { name: "Personal backups", description: "Back up a complete closed Safe, including saved logins, or restore its original encrypted volume. Inspect interrupted transfers separately from Share.", disabled: state()?.app_mode !== "persistent" ? "Unlock writable encrypted storage first." : undefined,
        action: "Open backup and recovery", run: () => section("backups") },
      { name: "Share all Safes", description: "Export every persistent Safe into one encrypted Share. Provider login stores are excluded; content scanning is best effort.",
        disabled: state()?.app_mode !== "persistent" ? "Unlock writable encrypted storage first." : !state()?.sessions.length ? "There are no persistent Safes to export." : active().length ? "Close the included Safes before Share all." : hostClosing() || state()?.recovery_required ? "Wait for verified teardown and recovery." : undefined,
        action: "Choose destination", run: shareAll },
      { name: "Share imports", description: "Inspect pending and interrupted imports, or discard unpublished data explicitly. Completed imports are read-only.", disabled: state()?.app_mode === "ram-only" ? "Unlock your encrypted archive to inspect Share imports." : undefined,
        action: "Inspect imports", run: () => section("imports") },
      { name: "Family passwords", description: "Review the selected Safe's local family, change its shared password, or recover an interrupted update. Old backups retain their password.", disabled: state()?.app_mode !== "persistent" ? "Unlock writable encrypted storage first." : undefined,
        action: "Review family and recovery", run: () => section("password") }]
    if (page() === "lock") return [
      { name: "Keep working", description: "Return to your Safes.", run: () => { setPage("safes"); setSelected(0) } },
      { name: quitAfterLock() ? "Lock and exit" : "Lock Oblivion", description: `Close ${active().length} active Safe(s), stop their agents and lock encrypted storage.`, run: () => {
        void execute(["lock"]).then(() => { if (quitAfterLock() && !state()?.app_open) void leave() })
      } },
    ]
    if (page() === "agents") return agents.map((agent) => ({
      name: agent.name,
      description: agent.description,
      action: "New conversation",
      run: () => { void execute(["run", ...(target() ? ["--safe", target()!] : safeName() ? ["--name", safeName()!] : []), ...(ephemeral() ? ["--ephemeral"] : []), agent.id]) },
    }))
    if (!state()?.app_open) return [
      ...(props.liveStorage === "ephemeral" ? [] : [{
        name: state()?.general_present ? "Unlock Oblivion" : state()?.general_incomplete ? "Reset incomplete storage setup" : "Create encrypted storage",
        badge: state()?.general_present ? "Saved encrypted" : state()?.general_incomplete ? "Setup incomplete" : "First-time setup",
        description: storageUnavailable(state()) ?? (state()?.general_incomplete ? "Review and reset only the unfinished app archive before creating encrypted storage." : "Keep Safes, files and agent logins in encrypted storage. Each Safe has its own password and isolated virtual machine."),
        action: state()?.general_present ? "Unlock" : state()?.general_incomplete ? "Review incomplete setup" : "Review storage",
        disabled: storageUnavailable(state()),
        run: () => { if (state()?.general_present) { void execute(["unlock"]); return }; reviewStorage(state()?.general_incomplete ?? false) },
      }]),
      ...(props.liveStorage === "persistent" ? [] : [{ name: "Ephemeral mode", badge: "RAM only", description: `Work in RAM for this run${state()?.ephemeral_session_bytes ? ` with ${capacity(state()!.ephemeral_session_bytes!)} per Safe` : ""}. New Safes and files are discarded when they close or the computer restarts.`, action: "Enter ephemeral mode", run: () => { void execute(["ephemeral"]) } }]),
      ...(canChooseLiveStorage() ? [{ name: "Change storage mode", description: "Stop the Live runtime and choose persistent or RAM-only storage at the next start. Existing encrypted data is preserved. Press R on the closed screen to start the new choice.", action: "Choose next mode", run: () => { void chooseStorage() } }] : []),
    ]
    return safeRows().map(({ id, depth }) => {
      const opened = active().find((safe) => safe.id === id)
      const origin = agentRecord(id)
      return {
        name: `${depth ? "  ".repeat(Math.min(depth - 1, 4)) + "└─ " : ""}${state()?.session_titles[id] ?? `Safe ${id.slice(0, 8)}`}`,
        badge: `${origin ? "Agent-created · " : ""}${safeClosing(id) || opened && hostClosing() ? "Closing" : state()?.family_password_pending.includes(id) ? "Password recovery" : opened ? opened.recovery_required ? "Recovery required" : "Open" : origin?.state === "failed" ? "Creation failed" : origin?.state === "recovery-required" ? "Recovery required" : "Locked"}`,
        description: `${id.slice(0, 8)} · ${state()?.session_sizes?.[id] ? capacity(state()!.session_sizes![id]) + " · " : ""}${origin ? `Agent-created · requested ${requestedAgentName(origin.agent)}. Review its origin and creation record before opening.` : opened ? "Open another agent in this Safe's VM. All agents in this Safe share its files." : "Unlock this Safe and open an agent in its isolated VM."}`,
        action: origin ? "Review Safe" : "Choose agent",
        disabled: origin ? undefined : openingBlocked(id),
        run: () => origin ? inspect(id) : chooseAgent(id),
      }
    })
  })

  const toolbar = () => page() === "agents" && target() ? [{ title: "Continue latest", key: "C", disabled: !state()?.app_open || !!openingBlocked(target()!), run: continueLatest }] : state()?.app_open && page() === "safes" ? [
    { title: "New Safe", key: "N", disabled: state()?.recovery_required || hostClosing(), run: () => newSafe() },
    { title: "Refresh", key: "R", run: () => { void refresh() } },
    { title: "Import Share", key: "I", disabled: state()?.app_mode !== "persistent" || state()?.recovery_required || hostClosing(), run: () => share("import") },
    ...(selectedId() ? [
      { title: "Details", key: "D", run: () => { if (selectedId()) inspect(selectedId()!) } },
      { title: "Workspace", key: "W", disabled: !!openingBlocked(selectedId()!), run: workspace },
      { title: "Files", key: "F7", disabled: !!openingBlocked(selectedId()!), run: () => section("files") },
      { title: "Network", key: "F9", disabled: !!openingBlocked(selectedId()!), run: () => section("network") },
      { title: "Share", key: "S", disabled: state()?.app_mode !== "persistent" || !state()?.sessions.includes(selectedId()!) || !!selectedOpen() || state()?.recovery_required || hostClosing() || safeClosing(selectedId()), run: () => share("export") },
    ] : []),
  ] : []

  onMount(() => {
    if (!props.initial && !props.initialError) void refresh()
    const timer = clock.setInterval(() => { if (!awaitingInitialRetry) void refresh() }, 5000)
    const tick = clock.setInterval(() => setNow(performance.now()), 1000)
    onCleanup(() => { clock.clearInterval(timer); clock.clearInterval(tick) })
  })
  onCleanup(() => { stopped = true })

  useKeyboard((key) => {
    if (key.name !== "unknown" && !/^\x1b\[(?:[?>]?[0-9;]*[cnyRt]|[IO]|\?[0-9;]*u)$/.test(key.sequence ?? "")) activity()
    if (key.defaultPrevented || attached()) return
    if (props.overlay) {
      if (["escape", "f7", "f9"].includes(key.name) || key.ctrl && key.name === "q") { key.preventDefault(); void leave(); return }
      if (["f1", "f2", "f3"].includes(key.name)) { key.preventDefault(); return }
    }
    if (busy()) return
    if (key.ctrl && key.name === "q") { key.preventDefault(); lock(); return }
    if (["f1", "f2", "f3"].includes(key.name)) { key.preventDefault(); if (key.name !== "f2" || state()?.app_open) section(key.name === "f1" ? "safes" : key.name === "f2" ? "settings" : "system"); return }
    if (key.name === "f7" && state()?.app_open) { key.preventDefault(); section("files"); return }
    if (key.name === "f9" && state()?.app_open) { key.preventDefault(); section("network"); return }
    if (key.name === "escape") {
      if (["files", "network", "rename", "grow", "idle", "storage", "share", "imports", "backups", "password", "task"].includes(page())) return
      key.preventDefault()
      if (page() === "agents") { backFromAgents(); return }
      if (page() !== "safes") { section("safes"); return }
      lock(true)
      return
    }
    if (["name", "files", "network", "rename", "grow", "idle", "storage", "share", "imports", "backups", "password", "task"].includes(page())) return
    if (key.name === "r" && ["safes", "inspect"].includes(page())) { key.preventDefault(); void refresh(); return }
    if (key.name === "tab" && toolbar().length) { key.preventDefault(); setArea((value) => value === "list" ? "actions" : "list"); return }
    if (page() === "agents" && key.name === "c" && target()) { key.preventDefault(); continueLatest(); return }
    if (page() === "safes" && state()?.app_open) {
      if (key.name === "n") { key.preventDefault(); newSafe(); return }
      if (key.name === "w") { key.preventDefault(); workspace(); return }
      if (key.name === "d" && selectedId()) { key.preventDefault(); inspect(selectedId()!); return }
      if (key.name === "s") { key.preventDefault(); share("export"); return }
      if (key.name === "i") { key.preventDefault(); share("import"); return }
      if (key.name === "l") {
        key.preventDefault()
        const id = selectedId()
        if (id && active().some((safe) => safe.id === id)) void execute(["close", id], "Safe closed and locked.")
      }
    }
  })

  return <box width="100%" height="100%" flexDirection="column" backgroundColor={theme.background.base} onMouse={() => activity()}>
    <box flexShrink={0} flexDirection="row" justifyContent="space-between" paddingLeft={2} paddingRight={2} paddingTop={spacious() ? 1 : 0} paddingBottom={1} border={["bottom"]} borderColor={theme.border.base}>
      <text fg={theme.text.brand}><b>OBLIVION</b></text>
      <Show when={!props.overlay} fallback={<text fg={theme.text.base}>{safeTitle()} / {props.overlay?.page === "files" ? "Files" : "Network"}</text>}><box flexDirection="row" gap={2}><For each={[
        { title: "Safes", id: "safes" as const, key: "F1" },
        { title: "Settings", id: "settings" as const, key: "F2" },
        { title: "System", id: "system" as const, key: "F3" },
      ]}>{(item) => <ActionItem theme={palette} modern flush variant={(page() === item.id || item.id === "settings" && ["network", "rename", "grow", "idle", "imports", "backups", "password"].includes(page()) || item.id === "safes" && ["name", "agents", "files", "share", "inspect", "task"].includes(page())) ? "primary" : "secondary"}
        action={{ title: item.title, key: item.key, disabled: attached() || busy() || item.id === "settings" && !state()?.app_open, onTrigger: () => section(item.id) }} />}</For></box></Show>
      <text fg={theme.text.muted}>{props.overlay ? "Safe panel" : props.preview ? "Preview" : state()?.app_open ? state()?.app_mode === "ram-only" ? "Ephemeral mode" : state()?.app_mode === "read-only" ? "Read-only archive" : `${active().length} active Safe(s)` : "Privacy layer"}</text>
    </box>
    <box flexGrow={1} minHeight={0} flexDirection="column" paddingLeft={spacious() ? 5 : 2} paddingRight={spacious() ? 5 : 2} paddingTop={spacious() ? 2 : 1} paddingBottom={1}>
      <Show when={page() === "system"}><NativeSystem state={state()} live={props.liveStorage ? props.runtime : undefined} /></Show>
      <Show when={page() === "inspect" && context() && state()}><SafeInspector state={state()!} id={context()!} blocked={openingBlocked(context()!)} task={() => { void reviewTask(context()!) }} launch={(agent) => { if (!openingBlocked(context()!)) void execute(["run", "--safe", context()!, agent]) }} choose={() => chooseAgent(context())} back={() => section("safes")} /></Show>
      <Show when={page() === "task" && context() && state()}><NativeTask runtime={props.runtime} state={state()!} safe={context()!} name={safeTitle()} policy={scopedNetworkObservation(observed(), context(), state(), now())?.safe_access.current} blocked={openingBlocked(context()!)} run={(args) => execute(args, undefined, false)} back={() => inspect(context()!)} /></Show>
      <Show when={page() === "imports"}><NativeImports runtime={props.runtime} writable={state()?.app_mode === "persistent" && !hostClosing()} run={(args) => execute(args, undefined, false)} back={() => section("settings")} /></Show>
      <Show when={page() === "password"}><NativePassword runtime={props.runtime} writable={state()?.app_mode === "persistent" && !hostClosing()} opening={state()?.idle_lock.host?.nonce}
        blocked={error() ? "Runtime status is unavailable. Refresh before changing a password." : state()?.recovery_required ? "Complete verified teardown and recovery first." : undefined}
        safe={safe() ? { id: safe()!, name: safeTitle(), persistent: state()?.sessions.includes(safe()!) ?? false, closed: !selectedOpen() } : undefined}
        openIds={active().flatMap((entry) => entry.id ? [entry.id] : [])} run={(args) => execute(args, undefined, false)} back={() => section("settings")} /></Show>
      <Show when={page() === "backups"}><NativeBackups runtime={props.runtime} writable={state()?.app_mode === "persistent" && !hostClosing()} opening={state()?.idle_lock.host?.nonce}
        blocked={state()?.recovery_required ? "Complete storage recovery before creating or restoring a backup." : undefined}
        safe={safe() ? { id: safe()!, name: safeTitle(), persistent: state()?.sessions.includes(safe()!) ?? false, closed: !active().some((entry) => entry.id === safe()) } : undefined}
        run={(args) => execute(args, undefined, false)} back={() => section("settings")} /></Show>
      <Show when={page() === "share" && sharing()} keyed>{(selection) => <NativeShare
        opening={state()?.idle_lock.host?.nonce}
        selection={selection.operation === "import" ? selection : selection.scope === "all" ? { ...selection, count: state()?.sessions.length ?? 0, closed: !active().length }
          : { ...selection, closed: !active().some((safe) => safe.id === selection.safe), branch: selection.branch ? { count: branchMembers(selection.safe).length, closed: !active().some((safe) => branchMembers(selection.safe).includes(safe.id!)) } : undefined }}
        run={(args) => execute(args, undefined, false)} back={() => section("safes")} />}</Show>
      <Show when={page() === "storage" && storageReview()} keyed>{(review) => <NativeStorage bytes={review.bytes} reset={review.reset} back={() => { setPage("safes"); setSelected(0) }} submit={() => { void execute(["init", ...(review.reset ? ["--reset-incomplete", "--confirmed-reset"] : [])], review.reset ? "Incomplete setup removed. Review storage to create a new archive." : "Storage created. Unlock Oblivion to begin.") }} />}</Show>
      <Show when={page() === "idle" && state()}><NativeIdle state={state()!} back={() => section("settings")} save={(safe, host) => {
        if (hostClosing()) { setNotice("Automatic lock is already closing Oblivion. Wait for teardown to finish."); return }
        void execute(["settings", "idle", "--safe-minutes", String(safe), "--host-minutes", String(host)], "Automatic lock updated.", false)
      }} /></Show>
      <Show when={props.overlay && state() && !selectedOpen()}><text fg={theme.feedback.warning}>This Safe is no longer open. Return to the agent terminal to continue.</text></Show>
      <Show when={page() === "network" && (!props.overlay || selectedOpen()) && safe()} keyed>{(id) => <NativeNetwork safe={id} name={safeTitle()} open={active().some((opened) => opened.id === id)} runtime={props.runtime} run={async (args) => await execute(args, undefined, false) === 0} observed={setObserved} back={() => props.overlay ? void leave() : section("settings")} />}</Show>
      <Show when={page() === "files" && (!props.overlay || selectedOpen()) && safe()} keyed>{(id) => <NativeFiles safe={id} name={safeTitle()} transfers={fileTransfers} opening={state()?.idle_lock.safes.find((safe) => safe.opening.safe_id === id)?.opening.nonce}
        blocked={hostClosing() || safeClosing(id) ? "This Safe is closing and locking." : error() || undefined} runtime={props.runtime} run={async (args) => await execute(args, undefined, false) === 0} back={() => props.overlay ? void leave() : section("safes")} />}</Show>
      <Show when={page() === "rename" || page() === "grow"}><FormView form={{ title: page() === "rename" ? "Rename Safe" : "Increase storage", description: safeTitle(), fields: [{ id: "value", label: page() === "rename" ? "Safe name" : "New total capacity (MiB)", value: page() === "rename" ? safeTitle() : String(Math.max(2048, Math.ceil((state()?.session_sizes?.[safe()!] ?? 0) / 1024 ** 2) + 1024)), validate: (value) => page() === "rename" ? !value.trim() || value.trim() !== value ? "Enter a name without leading or trailing spaces." : undefined : !/^\d+$/.test(value) || Number(value) < 512 ? "Enter a capacity of at least 512 MiB." : undefined }], submit: page() === "rename" ? "Rename" : "Increase storage", run: async () => {} }} cancel={() => section("settings")} submit={(values) => { void execute(["safe", page() === "rename" ? "rename" : "grow", safe()!, values.value]) }} /></Show>
      <Show when={["safes", "settings", "name", "agents", "lock"].includes(page())}>
      <Show when={page() === "name"} fallback={<Menu title={page() === "settings" ? "Settings" : page() === "lock" ? "Close and lock" : page() === "agents" ? "Choose an agent" : state()?.app_open ? "Your Safes" : "Welcome to Oblivion"}
        description={page() === "settings" ? `${safeTitle()} · Network and storage apply to the selected Safe. Automatic lock applies to Oblivion.` : page() === "agents" ? target() ? `${state()?.session_titles[target()!] ?? target()!.slice(0, 8)} · Shared files, independent agent conversations\nEnter starts a new conversation. C continues the highlighted agent's latest saved conversation.` : ephemeral() ? "Create an isolated Safe in RAM. Its contents are discarded when closed." : `${safeName() ?? "New Safe"} · Separate password, encrypted files and virtual machine.` : page() === "lock" ? "Active work stops when its Safe is locked." : state()?.app_open ? "Choose a Safe to continue, or create a separate environment." : props.liveStorage ? `${props.liveStorage === "ephemeral" ? "RAM-only Live run. Persistent storage is not attached." : "Persistent Live run. Encrypted data stays on the selected boot device."} ${canChooseLiveStorage() ? "Use Change storage mode below to choose again." : "Close active work and complete recovery before changing modes."}` : "Run your coding agent in an isolated VM. Choose how to keep your work."}
        items={items()} selected={selected()} change={setSelected} focused={area() === "list"} disabled={attached() || busy() || !!error()}
        choose={(index) => { const item = items()[index]; if (item && !item.disabled) item.run() }}
        toolbar={toolbar()} actionsFocused={area() === "actions"} focusActions={() => setArea("actions")} focus={() => setArea("list")}
        empty="No Safes yet. Press N to create your first Safe." back={page() !== "safes" ? () => { if (page() === "agents") { backFromAgents(); return }; section("safes") } : undefined} />}>
        <FormView form={{ title: "New Safe", description: "Give this isolated environment a name. Its password is requested securely in the terminal.", submit: "Choose agent", fields: [{ id: "name", label: "Safe name", validate: (value) => value.trim() !== value || !value || Array.from(value).length > 80 || Buffer.byteLength(value) > 256 || /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value) ? "Use 1–80 characters without leading or trailing spaces." : undefined }], run: async () => {} }}
          cancel={() => { setPage("safes"); setSelected(0) }} submit={(values) => chooseAgent(undefined, false, values.name)} />
      </Show>
      </Show>
      <Show when={state()?.recovery_required}><text flexShrink={0} fg={theme.feedback.warning}>Recovery is required. Close and lock Oblivion before opening more Safes.</text></Show>
      <Show when={state()?.idle_lock.host?.closing || state()?.idle_lock.safes.some((entry) => entry.closing)}><text flexShrink={0} fg={theme.feedback.warning}>Closing inactive work. Waiting for verified teardown.</text></Show>
      <Show when={state()?.idle_lock.last_error}><text flexShrink={0} fg={theme.feedback.warning}>Automatic lock requires recovery: {state()?.idle_lock.last_error}</text></Show>
      <Show when={error() || notice()}><text flexShrink={0} fg={error() ? theme.feedback.error : theme.feedback.info}>{error() || notice()}</text></Show>
    </box>
    <box flexShrink={0} flexDirection="row" flexWrap="wrap" columnGap={2} justifyContent="space-between" paddingLeft={2} paddingRight={2} paddingTop={spacious() ? 1 : 0} paddingBottom={spacious() ? 1 : 0} border={["top"]} borderColor={theme.border.base}>
      <NativeNetworkIndicator observation={observed()} safe={safe()} host={state()} hostReceived={hostReceived()} />
      <ActionBar actions={props.overlay ? [{ title: "Back to agent", key: "Esc", run: () => { void leave() } }] : state()?.app_open ? [
        { title: "Lock Safe", key: "L", disabled: !selectedOpen() || hostClosing() || safeClosing(safe()), run: () => {
          const id = selectedOpen()?.id
          if (id) void execute(["close", id], "Safe closed and locked.")
        } },
        { title: "Lock Oblivion", key: "Ctrl+Q", run: () => lock() },
      ] : [{ title: "Exit", key: "Esc", run: () => { void leave() } }]} disabled={attached() || busy()} />
    </box>
    <Show when={busy()}><BusyModal text={props.overlay ? "Opening Safe panel" : "Opening Oblivion"} /></Show>
  </box>
}
