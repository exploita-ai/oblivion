import { useKeyboard } from "@opentui/solid"
import { createMemo, createSignal, onCleanup, onMount, Show } from "solid-js"
import { ControlError, type Request } from "./control"
import { FormView, type Form, type Field } from "./form"
import { capacity, defaults, status, type Status } from "./state"
import { BootLogo } from "./logo"
import { catalog, Setup, type Catalog } from "./setup"
import { Documents } from "./documents"
import { Menu, type MenuItem } from "./menu"
import { Shell, sections, accessSections } from "./shell"
import { ChatViewport, type ChatConnect, type ChatConnection, type ChatFrame } from "./chat"
import { startWhenReady } from "./start-chat"
import { DebugPage, debugStatus } from "./debug-page"
import { SystemPage } from "./system-page"
import type { PageAction } from "./action-bar"
import { NetworkPage, networkTabs } from "./network-page"

export type Runtime = {
  connectChat?: ChatConnect
  clearClipboard?: () => void
  request: (input: Request) => Promise<string>
  console: () => Promise<"sessions" | "new">
  documents: () => Promise<void>
  exit: () => void
}

const providers = [
  { value: "abliteration-ai", label: "Abliteration.ai" },
  { value: "refuseless", label: "Refuseless" },
  { value: "openrouter", label: "OpenRouter · ZDR enforced" },
]

function providerName(id: string) {
  return providers.find((provider) => provider.value === id)?.label ?? id
}

export function App(props: { runtime: Runtime; preview?: boolean; initial?: Status; documentsOnly?: boolean }) {
  const [state, setState] = createSignal(props.initial)
  const [page, setPage] = createSignal(0)
  const [sessionSection, setSessionSection] = createSignal(0)
  const [accessSection, setAccessSection] = createSignal(0)
  const [networkTab, setNetworkTab] = createSignal(0)
  const networkVisible = () => !!state()?.general_mounted && !state()?.session_open && page() === 1
  const [keyID, setKeyID] = createSignal<string>()
  const [diagnostics, setDiagnostics] = createSignal<ReturnType<typeof debugStatus.parse>>()
  const debugVisible = () => !!state()?.debug_available && !state()?.session_open && page() === sections.length
  const category = () => debugVisible() ? "Debug" : sections[page()]
  async function debug(action = "status") {
    setDiagnostics(debugStatus.parse(JSON.parse(await command("debug", { action }))))
  }
  const sessionTitle = (id: string) => state()?.session_titles[id] ?? `Session ${id.slice(0, 8)}`
  const [session, setSession] = createSignal<string | undefined>(props.initial?.active_session ?? undefined)
  const [documents, setDocuments] = createSignal(!!props.documentsOnly || !!props.initial?.session_open)
  const [documentsLocked, setDocumentsLocked] = createSignal(false)
  const [chatVisible, setChatVisible] = createSignal(false)
  const [connection, setConnection] = createSignal<ChatConnection>()
  let drawChat: ((frame: ChatFrame) => void) | undefined
  const [networkWait, setNetworkWait] = createSignal<AbortController>()
  onCleanup(() => networkWait()?.abort())
  const [wizard, setWizard] = createSignal<Catalog>()
  const [intro, setIntro] = createSignal(false)
  const [elapsed, setElapsed] = createSignal(0)
  const [observed, setObserved] = createSignal(performance.now())
  const [now, setNow] = createSignal(performance.now())
  const breadcrumb = () => !state()?.general_mounted
    ? `ACCESS / ${debugVisible() ? "Debug" : wizard() ? "Keyboard and time zone" : form()?.title ?? (state()?.general_present ? "Welcome back" : "First-time setup")}`
    : page() === 0 && session() && state()?.session_open ? `SESSION / ${state()?.session_titles[session()!] ?? session()!.slice(0, 8)} / ${form()?.title ?? "Documents"}`
    : `HOST / ${category()}${networkVisible() ? ` / ${networkTabs[networkTab()]}` : ""}${keyID() ? " / " + (state()?.api_keys?.entries.find((entry) => entry.id === keyID())?.name ?? "Key") : page() === 0 && session() ? ` / ${state()?.session_titles[session()!] ?? session()!.slice(0, 8)}` : ""}`
  const editing = () => !!form() || !!wizard() || !!busy() || intro() || documentsLocked()
  const blocked = () => editing() || documents()
  const navigate = (index: number) => { setChatVisible(false); setDocuments(false); setPage(index); setSession(undefined); setKeyID(undefined); setSelection(0); setFocus("content"); setNotice(""); if (debugVisible()) void perform("Refresh debug status", () => debug()) }
  const back = () => {
    setNotice("")
    if (!state()?.general_mounted) { setPage(0); setSelection(0); setFocus("content"); return }
    if (state()?.session_open) {
      setSession(state()?.active_session ?? "ephemeral"); setPage(0); setKeyID(undefined); setFocus("navigation"); return
    }
    if (keyID()) { setKeyID(undefined); setSelection(0); return }
    if (page() === 0 && session()) { setSession(undefined); setSelection(0); return }
    setFocus("navigation")
  }
  const [focus, setFocus] = createSignal<"navigation" | "content" | "actions">("content")
  const [selection, setSelection] = createSignal(0)
  const [resumeChat, setResumeChat] = createSignal(false)
  const [form, setForm] = createSignal<Form>()
  const [busy, setBusy] = createSignal("")
  const [notice, setNotice] = createSignal("")
  const [feedback, setFeedback] = createSignal<"info" | "success" | "error">("info")
  const welcome = () => !!state()?.general_present && !state()?.general_mounted && !state()?.general_incomplete && !state()?.recovery_required && !form() && !wizard() && !debugVisible()
  const unavailable = () => !state()?.general_mounted ? "Unlock Oblivion first." : state()?.session_open && state()?.session_mode !== "documents" ? "Close the active chat first." : undefined
  const networkUnavailable = () => state()?.recovery_required ? "Complete recovery first." : state()?.session_open && state()?.session_mode !== "documents" ? "Close the active chat first." : undefined
  const persistent = () => !!state()?.general_mounted && !state()?.general_readonly

  function accessSettings(index: number) {
    setAccessSection(index); setFocus("content"); setNotice(""); setSelection(0)
    if (index === accessSections.length && state()?.debug_available) { navigate(sections.length); return }
    setPage(0)
    void perform("Load settings", setup)
  }

  async function refresh() {
    const previous = state()?.active_session
    setState(status.parse(JSON.parse(await props.runtime.request({ operation: "status" }))))
    if (previous && previous !== state()?.active_session) props.runtime.clearClipboard?.()
    setObserved(performance.now())
    if (state()?.session_mode !== "chat") detachChat()
    if (!previous && state()?.active_session) { setSession(state()?.active_session ?? undefined); setDocuments(true) }
    if (previous && !state()?.active_session) { setDocuments(false); setSession(undefined) }
  }

  function detachChat() {
    connection()?.close()
    setConnection(undefined); setChatVisible(false)
  }
  onCleanup(detachChat)

  async function perform(label: string, operation: () => Promise<void>) {
    if (busy()) return
    setBusy(label)
    setNotice("")
    setFeedback("info")
    setForm(undefined)
    try {
      await operation()
      await refresh()
      setFeedback("success")
      setNotice(wizard() || ["Refresh", "Load system status"].includes(label) ? "" : label + " completed.")
    } catch (error) {
      setFeedback(error instanceof ControlError && ["gateway_not_ready", "chat_start_cancelled"].includes(error.code) ? "info" : "error")
      setNotice(explain(error))
      await refresh().catch(() => undefined)
    } finally {
      setBusy("")
      if (state()?.session_open && !chatVisible() && !form() && !wizard()) setDocuments(true)
    }
  }

  async function command(operation: Request["operation"], value?: object | string, session?: string) {
    if (operation === "close" || operation === "lock") props.runtime.clearClipboard?.()
    const payload = value === undefined ? undefined : new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value))
    try {
      return await props.runtime.request({ operation, payload, session })
    } finally {
      payload?.fill(0)
    }
  }

  function confirm(title: string, description: string, run: () => Promise<void>) {
    setForm({ title, description, fields: [], submit: title, run })
  }

  function unlock(ephemeral = false) {
    setForm({
      title: ephemeral ? "Ephemeral mode" : "Unlock Oblivion",
      description: ephemeral ? "Use your saved settings without writing to persistent storage. New conversations and files live in RAM and are removed when closed." : "Unlock your settings and session list. Each session keeps its own password.",
      fields: [{ id: "password", label: "Oblivion password", secret: true }], submit: ephemeral ? "Start ephemeral mode" : "Unlock Oblivion",
      run: async (values) => {
        await command(ephemeral ? "unlock-ephemeral" : "unlock", values.password)
        navigate(0)
        await refresh()
        if (!ephemeral && state()?.settings?.saved?.completed !== true) await setup()
      },
    })
  }

  async function setup() {
    setWizard(catalog.parse(JSON.parse(await props.runtime.request({ operation: "settings-catalog" }))))
  }

  function keyboardTest() {
    setForm({ title: "Test your keyboard", description: "Type a harmless sample such as @ - / : and check the characters. Do not enter a password here.", fields: [{ id: "sample", label: "Keyboard test", description: "This sample is discarded when you continue." }], submit: "Continue", run: async () => {} })
  }

  function create() {
    if (state()?.general_readonly) {
      setForm({ title: "New ephemeral session", description: "All chats share this session’s documents. Everything stays in RAM.", fields: [titleField()], submit: "Create and start chat", run: async (values) => {
        await command("open-documents-ephemeral"); await refresh();
        const id = state()!.active_session!;
        await command("rename-session", { id, title: values.title.trim() }); setSession(id); setSelection(0); await refresh(); await launchChat()
      } })
      return
    }
    setForm({
      title: "Create a protected session", description: `A separate encrypted volume keeps all chats and their shared documents together. Size: ${capacity(state()?.session_bytes ?? 0)}.`,
      fields: [titleField(), { id: "password", label: "Session password", secret: true, description: "Use at least 16 characters.", validate: (value) => Buffer.byteLength(value) < 16 ? "Use a longer password (at least 16 bytes)." : undefined }, { id: "confirm", label: "Repeat session password", secret: true, validate: (value, values) => value !== values.password ? "The passwords do not match. Try again." : undefined }, ...chatKeyFields()], submit: "Create and start chat",
      run: async (values) => {
        validatePassword(values)
        const id = (await command("create", values.password)).trim()
        await command("rename-session", { id, title: values.title.trim() })
        await command("open-documents", values.password, id)
        setSession(id); setSelection(0)
        await refresh(); await launchChat(values.key)
      },
    })
  }

  async function chat() {
    if (props.runtime.connectChat) {
      if (!connection()) setConnection(props.runtime.connectChat((event) => {
        if (event.type === "frame") { drawChat?.(event); return }
        // Guest requests are hints. Only a fresh action in the host form locks.
        setChatVisible(false)
        confirm(event.action === "new" ? "Create another session" : event.action === "sessions" ? "Switch session" : "Close and lock session", "The chat requested this action. Confirm to stop the response and lock this session, or Esc to keep it open.", async () => {
          await command("close"); detachChat(); setSession(undefined)
          if (event.action === "new") create()
        })
      }, () => {
        detachChat(); setDocuments(true); setFeedback("error"); setNotice("The chat display disconnected. Return to chat to reconnect, or close and lock the session.")
      }))
      setDocuments(false); setForm(undefined); setChatVisible(true); setFocus("content")
      return
    }
    const action = await props.runtime.console()
    await refresh()
    if (action === "new") create()
    if (!state()?.session_open) setSession(undefined)
  }

  function open(id: string) {
    setForm({ title: "Open protected session", description: `${sessionTitle(id)} · All chats and shared documents are restored from this session's encrypted volume.`, fields: [{ id: "password", label: "Session password", secret: true }, ...chatKeyFields()], submit: "Unlock session", run: async (values) => { await command("open-documents", values.password, id); setSession(id); await refresh(); await launchChat(values.key) } })
  }

  function prepare() {
    const plan = state()?.persistence?.plan
    if (!plan) return
    setForm({
      title: "Create encrypted storage",
      description: `System storage: /dev/${plan.device} · ${capacity(plan.disk_bytes)}. Reserve ${capacity(plan.sectors * 512)} of available unpartitioned space for Oblivion. Existing data in that space will be overwritten.`,
      fields: [{ id: "confirmStorage", label: "Confirm storage", choices: [{ value: "no", label: "Cancel setup" }, { value: "yes", label: "Use the available free space" }] }, { id: "password", label: "New Oblivion password", secret: true }, { id: "confirm", label: "Repeat Oblivion password", secret: true }],
      submit: "Create encrypted storage",
      run: async (values) => {
        if (values.confirmStorage !== "yes") throw new ControlError("storage_confirmation_required")
        validatePassword(values)
        await command("prepare-usb", { plan, password: values.password })
        await command("unlock", values.password)
        navigate(0)
        await refresh()
        await setup()
      },
    })
  }

  function addKey() {
    setForm({
      title: "Add provider API key",
      description: persistent() ? "Saved automatically in encrypted storage. Secrets stay hidden." : "Kept in RAM for this ephemeral workspace. Secrets stay hidden.",
      fields: [
        { id: "provider", label: "Provider", value: "abliteration-ai", choices: providers },
        { id: "name", label: "Key name", value: "Personal" },
        { id: "key", label: "API key", secret: true, description: "Paste the complete key from the selected provider. It stays hidden.", validate: validateKey },
      ],
      submit: "Add key",
      run: async (values) => {
        await command("api-keys", { action: persistent() ? "add" : "temporary", provider: values.provider, name: values.name, key: values.key })
        if (state()?.session_open && state()?.session_mode !== "chat") { await refresh(); await launchChat() }
      },
    })
  }

  function editKey(action: "rename" | "replace", id: string, name: string) {
    setForm({ title: action === "rename" ? "Rename API key" : "Replace API key", description: action === "rename" ? "Choose a name you will recognize when starting a chat." : `Replace the secret for “${name}”. Its provider stays unchanged.`, fields: action === "rename" ? [{ id: "name", label: "Name", value: name }] : [{ id: "key", label: "New API key", secret: true, validate: validateKey }], submit: action === "rename" ? "Save name" : "Replace key", run: async (values) => { await command("api-keys", { action, id, ...(action === "rename" ? { name: values.name } : { key: values.key }) }) } })
  }

  function transport(socks: boolean) {
    if (!socks) { void perform("Switching to Tor", async () => { await command("egress", { action: persistent() ? "save" : "select", transport: { mode: "tor" } }) }); return }
    const selected = state()?.egress?.selected
    setForm({ title: "Configure SOCKS5 proxy", description: `No direct fallback. ${persistent() ? "Changes are saved encrypted automatically." : "Changes stay in RAM."}`, fields: [{ id: "endpoint", label: "Proxy IPv4 address and port", value: selected?.mode === "socks5" ? selected.endpoint : "", description: "For example 192.168.1.10:1080" }, { id: "username", label: "Username (optional)" }, { id: "password", label: "Password (optional)", secret: true }], submit: "Use SOCKS5", run: async (values) => {
      await command("egress", { action: persistent() ? "save" : "select", transport: { mode: "socks5", endpoint: values.endpoint, authentication: values.username ? { username: values.username, password: values.password } : null } })
    } })
  }

  function addRule() {
    setForm({ title: "Add a web access rule", description: "Control tool access to public destinations. Inference providers use a separate fixed gateway route.", fields: [{ id: "destination", label: "Domain or public IP", description: "For example example.org or *.example.org" }, { id: "port", label: "Port", value: "443" }, { id: "action", label: "Action", choices: [{ value: "deny", label: "Block" }, { value: "allow", label: "Allow" }] }], submit: "Add rule", run: async (values) => { await command("network-policy", { action: "put", rule: { destination: values.destination, port: Number(values.port), action: values.action }, save: persistent() }) } })
  }

  async function changeConnection(value: object) {
    await command("connections", value)
  }

  function startChat() {
    const entries = state()?.api_keys?.entries ?? []
    if (!entries.length) { addKey(); setFeedback("info"); setNotice("Add an API key to start chat. Your session documents are still available."); return }
    setForm({ title: "Start chat", description: "Choose a provider and key for this opening. Documents remain available if the protected route is not ready.", fields: [{ id: "key", label: "Provider and API key", value: state()?.api_keys?.selected ?? state()?.api_keys?.default ?? entries[0].id, choices: entries.map((key) => ({ value: key.id, label: `${providerName(key.provider)} · ${key.name}${key.id === state()?.api_keys?.default ? " (default)" : ""}` })) }], submit: "Connect and start chat", run: async (values) => {
      await launchChat(values.key)
    } })
  }

  function chatKeyFields(): Field[] {
    const entries = state()?.api_keys?.entries ?? []
    if (entries.length < 2) return []
    return [{ id: "key", label: "Provider and API key", value: state()?.api_keys?.default ?? entries[0].id,
      choices: entries.map((key) => ({ value: key.id, label: `${providerName(key.provider)} · ${key.name}${key.id === state()?.api_keys?.default ? " (default)" : ""}` })) }]
  }

  async function launchChat(key?: string) {
    setDocuments(false)
    const entries = state()?.api_keys?.entries ?? []
    const id = key ?? state()?.api_keys?.default ?? entries[0]?.id
    if (!id) { addKey(); setFeedback("info"); setNotice("Add an API key to start chat. Press Esc to browse documents offline."); return }
    await command("api-keys", { action: "select", id })
    const controller = new AbortController()
    await startWhenReady(async () => { await command("start-chat") }, {
      signal: controller.signal,
      waiting: (waiting) => {
        setNetworkWait(waiting ? controller : undefined)
        setBusy(waiting ? `Connecting to ${state()?.egress?.selected?.mode === "socks5" ? "SOCKS5" : "Tor"}` : "Starting chat")
      },
    })
    await chat()
  }

  function sessionView(index: number) {
    setNotice("")
    setSessionSection(index); setFocus("content"); setPage(0); setSession(state()?.active_session ?? "ephemeral"); setKeyID(undefined)
    setChatVisible(false); setDocuments(index === 1)
    if (index === 1) return
    if (state()?.session_mode === "chat") { void chat(); return }
    startChat()
  }

  function closeSession() {
    setNotice("")
    setResumeChat(chatVisible())
    setChatVisible(false); setDocuments(false)
    confirm("Close and lock session", "Stop all running chats and lock the session's encrypted volume.", async () => {
      await command("close"); detachChat(); navigate(0)
    })
  }

  function lockOblivion() {
    confirm("Lock Oblivion", "Lock your encrypted settings and return to Welcome back.", async () => { await command("lock"); navigate(0) })
  }

  function pageActions(): PageAction[] {
    if (debugVisible()) return [
      { title: diagnostics()?.ssh_active ? "Disable access" : "Enable access", key: "E", disabled: !diagnostics(), run: () => void perform(diagnostics()?.ssh_active ? "Disable debug access" : "Enable debug access", () => debug(diagnostics()?.ssh_active ? "disable-ssh" : "enable-ssh")) },
      { title: "Refresh", key: "R", run: () => void perform("Refresh debug status", () => debug()) },
    ]
    if (!state()?.general_mounted || state()?.session_open || state()?.recovery_required) return []
    if (networkVisible()) {
      if (networkTab() === 2) return [{ title: "Add rule", key: "N", disabled: !!networkUnavailable(), run: addRule }]
      if (networkTab() === 1) return []
      return [{ title: "Refresh", key: "R", disabled: !!networkUnavailable(), run: () => void perform("Refreshing connections", async () => {
        if (state()?.connections?.wifi_enabled && state()?.connections?.devices.some((device) => device.kind === "wifi")) await command("connections", { action: "scan" })
      }) }]
    }
    if (page() === 0 && !session()) return [
      { title: "New session", key: "N", run: create },
      { title: "Rename", key: "R", disabled: !state()?.sessions[selection()], run: () => {
        const id = state()?.sessions[selection()]; if (!id) return
        setForm({ title: "Rename session", description: "The title is saved in your encrypted Oblivion storage. Chat titles are managed separately inside the session.", fields: [titleField(sessionTitle(id))], submit: "Save title", run: async (values) => { await command("rename-session", { id, title: values.title.trim() }) } })
      } },
    ]
    if (page() === 2 && !keyID()) return [{ title: "Add API key", key: "N", disabled: !!unavailable(), run: addKey }]
    return []
  }

  function networkDescription() {
    const current = state()
    const storage = current?.general_readonly ? "Changes stay in RAM" : "Changes are saved encrypted automatically"
    if (networkTab() === 1) return `${storage}. ${current?.egress?.selected.mode === "socks5" ? "SOCKS5" : "Tor"} selected. The route starts with chat; selection alone does not verify protection.`
    if (networkTab() === 2) return `${storage}. Control websites reached by session tools. Provider traffic uses its dedicated route.`
    if (!current?.connections) return "NetworkManager is unavailable. Retry to refresh the connection status."
    const wifi = current.connections.devices.some((device) => device.kind === "wifi") ? "Choose a Wi-Fi network or manage Ethernet." : "Ethernet connections. No Wi-Fi adapter detected."
    return `${wifi} ${current.connections.internet === "local" ? "Internet [?]: local route available; external access is not verified." : ""} ${storage}.`
  }

  function connectWifi(ap: NonNullable<Status["connections"]>["access_points"][number]) {
    const open = ap.security === "--" || ap.security === ""
    setForm({ title: `Connect to ${ap.ssid}`, description: `${ap.security || "Open network"} · Signal ${ap.signal}%`,
      fields: open ? [] : [{ id: "password", label: "Wi-Fi password", secret: true }],
      submit: "Connect", run: async (values) => {
        await changeConnection({ action: "connect", device: ap.device, bssid: ap.bssid, password: values.password ?? "" })
      },
    })
  }

  function networkItems(): MenuItem[] {
    const current = state()
    if (!current) return []
    if (networkTab() === 1) return [
      { name: `${current.egress?.selected.mode !== "socks5" ? "[x]" : "[ ]"} Tor`, description: "Route provider and permitted tool traffic through Tor. No direct fallback.", disabled: networkUnavailable(), action: "Use Tor", run: () => { if (current.egress?.selected.mode === "socks5") transport(false) } },
      { name: `${current.egress?.selected.mode === "socks5" ? "[x]" : "[ ]"} SOCKS5 proxy`, description: "Use your own proxy instead of Tor. Configure address and optional authentication.", disabled: networkUnavailable(), action: "Configure proxy", run: () => transport(true) },
    ]
    if (networkTab() === 2) return [
      ...(current.network_policy?.policy.rules ?? []).map((rule) => ({ name: `${rule.action.toUpperCase()} ${rule.destination}:${rule.port}`, description: rule.session ? `Session ${rule.session.slice(0, 8)}` : "All sessions", disabled: networkUnavailable(), action: "Remove rule", run: () => confirm("Remove web rule", `${rule.action} ${rule.destination}:${rule.port}`, async () => {
        await command("network-policy", { action: "remove", rule, save: persistent() })
        setSelection(0)
      }) })),
    ]
    const snapshot = current.connections
    const devices = snapshot?.devices ?? []
    return [
      ...devices.filter((device) => device.kind === "ethernet").map((device) => ({ name: `Ethernet · ${device.name}`, badge: device.state, description: device.state.startsWith("connected") ? "Disconnect this Ethernet connection. This interrupts network traffic." : "Connect using the existing Ethernet profile or automatic configuration.", disabled: networkUnavailable(), action: device.state.startsWith("connected") ? "Disconnect" : "Connect", run: () => device.state.startsWith("connected")
        ? confirm("Disconnect Ethernet", "This interrupts traffic through this adapter.", async () => { await changeConnection({ action: "disconnect", device: device.name }) })
        : void perform("Connect Ethernet", async () => { await changeConnection({ action: "connect", device: device.name }) }) })),
      ...(devices.some((device) => device.kind === "wifi") ? [
        { name: "Wi-Fi", badge: snapshot?.wifi_enabled ? "On" : "Off", description: "Turn the Wi-Fi radio on or off.", disabled: networkUnavailable(), action: snapshot?.wifi_enabled ? "Turn off Wi-Fi" : "Turn on Wi-Fi", run: () => snapshot?.wifi_enabled
          ? confirm("Turn off Wi-Fi", "This disconnects Wi-Fi networks.", async () => { await changeConnection({ action: "radio", enabled: false }) })
          : void perform("Turn on Wi-Fi", async () => { await changeConnection({ action: "radio", enabled: true }) }) },
        ...(snapshot?.access_points ?? []).map((ap) => ({ name: ap.ssid, badge: ap.active ? "Connected" : `${ap.signal}% · ${ap.security || "Open"}`, description: `${ap.device} · ${ap.security || "Open network"} · Signal ${ap.signal}%`, disabled: networkUnavailable() ?? (/802\.1X|EAP|WEP/.test(ap.security) || !/WPA2|WPA3|^--$|^$/.test(ap.security) ? "This Wi-Fi security type is not supported yet." : undefined), action: ap.active ? "Disconnect" : "Connect", run: () => ap.active
          ? confirm("Disconnect Wi-Fi", `Disconnect from ${ap.ssid}.`, async () => { await changeConnection({ action: "disconnect", device: ap.device }) })
          : connectWifi(ap) })),
      ] : []),
    ]
  }

  const items = createMemo<MenuItem[]>(() => {
    const current = state()
    if (!current) return []
    if (networkVisible()) return networkItems()
    if (current.recovery_required) return [{ name: "Complete recovery and lock", description: "Cleanup is required before another session can open.", run: () => void perform("Recover and lock", async () => { await command("lock"); setSession(undefined) }) }, { name: "Force stop and lock", description: "Use only if graceful recovery fails. Unsaved work may be lost.", run: () => confirm("Force stop and lock", "Force the failed session VM to stop, then lock its encrypted volume and persistent settings. Unfinished writes may be lost.", async () => { await command("force-close"); await command("lock"); setSession(undefined) }) }]
    if (!current.general_mounted && current.general_present && !current.general_incomplete) return [
      { name: "Unlock Oblivion", badge: "PERSISTENT", description: "Unlock your saved settings and sessions. Each session has its own password. Changes are saved inside encrypted storage.", run: () => unlock() },
      { name: "Ephemeral mode", badge: "RAM ONLY", description: "Use your saved settings read-only. New chats, documents and changes stay in RAM and are lost when closed. Persistent storage stays unchanged.", run: () => unlock(true) },
    ]
    if (!current.general_mounted) return [
      ...(current.general_incomplete ? [{ name: "Discard incomplete preparation", description: "Remove only the unfinished Oblivion setup attempt.", run: () => confirm("Discard incomplete preparation", "This removes unfinished encrypted storage. Completed storage is preserved.", async () => { await command("discard-general-pending") }) }] : [{ name: "Create encrypted storage", description: current.persistence?.unavailable ? "No compatible persistent storage is available." : "Protect sessions, documents, API keys and preferences in one encrypted space.", disabled: current.persistence?.unavailable ?? undefined, run: prepare }]),
    ]
    if (page() === 0 && session()) {
      if (!current.session_open) return [
        { name: "Unlock session", description: "Unlock this session and start chat. Documents remain available offline with F7.", run: () => open(session()!) },
        { name: "Back to sessions", description: "Keep this session locked.", run: back },
      ]
      return []
    }
    if (page() === 0) return [
      ...(current.session_open ? [{ name: "Current session", description: current.session_mode === "documents" ? "OPEN · Documents only · No network device" : "OPEN · Chat", run: () => setSession(current.active_session ?? "ephemeral") }] : []),
      ...current.sessions.filter((id) => id !== current.active_session).map((id) => ({ name: sessionTitle(id), description: `Unlock to resume your chats. Browse documents anytime with F7. ${capacity(current.session_bytes)} of private storage.`, disabled: current.session_open ? "Close the current session first." : undefined, badge: id.slice(0, 8), action: "Unlock session", run: () => { setSession(id); setSelection(0); open(id) } })),
      ...current.incomplete_sessions.map((id) => ({ name: `Incomplete session ${id.slice(0, 8)}`, description: "Interrupted creation; cleanup required.", run: () => confirm("Discard incomplete session", `Remove the unfinished volume ${id.slice(0, 8)}?`, async () => { await command("discard-session-pending", undefined, id) }) })),
    ]
    if (category() === "API keys" && keyID()) {
      const entry = current.api_keys?.entries.find((entry) => entry.id === keyID())
      if (!entry) return []
      const readonly = current.general_readonly && !entry.temporary
      return [
        { name: "Set as default", description: `Use “${entry.name}” for future chats. You can choose another key each time you start a chat.`, disabled: unavailable(), run: () => void perform("Set default key", async () => { await command("api-keys", { action: "default", id: entry.id }) }) },
        ...(!readonly ? [
          { name: "Rename", description: "Change this key’s display name. Its secret stays unchanged.", disabled: unavailable(), run: () => editKey("rename", entry.id, entry.name) },
          { name: "Replace secret", description: `Enter a new ${providerName(entry.provider)} key under the same name.`, disabled: unavailable(), run: () => editKey("replace", entry.id, entry.name) },
          { name: "Remove key", description: "Remove this key from Oblivion. This does not revoke it at the provider.", disabled: unavailable(), run: () => confirm("Remove API key", `Remove “${entry.name}” from Oblivion?`, async () => { await command("api-keys", { action: "remove", id: entry.id }); setKeyID(undefined); setSelection(0) }) },
        ] : []),
      ]
    }
    if (category() === "API keys") return [
      ...(current.api_keys?.entries ?? []).map((entry) => ({ name: entry.name, description: `${providerName(entry.provider)} · ${entry.id === current.api_keys?.selected ? "Selected · " : ""}${entry.id === current.api_keys?.default ? "Default · " : ""}${entry.temporary ? "RAM only" : "Saved encrypted"}`, badge: `${providerName(entry.provider)}${entry.id === current.api_keys?.default ? " · Default" : ""}`, disabled: unavailable(), run: () => { setKeyID(entry.id); setSelection(0) } })),
    ]
    if (category() === "Keyboard & time zone") return [
      { name: "Edit preferences", description: "Choose a layout, variant and time zone from the installed Debian catalog.", disabled: current.session_open ? "Close the active session first; its keyboard and time zone are applied at VM startup." : undefined, run: () => void perform("Load settings", setup) },
      { name: "Test keyboard", description: "Type a harmless sample before using a password.", run: keyboardTest },
    ]
    return []
  })

  function choose(index: number) {
    if (blocked()) return
    const item = items()[index]
    if (!item) return
    if (item.disabled) { setFeedback("info"); setNotice(item.disabled); return }
    setNotice("")
    item.run()
  }

  useKeyboard((key) => {
    if (key.defaultPrevented) return
    if (networkWait() && key.name === "escape") { key.preventDefault(); networkWait()!.abort(); return }
    if (!editing() && state()?.session_open) {
      if (key.name === "f6" || key.name === "f7") { key.preventDefault(); key.stopPropagation(); sessionView(key.name === "f6" ? 0 : 1); return }
      if (key.ctrl && key.name === "q" || key.name === "f8" || key.raw === "\x1d" || key.ctrl && key.name === "]") {
        key.preventDefault(); key.stopPropagation(); closeSession(); return
      }
      if (key.raw === "\x1e" || key.ctrl && key.name === "^") { key.preventDefault(); key.stopPropagation(); sessionView(1); return }
      if (chatVisible() && focus() === "content") return
    }
    if (key.defaultPrevented || editing()) return
    if (state()?.session_open && key.name === "f8") { key.preventDefault(); closeSession(); return }
    if (documents() && focus() === "content") return
    if (key.ctrl && key.name === "q") { key.preventDefault(); lockOblivion(); return }
    if (state()?.general_mounted && !state()?.session_open && /^[1-5]$/.test(key.name)) { key.preventDefault(); navigate(Number(key.name) - 1); return }
    const shortcut = pageActions().find((action) => action.key.toLowerCase() === key.name && !key.ctrl && !key.meta)
    if (shortcut && !shortcut.disabled) { key.preventDefault(); shortcut.run(); return }
    if (networkVisible() && focus() === "content") return
    if (focus() === "navigation" && ["left", "right", "up", "down"].includes(key.name)) {
      key.preventDefault()
      const delta = key.name === "left" || key.name === "up" ? -1 : 1
      if (!state()?.general_mounted) { setAccessSection((value) => Math.max(0, Math.min(accessSections.length - 1 + Number(!!state()?.debug_available), value + delta))); return }
      if (state()?.session_open) { setSessionSection((value) => Math.max(0, Math.min(1, value + delta))); return }
      navigate(Math.max(0, Math.min(sections.length - 1 + Number(!!state()?.debug_available), page() + delta))); setFocus("navigation"); return
    }
    if (focus() === "navigation" && key.name === "return") { key.preventDefault(); if (!state()?.general_mounted) { accessSettings(accessSection()); return }; if (state()?.session_open) { sessionView(sessionSection()); return }; setFocus("content"); return }
    if (key.name === "tab") {
      key.preventDefault()
      const areas = pageActions().length ? ["navigation", "actions", "content"] as const : ["navigation", "content"] as const
      const index = areas.indexOf(focus() as "navigation" | "content")
      setFocus(areas[(index + (key.shift ? areas.length - 1 : 1)) % areas.length]); return
    }
    if (key.name === "escape") { key.preventDefault(); back(); return }
    if (key.name === "r" && !key.ctrl) { key.preventDefault(); void perform("Refresh", async () => {}); return }
  })

  onMount(() => {
    let timer: ReturnType<typeof setInterval> | undefined
    let reveal: ReturnType<typeof setInterval> | undefined
    if (!props.initial) {
      void props.runtime.request({ operation: "claim-intro" }).then((value) => {
        if (value.trim() !== "true") return
        const started = performance.now()
        setIntro(true)
        reveal = setInterval(() => {
          const value = performance.now() - started
          setElapsed(value)
          if (value >= 3000) { setIntro(false); clearInterval(reveal) }
        }, 50)
      }).catch(() => undefined)
      void perform("Load system status", async () => {
        await refresh()
        if (!state()?.general_present && !state()?.recovery_required) await setup()
      })
    }
    timer = setInterval(() => {
      setNow(performance.now())
      if (!busy()) void refresh().catch(() => undefined)
    }, 3000)
    onCleanup(() => { clearInterval(timer); clearInterval(reveal) })
  })
  const networkFresh = () => now() - observed() + (state()?.network_status?.age_ms ?? 0) <= 10000
  const networkLabel = () => networkFresh() ? state()?.network_status?.label ?? "STATUS UNKNOWN" : "STATUS UNKNOWN"

  return <Show when={!intro()} fallback={<BootLogo elapsed={elapsed()} />}>
    <Shell mounted={!!state()?.general_mounted} welcome={welcome()} activeSession={state()?.active_session}
      breadcrumb={chatVisible() ? `SESSION / ${state()?.active_session?.slice(0, 8)} / Chat` : documents() ? `SESSION / ${state()?.active_session?.slice(0, 8)} / Documents` : breadcrumb()}
      chat={chatVisible()} documents={documents()} onSection={(index) => state()?.general_mounted ? navigate(index) : accessSettings(index)}
      accessSetting={wizard() ? 0 : undefined} debugAvailable={state()?.debug_available} debugActive={debugVisible()}
      onChat={() => sessionView(0)} onDocuments={() => sessionView(1)}
      page={!state()?.general_mounted ? accessSection() : state()?.session_open ? sessionSection() : page()} navigation={focus() === "navigation" && !editing()} editing={editing()}
      host={now() - observed() <= 10000 ? state()?.network_status?.host_link ?? "STATUS UNKNOWN" : "STATUS UNKNOWN"}
      network={networkLabel()} blocked={!!state()?.network_status?.direct_blocked && networkFresh()}
      internet={now() - observed() <= 10000 ? state()?.connections?.internet ?? "unknown" : "unknown"} transport={state()?.egress?.selected.mode ?? "tor"}
      busy={busy()} cancellable={!!networkWait()} onClose={state()?.session_open ? closeSession : lockOblivion} notice={notice()} feedback={feedback()}>
        <Show when={chatVisible() && connection()} fallback={
        <Show when={documents()} fallback={<Show when={wizard()} fallback={<Show when={form()} fallback={
          <Show when={debugVisible()} fallback={<Show when={page() === 4 && state()?.general_mounted && !state()?.session_open} fallback={<Show when={networkVisible()} fallback={
          <Menu details={!(page() === 2 && !keyID())} toolbar={pageActions()} actionsFocused={focus() === "actions"} focusActions={() => setFocus("actions")} empty={page() === 2 ? "No API keys. Add your first key above." : "No sessions. Create a session above."} title={!state()?.general_mounted ? state()?.general_present ? "Welcome back" : "Welcome to Oblivion" : page() === 0 ? session() ? `Session ${state()?.session_titles[session()!] ?? session()!.slice(0, 8)}` : "Your protected sessions" : keyID() ? state()?.api_keys?.entries.find((entry) => entry.id === keyID())?.name ?? "API key" : page() === 2 ? "Saved API keys" : category()}
            description={!state()?.general_mounted ? state()?.general_present ? "Persistent: keep chats, documents and settings in encrypted storage.\nEphemeral: work in RAM; new data is lost when closed and persistent storage stays unchanged.\nBoth modes use your configured Tor or SOCKS5 route for online AI." : "Create the encrypted space that protects your sessions, documents, API keys and preferences." : page() === 0 ? session() ? `${state()?.general_readonly ? "Ephemeral · RAM only" : "Persistent · Separate encrypted volume"} · ${state()?.session_mode === "chat" ? "Chat running" : state()?.session_open ? "Documents open · Offline" : "Locked"}` : "Enter to unlock a session · N to create a new workspace" : category() === "API keys" ? "Select a key to manage it. Secrets stay hidden." : category() === "Network" ? "Choose your connection and the route used by your sessions." : category() === "Keyboard & time zone" ? `${state()?.settings?.current.keyboard ?? "us"} · ${state()?.settings?.current.timezone ?? "UTC"} · Interface: English` : `${capacity(state()?.available_bytes ?? 0)} free · ${state()?.general_readonly ? "Read-only storage" : "Encrypted storage"}`}
            items={items()} selected={selection()} disabled={blocked()} actions={!welcome()} back={state()?.general_mounted ? back : undefined} focused={focus() === "content" && !blocked()} focus={() => setFocus("content")} change={setSelection} choose={choose} />
          }><NetworkPage toolbar={pageActions()} tab={networkTab()} changeTab={(tab) => { setNetworkTab(tab); setSelection(0); setNotice("") }}
            description={networkDescription()} items={items()} selected={selection()} change={setSelection} choose={choose}
            focused={focus() === "content"} disabled={editing()} activate={() => setFocus("content")} sidebar={() => setFocus("navigation")} back={back} />
          </Show>}><SystemPage status={state()!} focused={!editing() && focus() === "content"} /></Show>}><DebugPage status={diagnostics()} actions={pageActions()} focused={!editing() && focus() !== "navigation"} activate={() => setFocus("actions")} /></Show>
        }>{(current) => <FormView form={current()} cancel={() => { setForm(undefined); if (state()?.session_open) { if (resumeChat() && connection()) void chat(); else setDocuments(true); setResumeChat(false) }; if (page() === 0 && session() && !state()?.session_open) { setSession(undefined); setSelection(0) } }} submit={(values) => {
          // perform unmounts the form. Capture its action before the Show accessor expires.
          const submitted = current()
          void perform(submitted.title, () => submitted.run(values))
        }} />}</Show>}>
          {(value) => <Setup catalog={value()} current={state()?.settings?.current ?? defaults()} writable={!!state()?.general_mounted && !state()?.general_readonly} applyKeyboard={async (keyboard, variant) => {
            await command("settings", { action: "apply", preferences: { ...(state()?.settings?.current ?? defaults()), keyboard, variant } }); await refresh()
          }} cancel={() => setWizard(undefined)} failed={(error) => { setFeedback("error"); setNotice(explain(error)) }} save={async (preferences, persist) => {
            await command("settings", { action: persist ? "save" : "apply", preferences })
            await refresh(); setWizard(undefined)
          }} />}
        </Show>}>
          <Show when={state()?.active_session} fallback={<text>Loading session...</text>}>{(id) => <Documents request={props.runtime.request} session={id()} chat={state()?.session_mode === "chat"}
            focused={focus() === "content"} activate={() => setFocus("content")} focusSidebar={undefined} onNavigationLock={setDocumentsLocked}
            back={() => { if (props.documentsOnly) { props.runtime.exit(); return }; sessionView(0) }} />}</Show>
        </Show>
        }>{(current) => <ChatViewport connection={current()} attach={(receive) => { drawChat = receive }} activate={() => setFocus("content")} focused={focus() === "content" && !busy()} />}</Show>
    </Shell>
  </Show>
}

function validatePassword(values: Record<string, string>) {
  if (Buffer.byteLength(values.password) < 16) throw new ControlError("password_too_short")
  if (values.password !== values.confirm) throw new ControlError("passwords_do_not_match")
}

function explain(error: unknown) {
  const messages: Record<string, string> = {
    debug_operation_failed: "Debug access could not be changed. Check that the host has a local network connection, then refresh.",
    debug_image_required: "Debug tools are available only in the debug image.",
    network_manager_unavailable: "NetworkManager is unavailable. Refresh status to retry.",
    wifi_unavailable: "No Wi-Fi adapter is available. Connect an adapter or use Ethernet.",
    network_device_unavailable: "This adapter is no longer available. Refresh the connection list.",
    wifi_network_unavailable: "This network is no longer available. Refresh Wi-Fi networks and retry.",
    wifi_security_unsupported: "This Wi-Fi security type is not supported yet.",
    invalid_wifi_password: "Check the Wi-Fi password. WPA2 requires 8–63 characters or a 64-digit hexadecimal key.",
    network_connection_failed: "Could not connect. Check the Wi-Fi password and signal, then retry.",
    network_profile_save_failed: "The connection changed, but encrypted saving failed. Check storage before restarting.",
    network_operation_failed: "The network operation failed. Refresh status and try again.",
    invalid_api_key: "This key has an invalid format. Use the complete provider key, without spaces.",
    invalid_password: "The password was not accepted. Check the keyboard layout and try again.",
    volume_unlock_failed: "The volume could not be unlocked. Check your password and keyboard layout, then retry.",
    password_too_short: "Use a password of at least 16 bytes.",
    passwords_do_not_match: "The two passwords do not match. Try again.",
    storage_confirmation_required: "Choose 'Use the available free space' to create encrypted storage, or press Esc to cancel.",
    usb_confirmation_required: "Choose 'Use the available free space' to create encrypted storage, or press Esc to cancel.",
    gateway_not_ready: "The network route is still connecting. Wait, then retry Start chat.",
    chat_start_cancelled: "Connection cancelled. Your session documents remain open offline.",
    gateway_connect_timeout: "The protected connection is taking too long. Check Network, then retry Start chat. Documents remain offline.",
    gateway_unavailable: "The gateway is unavailable. Retry Start chat; documents remain available.",
    gateway_start_failed: "The gateway could not start. Check the host connection and retry Start chat.",
    session_already_open: "Close the active session before opening another one.",
    session_must_be_closed: "Close the active session before changing this setting.",
    general_not_writable: "Persistent storage is read-only. Unlock Oblivion in persistent mode to save changes.",
    controller_unavailable: "The storage controller is unavailable. No operation was confirmed.",
    controller_timeout: "The controller has not confirmed completion. Refresh status before retrying.",
    insufficient_space: "There is not enough free space for another session.",
    invalid_timezone: "Unknown time zone. Use an IANA name such as Europe/Rome or UTC.",
    invalid_keyboard: "This keyboard layout is not supported by this image.",
    preview_only: "This is a UI preview. Open a Linux lab VM to test that operation.",
  }
  if (!(error instanceof ControlError)) return "Could not complete the operation. Refresh status before continuing."
  return messages[error.code] ?? `Operation not completed (${error.code}). Refresh status before retrying.`
}

function validateKey(value: string) {
  return /^[\x21-\x7e]{16,1024}$/.test(value) ? undefined : "Enter the complete API key (16-1024 characters, without spaces)."
}

function titleField(value = ""): Field {
  return { id: "title", label: "Session title", value, description: "A name for this session and its shared documents.", validate: (input) => {
    const title = input.trim()
    return !title || Array.from(title).length > 80 || Buffer.byteLength(title) > 256 || /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(title) ? "Use a title of 1–80 characters without control characters." : undefined
  } }
}
