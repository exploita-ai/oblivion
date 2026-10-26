import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { App } from "../src/app"
import { Picker } from "../src/picker"
import { FilePicker } from "../src/vendor/termcn/file-picker"
import { BootLogo, wordmark } from "../src/logo"
import { preview } from "../src/preview"
import { status } from "../src/state"
import { Documents } from "../src/documents"
import { Setup } from "../src/setup"
import { ControlError } from "../src/control"

test("pending gateway startup waits visibly and cancellation keeps Documents open", async () => {
  const fixture = preview(() => {})
  await fixture.request({ operation: "open-documents", session: "a".repeat(32) })
  const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
  const operations: string[] = []
  const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, request: async (request) => {
    operations.push(request.operation)
    if (request.operation === "start-chat") throw new ControlError("gateway_not_ready")
    return fixture.request(request)
  }, console: async () => { throw new Error("Chat must not attach before the gateway is ready") } }} />, { width: 160, height: 50, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("F6"); await app.renderOnce()
    await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations).toContain("start-chat")
    expect(app.captureCharFrame()).toContain("Connecting to Tor")
    expect(app.captureCharFrame()).toContain("Esc Cancel")
    expect(app.captureCharFrame()).not.toContain("! The network route")
    expect(app.captureCharFrame()).not.toContain("Working ·")
    expect(app.captureCharFrame()).not.toContain("Tor [ ]")
    await app.mockInput.pressEscape(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Connection cancelled")
    expect(app.captureCharFrame()).toContain("SESSION / aaaaaaaa / Documents")
    expect(app.captureCharFrame()).toContain("workspace/")
  } finally { await app.dispose() }
})

test("document pagination returns to the previous page without losing selections", async () => {
  const requests: (string | null)[] = []
  const app = await testRender(() => <Documents session={"a".repeat(32)} chat={false} back={() => {}} request={async (request) => {
    const input = JSON.parse(new TextDecoder().decode(request.payload)) as { after: string | null }
    requests.push(input.after)
    return JSON.stringify({ path: "", entries: [{ name: input.after ? "workspace" : "imports", directory: true, bytes: 0 }], next: input.after ? null : "imports", skipped: 0 })
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey(" ")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Previous page")
    expect(app.captureCharFrame()).toContain("1 selected")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(requests).toEqual([null, "imports", null])
    expect(app.captureCharFrame()).toContain("[x] / imports/")
    await app.mockInput.pressKey("TAB")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Focus: ACTIONS")
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test("setup supports variants, a keyboard test and temporary-only UTC before unlock", async () => {
  const applied: string[][] = []
  const app = await testRender(() => <Setup catalog={{ keyboards: [{ value: "it", label: "Italian", variants: [{ value: "", label: "Default" }, { value: "nodeadkeys", label: "No dead keys" }] }], timezones: ["UTC", "Europe/Rome"] }} current={{ version: 1, completed: false, keyboard: "it", variant: "", timezone: "UTC" }} writable={false} applyKeyboard={async (...values) => { applied.push(values) }} save={async () => {}} cancel={() => {}} failed={(error) => { throw error }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressEnter(); await app.renderOnce()
    await app.mockInput.typeText("No dead"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(applied).toEqual([["it", "nodeadkeys"]])
    expect(app.captureCharFrame()).toContain("Keyboard / Test")
    await app.mockInput.typeText("èòà @ - / :"); await app.mockInput.pressKey("TAB"); await app.mockInput.pressEnter(); await app.renderOnce()
    await app.mockInput.typeText("UTC"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Local time:")
    expect(app.captureCharFrame()).toContain("Apply temporarily")
    expect(app.captureCharFrame()).not.toContain("Save encrypted")
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test.each([[80, 24], [160, 50]])("documents occupy the %ix%i viewport with visible actions", async (width, height) => {
  const runtime = preview(() => {})
  await runtime.request({ operation: "open-documents", session: "a".repeat(32) })
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App runtime={runtime} initial={initial} documentsOnly />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    const frame = app.captureCharFrame()
    expect(frame).toContain("SESSION / aaaaaaaa / Documents")
    expect(frame).toContain("workspace/")
    expect(frame).toContain("Transfer history / recovery")
    expect(frame).toContain("Tor [ ]")
    expect(frame.split("\n").length).toBe(height + 1)
    await app.mockInput.pressKey("TAB")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Focus: ACTIONS")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Select one or more files or folders with Space.")
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test("search uses OpenTUI input editing and Enter chooses the filtered value", async () => {
  const choices: string[] = []
  const app = await testRender(() => <Picker title="Keyboard" description="Choose a layout" choices={[{ value: "us", label: "English (US)" }, { value: "it", label: "Italian" }]} choose={(value) => choices.push(value)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.typeText("Italix")
    await app.mockInput.pressKey("BACKSPACE")
    await app.mockInput.typeText("an")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Italian")
    expect(app.captureCharFrame()).not.toContain("English (US)")
    await app.mockInput.pressEnter()
    expect(choices).toEqual(["it"])
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test("termcn picker retains multiple selections while opening a directory", async () => {
  const [selected, setSelected] = createSignal<string[]>([])
  const navigated: string[] = []
  const app = await testRender(() => <FilePicker currentDir="workspace" entries={[{ name: "a.txt", path: "workspace/a.txt", directory: false, bytes: 12 }, { name: "folder", path: "workspace/folder", directory: true, bytes: 0 }]} selected={selected()} focused onChange={setSelected} onNavigate={(value) => navigated.push(value)} onNext={() => {}} onBack={() => {}} />, { width: 80, height: 20, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await app.renderOnce()
    expect(selected()).toEqual(["workspace/a.txt", "workspace/folder"])
    expect(app.captureCharFrame()).toContain("2 selected")
    await app.mockInput.pressEnter()
    expect(navigated).toEqual(["workspace/folder"])
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test.each([[80, 24], [160, 50], [40, 16]])("wordmark fits at %ix%i and responds to resize", async (width, height) => {
  expect(wordmark(width - 4).split("\n").every((line) => Array.from(line).length <= width - 4)).toBe(true)
  const app = await testRender(() => <BootLogo elapsed={3000} />, { width, height })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("PRIVATE WORKSPACE")
    app.resize(40, 16); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("OBLIVION")
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test("expired positive network observations are never displayed as ready", async () => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  initial.network_status = { label: "TOR READY", host_link: "CONNECTED", direct_blocked: true, age_ms: 10001 }
  const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Tor [?]")
    expect(app.captureCharFrame()).not.toContain("TOR READY")
    expect(app.captureCharFrame()).not.toContain("Direct connections: BLOCKED")
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test("cancelling a pending import cleans up once and returns to session roots", async () => {
  const pending = Promise.withResolvers<never>()
  const cleanup = Promise.withResolvers<string>()
  const started = Promise.withResolvers<void>()
  let cancellations = 0
  const app = await testRender(() => <Documents session={"a".repeat(32)} chat={false} back={() => {}} request={async (request) => {
    if (request.operation === "browse") return JSON.stringify({ path: "", entries: [{ name: "workspace", directory: true, bytes: 0 }], next: null, skipped: 0 })
    const input = JSON.parse(new TextDecoder().decode(request.payload)) as { operation: string }
    if (input.operation === "list") return JSON.stringify({ configured: true, export_configured: true, active: false, sources: [{ id: "8:16", name: "sdb", bytes: 33554432 }] })
    if (input.operation === "import") return JSON.stringify({ id: "b".repeat(32) })
    if (input.operation === "cancel") { cancellations++; return cleanup.promise }
    throw new Error("Unexpected transfer operation")
  }} connect={async () => ({
    browse: async () => { started.resolve(); return pending.promise },
    offer: async () => { throw new Error("No selection yet") },
    approve: async () => { throw new Error("No confirmation yet") },
    recover: async () => { throw new Error("Not recovering") },
    close: () => pending.reject(new Error("cancelled")),
  })} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("TAB"); await app.mockInput.pressEnter(); await app.renderOnce()
    await app.mockInput.pressEnter(); await started.promise; await app.renderOnce()
    await app.mockInput.pressEscape(); cleanup.resolve(""); await cleanup.promise; await app.renderOnce()
    expect(cancellations).toBe(1)
    expect(app.captureCharFrame()).toContain("Transfer cancelled.")
    expect(app.captureCharFrame()).toContain("Roots: workspace / imports")
    expect(app.captureCharFrame()).toContain("workspace/")
    expect(app.captureCharFrame()).not.toContain("Source: sdb")
  } finally { app.renderer.destroy(); await app.renderer.closed }
})

test.each([
  ["TOR READY", true, "CONNECTED", 0, "Tor [+]", "SOCKS5 [ ]"],
  ["SOCKS5 READY", true, "CONNECTED", 0, "Tor [ ]", "SOCKS5 [+]"],
  ["TOR READY", false, "CONNECTED", 0, "Tor [?]", "SOCKS5 [ ]"],
  ["SOCKS5 READY", false, "CONNECTED", 0, "Tor [ ]", "SOCKS5 [?]"],
  ["TOR READY", true, "OFFLINE", 0, "Tor [?]", "SOCKS5 [ ]"],
  ["TOR READY", true, "STATUS UNKNOWN", 0, "Tor [?]", "SOCKS5 [ ]"],
  ["TOR READY", true, "CONNECTED", 10001, "Tor [?]", "SOCKS5 [?]"],
  ["CONNECTING", true, "CONNECTED", 0, "Tor [.]", "SOCKS5 [ ]"],
  ["OFFLINE · NO NETWORK DEVICE", true, "CONNECTED", 0, "Tor [ ]", "SOCKS5 [ ]"],
  ["NOT STARTED", false, "CONNECTED", 0, "Tor [ ]", "SOCKS5 [ ]"],
] as const)("footer indicators require current verified observations: %s / %s / %s / %i", async (label, direct_blocked, host_link, age_ms, tor, socks) => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  initial.network_status = { label, direct_blocked, host_link, age_ms }
  const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    for (const [width, height] of [[80, 24], [160, 50]]) {
      app.resize(width, height); await app.renderOnce()
      const footer = app.captureCharFrame().split("\n").slice(-4).join("\n")
      expect(footer).toContain("Internet [?]")
      expect(footer).toContain(tor)
      expect(footer).toContain(socks)
      expect(footer).not.toMatch(/SESSION NETWORK|Direct connections|All sessions|NOT STARTED|F6 Menu/)
    }
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("all former settings are directly reachable from navigation at %ix%i", async (width, height) => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Settings")
    expect(app.captureCharFrame()).not.toContain("PRIVATE WORKSPACE")
    for (const [key, section, action] of [["2", "Network", "Connection"], ["3", "API keys", "Add API key"], ["4", "Keyboard & time zone", "Edit preferences"], ["5", "System", "CPU cores"]]) {
      await app.mockInput.pressKey(key)
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain(`HOST / ${section}`)
      expect(app.captureCharFrame()).toContain(action)
    }
    await app.mockInput.pressKey("TAB")
    await app.mockInput.pressArrow("up")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("HOST / Keyboard & time zone")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Keyboard / Layout")
  } finally { await app.dispose() }
})
