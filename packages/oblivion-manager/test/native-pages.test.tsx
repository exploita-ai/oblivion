import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { NativeNetwork, NativeNetworkIndicator } from "../src/native-network"
import { NativeFiles } from "../src/native-files"
import { nativePreview } from "../src/native-control"

test("network settings require an explicit offline open and target the selected Safe", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const commands: string[][] = []
  const queries: string[][] = []
  const runtime = { ...fixture, run: async (args: string[]) => { commands.push(args); return fixture.run(args) }, query: async (args: string[]) => { queries.push(args); return fixture.query(args) } }
  const app = await testRender(() => <SafeManager initial={initial} runtime={runtime} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("\x1bOQ")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Open Safe offline")
    expect(queries).toHaveLength(0)
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["safe", "open", initial.sessions[0]]])
    expect(queries[0]).toEqual(["network", "status", "--safe", initial.sessions[0], "--json"])
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands.at(-1)).toEqual(["network", "set", "--safe", initial.sessions[0], "--policy", "strict"])
  } finally { await app.dispose() }
})

test.each([false, true])("network footer expires positive route observations (stale=%s)", async (stale) => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  await fixture.run(["safe", "open", (await fixture.status()).sessions[0]])
  const opened = await fixture.status()
  const state = { ...opened, open_sessions: opened.open_sessions.map((entry) => ({ ...entry, mode: "agent" })), network_status: { label: "TOR READY" as const, direct_blocked: true, host_link: "CONNECTED" as const, age_ms: 0 } }
  const app = await testRender(() => <NativeNetworkIndicator safe={state.sessions[0]} host={state} hostReceived={performance.now() - (stale ? 11000 : 0)} observation={{ safe: state.sessions[0], state, received: performance.now() - (stale ? 11000 : 0) }} />, { width: 80, height: 24 })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain(stale ? "Tor [ ]" : "Tor [+]")
    expect(app.captureCharFrame()).toContain(stale ? "Network [?]" : "Network [+]")
    expect(app.captureCharFrame()).toContain("SOCKS5 [ ]")
  } finally { await app.dispose() }
})

test("System uses controller-reported hardware", async () => {
  const fixture = nativePreview(() => {})
  const initial = { ...await fixture.status(), system: { os: "Debian", architecture: "aarch64", cpu: "Guest CPU", cores: 4, memory_total: 6 * 1024 ** 3, memory_available: 4 * 1024 ** 3 } }
  const app = await testRender(() => <SafeManager initial={initial} runtime={fixture} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("\x1bOR")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Guest CPU")
    expect(app.captureCharFrame()).toContain("4096 MiB available / 6144 MiB")
  } finally { await app.dispose() }
})

test("SOCKS5 configuration leaves password entry to the native terminal", async () => {
  const fixture = nativePreview(() => {})
  const commands: string[][] = []
  const app = await testRender(() => <NativeNetwork safe="0123456789abcdef0123456789abcdef" name="Research" open runtime={fixture} run={async (args) => { commands.push(args); return true }} observed={() => {}} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("t")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    await app.mockInput.typeText("192.0.2.10:1080")
    await app.mockInput.pressEnter()
    await app.mockInput.typeText("alice space")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["network", "set", "--safe", "0123456789abcdef0123456789abcdef", "-x", "socks5h://alice%20space@192.0.2.10:1080"]])
  } finally { await app.dispose() }
})

test("file export reviews the Safe source and explicit local destination before copying", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const commands: string[][] = []
  const app = await testRender(() => <NativeFiles safe="0123456789abcdef0123456789abcdef" name="Research" runtime={fixture} run={async (args) => { commands.push(args); return await fixture.run(args) === 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  async function visible(value: string) {
    const deadline = performance.now() + 2000
    while (performance.now() < deadline) {
      await app.renderOnce()
      if (app.captureCharFrame().includes(value)) return
      await Bun.sleep(5)
    }
    throw new Error(`Missing ${value}\n${app.captureCharFrame()}`)
  }
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible("workspace/")
    await app.mockInput.pressEnter()
    await visible("project/")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await visible("Choose destination directory")
    await app.mockInput.pressKey(".")
    await visible("Confirm export")
    expect(commands).toHaveLength(1)
    expect(app.captureCharFrame()).toContain("workspace/project")
    await app.mockInput.pressEnter()
    await visible("Copy completed and verified.")
    expect(commands.at(-1)?.slice(0, 6)).toEqual(["files", "export", "--safe", "0123456789abcdef0123456789abcdef", "workspace/project", process.cwd()])
    expect(commands.at(-1)?.slice(6)).toEqual(["--operation", expect.stringMatching(/^[a-f0-9]{32}$/), "--opening", "d".repeat(32)])
  } finally { await app.dispose() }
})
