import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { nativeOverlay, nativePreview } from "../src/native-control"

test("overlay startup accepts only a known page and one full Safe ID", () => {
  expect(nativeOverlay([])).toBeUndefined()
  expect(nativeOverlay(["--native-overlay", "files", "--safe", "0123456789abcdef0123456789abcdef"])).toEqual({ page: "files", safe: "0123456789abcdef0123456789abcdef" })
  expect(() => nativeOverlay(["--native-overlay", "safes", "--safe", "0123456789abcdef0123456789abcdef"])).toThrow("Usage:")
  expect(() => nativeOverlay(["--native-overlay", "network", "--safe", "short"])).toThrow("Usage:")
  expect(() => nativeOverlay(["--native-overlay", "network", "--safe", "0123456789abcdef0123456789abcdef", "extra"])).toThrow("Usage:")
})

test.each([[80, 24], [160, 50]])("Files overlay stays scoped and returns without locking at %ix%i", async (width, height) => {
  let exits = 0
  const fixture = nativePreview(() => { exits++ })
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const id = initial.sessions[1]!
  await fixture.run(["safe", "open", id])
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={{ ...initial, open_sessions: [{ slot: 1, id, mode: "agent", recovery_required: false }] }} overlay={{ page: "files", safe: id }} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Development / Files")
    expect(app.captureCharFrame()).toContain("Back to agent")
    expect(app.captureCharFrame()).not.toContain("Lock Oblivion")
    expect(app.captureCharFrame()).not.toContain("Your Safes")
    await app.mockInput.pressKey("\x1bOP")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Development / Files")
    await app.mockInput.pressEscape()
    expect(exits).toBe(1)
    expect(commands).toEqual([])
    expect((await fixture.status()).open_sessions[0]?.id).toBe(id)
  } finally { await app.dispose() }
})

test("Files export only requests an interactive open for a closed Safe in the manager", async () => {
  for (const open of [true, false]) {
    const fixture = nativePreview(() => {})
    await fixture.run(["unlock"])
    const id = (await fixture.status()).sessions[0]!
    if (open) await fixture.run(["safe", "open", id])
    const initial = await fixture.status()
    const commands: string[][] = []
    const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture,
      run: async (args) => { commands.push(args); return fixture.run(args) },
    }} />, { width: 80, height: 24, kittyKeyboard: true })
    try {
      await app.renderOnce()
      await app.mockInput.pressKey("\x1b[18~")
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain("Files are shared")
      await app.mockInput.pressArrow("down")
      await app.mockInput.pressEnter()
      await app.renderOnce()
      expect(commands).toEqual([["safe", "open", id, ...(open ? ["--already-open"] : [])]])
      expect(app.captureCharFrame()).toContain("Choose Safe files")
    } finally { await app.dispose() }
  }
})

test("Network overlay changes only its Safe and F7 returns to the agent", async () => {
  let exits = 0
  const fixture = nativePreview(() => { exits++ })
  await fixture.run(["unlock"])
  const id = (await fixture.status()).sessions[1]!
  await fixture.run(["safe", "open", id])
  const commands: string[][] = []
  const queries: string[][] = []
  const app = await testRender(() => <SafeManager initial={undefined} overlay={{ page: "network", safe: id }} runtime={{ ...fixture,
    run: async (args) => { commands.push(args); return fixture.run(args) },
    query: async (args) => { queries.push(args); return fixture.query(args) },
  }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Development / Network")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["network", "set", "--safe", id, "--policy", "strict"]])
    expect(queries.every((args) => args[3] === id)).toBe(true)
    await app.mockInput.pressKey("\x1b[18~")
    expect(exits).toBe(1)
    expect((await fixture.status()).open_sessions[0]?.id).toBe(id)
  } finally { await app.dispose() }
})

test("an overlay never reopens a Safe that was closed", async () => {
  let exits = 0
  const fixture = nativePreview(() => { exits++ })
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} overlay={{ page: "network", safe: initial.sessions[0]! }} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("This Safe is no longer open")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEscape()
    expect(exits).toBe(1)
    expect(commands).toEqual([])
  } finally { await app.dispose() }
})
