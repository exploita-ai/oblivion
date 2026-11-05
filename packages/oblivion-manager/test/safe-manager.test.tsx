import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { nativePreview } from "../src/native-control"

test.each([[80, 24], [160, 50]])("existing Safe agents distinguish New conversation and native Continue latest at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width, height, kittyKeyboard: true })
  try {
    for (const [index, agent, args] of [[0, "codex", ["resume", "--last"]], [1, "claude", ["--continue"]], [2, "opencode2", ["--continue"]]] as const) {
      await app.renderOnce()
      await app.mockInput.pressEnter()
      for (let row = 0; row < index; row++) await app.mockInput.pressArrow("down")
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain("New conversation")
      expect(app.captureCharFrame()).toContain("Continue latest")
      await app.mockInput.pressEscape()
      await app.renderOnce()
      expect(commands).toHaveLength(index)
      await app.mockInput.pressEnter()
      for (let row = 0; row < index; row++) await app.mockInput.pressArrow("down")
      await app.mockInput.pressKey("c")
      await app.renderOnce()
      expect(commands.at(-1)).toEqual(["run", "--safe", initial.sessions[0], agent, ...args])
    }
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("native manager opens the chosen agent in the selected Safe at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const commands: string[][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => {
    commands.push(args)
    return fixture.run(args)
  } }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Your Safes")
    expect(app.captureCharFrame()).toContain("Research")
    expect(app.captureCharFrame()).not.toContain("Keyboard")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Choose an agent")
    expect(app.captureCharFrame()).toContain("Sign in with Device Code")
    expect(app.captureCharFrame()).toContain("browser callback")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["run", "--safe", "0123456789abcdef0123456789abcdef", "claude"]])
    expect(app.captureCharFrame()).toContain("Your Safes")
  } finally { await app.dispose() }
})

test("agent startup stays in a progress modal and reports the protected connection failure", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const launch = Promise.withResolvers<void>()
  const refreshed = Promise.withResolvers<void>()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, status: async () => {
    refreshed.resolve()
    return fixture.status()
  }, run: async (_args, report) => {
    report?.("connecting")
    await launch.promise
    report?.("gateway-timeout")
    return 1
  } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Waiting for the protected connection…")
    launch.resolve()
    await refreshed.promise
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Waiting for the protected connection…")
    expect(app.captureCharFrame()).toContain("The protected connection timed out. The Safe stayed offline.")
  } finally { launch.resolve(); await app.dispose() }
})

test("welcome describes both modes and enters ephemeral mode through the CLI", async () => {
  const fixture = nativePreview(() => {})
  const commands: string[][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => {
    commands.push(args)
    return fixture.run(args)
  } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Unlock Oblivion")
    expect(app.captureCharFrame()).toContain("encrypted storage")
    await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Work in RAM")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["ephemeral"]])
    expect(app.captureCharFrame()).toContain("Your Safes")
    await app.mockInput.pressKey("n")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands.at(-1)).toEqual(["run", "--ephemeral", "codex"])
  } finally { await app.dispose() }
})

test("new named Safe and confirmed global lock stay distinct from agent arguments", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const commands: string[][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => {
    commands.push(args)
    return fixture.run(args)
  } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("n")
    await app.renderOnce()
    await app.mockInput.typeText("Research notes")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Choose an agent")
    expect(app.captureCharFrame()).toContain("Sign in with Device Code")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["run", "--name", "Research notes", "opencode2"]])
    await app.mockInput.pressKey("q", { ctrl: true })
    await app.renderOnce()
    expect(commands).toHaveLength(1)
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands.at(-1)).toEqual(["lock"])
    expect(app.captureCharFrame()).toContain("Unlock Oblivion")
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("Workspace opens a shell separately from the three-agent picker at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const commands: string[][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => {
    commands.push(args)
    return fixture.run(args)
  } }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Workspace")
    await app.mockInput.pressKey("w")
    await app.renderOnce()
    expect(commands).toEqual([["shell", "--safe", initial.sessions[0]]])
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Choose an agent")
    expect(app.captureCharFrame()).toContain("Codex")
    expect(app.captureCharFrame()).toContain("Claude")
    expect(app.captureCharFrame()).toContain("OpenCode 2")
    expect(app.captureCharFrame()).not.toContain("Workspace")
  } finally { await app.dispose() }
})
