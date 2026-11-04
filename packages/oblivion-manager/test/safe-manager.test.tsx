import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { nativePreview } from "../src/native-control"

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
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["run", "--safe", "0123456789abcdef0123456789abcdef", "claude"]])
    expect(app.captureCharFrame()).toContain("Your Safes")
  } finally { await app.dispose() }
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
