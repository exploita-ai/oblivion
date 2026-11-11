import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { nativePreview, type NativeRuntime } from "../src/native-control"

test.each([[80, 24], [160, 50]])("automatic-lock settings apply encrypted policy without a persistence menu at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const commands: string[][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("F2")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Automatic lock")
    expect(app.captureCharFrame()).toContain("encrypted storage")
    expect(app.captureCharFrame()).not.toContain("Save encrypted")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["settings", "idle", "--safe-minutes", "30", "--host-minutes", "60"]])
    expect(app.captureCharFrame()).toContain("Saved encrypted")
    await app.mockInput.pressEscape()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Automatic lock")
  } finally { await app.dispose() }
})

test("ephemeral idle policy permits explicit disable and stays in RAM", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["ephemeral"])
  const commands: string[][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("F2")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Changes apply in RAM")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressEnter()
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["settings", "idle", "--safe-minutes", "0", "--host-minutes", "0"]])
    expect(app.captureCharFrame()).toContain("RAM only")
  } finally { await app.dispose() }
})

test("manager reports only human activity and the selected opening identity", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const id = (await fixture.status()).sessions[0]!
  await fixture.run(["safe", "open", id])
  const events: Parameters<NativeRuntime["activity"]>[0][] = []
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, activity: async (input) => { events.push(input) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    app.resize(160, 50)
    await app.renderOnce()
    expect(events).toHaveLength(0)
    await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(events).toEqual([{ host: initial.idle_lock.host!.nonce, safe: initial.idle_lock.safes[0]!.opening }])
    await app.mockInput.pasteBracketedText("private text must never enter an activity report")
    await app.renderOnce()
    expect(events).toHaveLength(1)
    expect(JSON.stringify(events)).not.toContain("private text")
  } finally { await app.dispose() }
})

test("closing work remains visibly pending and cannot receive activity or new admissions", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const id = (await fixture.status()).sessions[0]!
  await fixture.run(["safe", "open", id])
  const initial = await fixture.status()
  initial.idle_lock.host!.closing = true
  const commands: string[][] = []
  const events: unknown[] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return 0 }, activity: async (event) => { events.push(event) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Closing")
    expect(app.captureCharFrame()).toContain("Waiting for verified teardown")
    await app.mockInput.pressKey("n")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toHaveLength(0)
    expect(events).toHaveLength(0)
    expect(initial.general_open).toBe(true)
  } finally { await app.dispose() }
})
