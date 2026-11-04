import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { nativePreview, type StoragePlan } from "../src/native-control"

const plan: StoragePlan = { device: "vda", identity: "252:0", table: "reviewed-table", disk_bytes: 8 * 1024 ** 3, start: 4 * 1024 ** 2, sectors: 12 * 1024 ** 2, partition: 5 }

test.each([[80, 24], [160, 50]])("Live setup reviews the exact device before invoking init at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {}, { general_present: false, persistence: { plan: structuredClone(plan), present: false, incomplete: false, unavailable: null } })
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("/dev/vda")
    expect(app.captureCharFrame()).toContain("8.0 GiB total")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEscape()
    await app.renderOnce()
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await app.renderOnce()
    initial.persistence!.plan!.identity = "252:16"
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["init", "--confirmed-plan", JSON.stringify(plan)]])
    expect(app.captureCharFrame()).toContain("Unlock Oblivion")
    expect(app.captureCharFrame()).toContain("Ephemeral mode")
    expect((await fixture.status()).app_open).toBe(false)
  } finally { await app.dispose() }
})

test("unsupported read-only Live media cannot start storage preparation", async () => {
  const fixture = nativePreview(() => {}, { general_present: false, persistence: { plan: null, present: false, incomplete: false, unavailable: "usb_medium_readonly" } })
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("read-only ISO")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("unfinished app storage has a dedicated reset confirmation and never auto-creates", async () => {
  const fixture = nativePreview(() => {}, { general_present: false, general_incomplete: true, persistence: { plan, present: false, incomplete: true, unavailable: null } })
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Reset incomplete storage")
    expect(app.captureCharFrame()).toContain("Published encrypted storage")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["init", "--reset-incomplete", "--confirmed-plan", JSON.stringify(plan)]])
    expect((await fixture.status()).general_present).toBe(false)
    expect((await fixture.status()).app_open).toBe(false)
  } finally { await app.dispose() }
})

test("published storage is offered for unlock even when an unfinished file is reported", async () => {
  const fixture = nativePreview(() => {}, { general_present: true, general_incomplete: true })
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Unlock Oblivion")
    expect(app.captureCharFrame()).not.toContain("Reset incomplete")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["unlock"]])
  } finally { await app.dispose() }
})

test("first boot can explicitly enter RAM-only mode without opening or creating General", async () => {
  const fixture = nativePreview(() => {}, { general_present: false })
  const initial = await fixture.status()
  const commands: string[][] = []
  const app = await testRender(() => <SafeManager initial={initial} runtime={{ ...fixture, run: async (args) => { commands.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(commands).toEqual([["ephemeral"]])
    expect(app.captureCharFrame()).toContain("Your Safes")
    const state = await fixture.status()
    expect(state.app_open).toBe(true)
    expect(state.app_mode).toBe("ram-only")
    expect(state.general_present).toBe(false)
    expect(state.general_open).toBe(false)
    expect(state.general_readonly).toBe(false)
  } finally { await app.dispose() }
})
