import { expect, test } from "bun:test"
import { ManualClock } from "@opentui/core/testing"
import { testRender } from "@opentui/solid"
import { chooseLiveStorage, nativePreview } from "../src/native-control"
import { SafeManager } from "../src/safe-manager"

test("Live storage switching waits for file shutdown, stops once and exits without a second lock", async () => {
  const closed = Promise.withResolvers<void>()
  const calls: string[] = []
  const switching = chooseLiveStorage({ close: async () => { calls.push("files close"); await closed.promise } },
    async (args) => { calls.push(args.join(" ")); return 0 }, () => { calls.push("exit") }, () => { calls.push("restore files") })
  expect(calls).toEqual(["files close"])
  closed.resolve()
  await switching
  expect(calls).toEqual(["files close", "runtime stop", "runtime choose-storage", "exit"])
})

test.each(["stop", "choose-storage"])("failed runtime %s preserves the manager's Files adapter and never exits", async (failure) => {
  const calls: string[] = []
  await expect(chooseLiveStorage({ close: async () => { calls.push("files close") } },
    async (args) => { calls.push(args.join(" ")); return args[1] === failure ? 1 : 0 },
    () => { calls.push("exit") }, () => { calls.push("restore files") })).rejects.toThrow()
  expect(calls).toEqual(["files close", "runtime stop", ...(failure === "choose-storage" ? ["runtime choose-storage"] : []), "restore files"])
})

test("unconfirmed file shutdown cannot start the storage switch or create a second file client", async () => {
  const calls: string[] = []
  await expect(chooseLiveStorage({ close: async () => { throw new Error("synthetic close failure") } },
    async (args) => { calls.push(args.join(" ")); return 0 }, () => { calls.push("exit") },
    () => { calls.push("restore files") })).rejects.toThrow("synthetic close failure")
  expect(calls).toHaveLength(0)
})

test.each([[80, 24], [160, 50]])("locked Live storage offers the native action at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {})
  const initial = await fixture.status()
  const calls: string[] = []
  const clock = new ManualClock()
  const app = await testRender(() => <SafeManager initial={initial} liveStorage="persistent" runtime={{ ...fixture,
    chooseLiveStorage: () => chooseLiveStorage({ close: async () => { calls.push("files close") } },
      async (args) => { calls.push(args.join(" ")); return 0 }, () => { calls.push("exit") }, () => {}),
    status: async () => { calls.push("status"); return fixture.status() },
  }} />, { width, height, clock, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Change storage mode")
    expect(app.captureCharFrame()).not.toContain("oblivion runtime choose-storage")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(calls).toEqual(["files close", "runtime stop", "runtime choose-storage", "exit"])
    clock.advance(10_000)
    await app.renderOnce()
    expect(calls).toEqual(["files close", "runtime stop", "runtime choose-storage", "exit"])
  } finally { await app.dispose() }
})

test.each(["desktop", "overlay", "no-capability", "open", "recovery", "general-open", "active-safe", "host-closing", "safe-closing"])("storage switching is unavailable for %s", async (reason) => {
  const fixture = nativePreview(() => {}, {
    ...(reason === "recovery" ? { recovery_required: true } : {}),
    ...(reason === "general-open" ? { general_open: true } : {}),
    ...(reason === "active-safe" ? { open_sessions: [{ slot: 0, id: "a".repeat(32), mode: "documents", recovery_required: false }] } : {}),
  })
  if (reason === "open") await fixture.run(["unlock"])
  const initial = await fixture.status()
  if (reason === "host-closing") initial.idle_lock.host = { nonce: "b".repeat(32), remaining_seconds: 0, closing: true }
  if (reason === "safe-closing") initial.idle_lock.safes = [{ opening: { slot: 0, safe_id: "a".repeat(32), nonce: "c".repeat(32) }, remaining_seconds: 0, closing: true }]
  const app = await testRender(() => <SafeManager initial={initial} liveStorage={reason === "desktop" ? undefined : "persistent"}
    overlay={reason === "overlay" ? { page: "files", safe: initial.sessions[0]! } : undefined}
    runtime={{ ...fixture, ...(reason === "no-capability" ? {} : { chooseLiveStorage: async () => { throw new Error("unavailable action invoked") } }) }} />,
  { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Change storage mode")
  } finally { await app.dispose() }
})

test("a failed Live switch suspends automatic status until an explicit R", async () => {
  const fixture = nativePreview(() => {})
  const initial = await fixture.status()
  const pending = Promise.withResolvers<void>()
  const calls: string[] = []
  const clock = new ManualClock()
  const app = await testRender(() => <SafeManager initial={initial} liveStorage="persistent" runtime={{ ...fixture,
    chooseLiveStorage: async () => { calls.push("switch"); await pending.promise },
    status: async () => { calls.push("status"); return fixture.status() },
  }} />, { width: 80, height: 24, clock, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    expect(calls).toEqual(["switch"])
    pending.reject(new Error("synthetic switch failure"))
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Live storage selection could not be prepared")
    clock.advance(15_000)
    await app.renderOnce()
    expect(calls).toEqual(["switch"])
    await app.mockInput.pressKey("r")
    await app.renderOnce()
    expect(calls).toEqual(["switch", "status"])
    expect(app.captureCharFrame()).toContain("Change storage mode")
  } finally { await app.dispose() }
})
