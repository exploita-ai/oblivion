import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { ManualClock } from "@opentui/core/testing"
import { BootLogo, wordmark } from "../src/boot-logo"
import { Startup } from "../src/startup"
import { nativePreview, nativeStatus, statusReader, type NativeStatus } from "../src/native-control"

test("controller status requires the backing recovery observation", async () => {
  const state = await nativePreview(() => {}).status()
  expect(nativeStatus.safeParse(state).success).toBe(true)
  expect(nativeStatus.safeParse({ ...state, backing_recovery_required: undefined }).success).toBe(false)
})

for (const [width, height] of [[80, 24], [160, 50]]) {
  test(`the boot wordmark occupies exactly three seconds while status initializes at ${width}x${height}`, async () => {
    const fixture = nativePreview(() => {})
    await fixture.run(["unlock"])
    const clock = new ManualClock()
    const app = await testRender(() => <Startup runtime={fixture} initial={fixture.status().then((state) => ({ state, received: performance.now() }))} />, { width, height, clock })
    try {
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain("A privacy layer for your coding agents")
      expect(app.captureCharFrame()).not.toContain("Your Safes")
      clock.advance(2999)
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain("A privacy layer for your coding agents")
      clock.advance(1)
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain("Your Safes")
      expect(app.captureCharFrame()).toContain("Research")
      expect(app.captureCharFrame()).not.toContain("A privacy layer for your coding agents")
    } finally { await app.dispose() }
  })
}

test("compact terminals keep the complete wordmark visible without a cropped glyph", async () => {
  const app = await testRender(() => <BootLogo elapsed={3000} />, { width: 30, height: 8 })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("OBLIVION")
    expect(wordmark(76).split("\n").every((line) => line.length <= 76)).toBe(true)
    expect(wordmark(156).split("\n").every((line) => line.length <= 156)).toBe(true)
  } finally { await app.dispose() }
})

test("a slow Live boot keeps one initializer while the three-second logo gives way to its loading modal", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const pending = Promise.withResolvers<NativeStatus>()
  const calls: boolean[] = []
  const status = statusReader((initial) => { calls.push(initial); return initial ? pending.promise : fixture.status() })
  const runtime = { ...fixture, status }
  const initial = runtime.status().then((state) => ({ state, received: performance.now() }))
  const clock = new ManualClock()
  const app = await testRender(() => <Startup runtime={runtime} initial={initial} liveStorage="persistent" />, { width: 80, height: 24, clock, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("A privacy layer for your coding agents")
    clock.advance(3000)
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("A privacy layer for your coding agents")
    expect(app.captureCharFrame()).toContain("Opening Oblivion")
    clock.advance(10_000)
    await app.renderOnce()
    expect(calls).toEqual([true])
    pending.resolve(await fixture.status())
    await initial
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Your Safes")
    expect(app.captureCharFrame()).not.toContain("Opening Oblivion")
    clock.advance(5000)
    await app.renderOnce()
    expect(calls).toEqual([true, false])
  } finally { await app.dispose() }
})

test("a failed initial boot stays visible and waits for an explicit retry", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const pending = Promise.withResolvers<NativeStatus>()
  const calls: boolean[] = []
  const status = statusReader((initial) => { calls.push(initial); return calls.length === 1 ? pending.promise : fixture.status() })
  const runtime = { ...fixture, status }
  const initial = runtime.status().then((state) => ({ state, received: performance.now() }))
  const clock = new ManualClock()
  const app = await testRender(() => <Startup runtime={runtime} initial={initial} />, { width: 80, height: 24, clock, kittyKeyboard: true })
  try {
    pending.reject(new Error("synthetic boot failure"))
    await initial.catch(() => {})
    clock.advance(3000)
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Press R to retry")
    expect(app.captureCharFrame()).not.toContain("Opening Oblivion")
    clock.advance(15_000)
    await app.renderOnce()
    expect(calls).toEqual([true])
    await app.mockInput.pressKey("r")
    await app.renderOnce()
    expect(calls).toEqual([true, true])
    expect(app.captureCharFrame()).toContain("Your Safes")
    expect(app.captureCharFrame()).not.toContain("Press R to retry")
  } finally { await app.dispose() }
})

test("status reads coalesce only while pending and use the boot budget until the first success", async () => {
  const fixture = nativePreview(() => {})
  const first = Promise.withResolvers<NativeStatus>()
  const calls: boolean[] = []
  const status = statusReader((initial) => { calls.push(initial); return calls.length === 1 ? first.promise : fixture.status() })
  const left = status()
  const right = status()
  expect(left).toBe(right)
  first.reject(new Error("synthetic unavailable runtime"))
  await expect(left).rejects.toThrow("synthetic unavailable runtime")
  await status()
  await status()
  expect(calls).toEqual([true, true, false])
})
