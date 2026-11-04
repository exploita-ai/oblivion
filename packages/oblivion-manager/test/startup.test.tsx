import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { ManualClock } from "@opentui/core/testing"
import { BootLogo, wordmark } from "../src/boot-logo"
import { Startup } from "../src/startup"
import { nativePreview } from "../src/native-control"

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
