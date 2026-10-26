import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { status } from "../src/state"

for (const ephemeral of [false, true]) {
  test(`API key creation is separate from saved keys and follows ${ephemeral ? "ephemeral" : "persistent"} mode`, async () => {
    const fixture = preview(() => {})
    if (ephemeral) await fixture.request({ operation: "unlock-ephemeral" })
    const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
    const commands: unknown[] = []
    const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, request: async (input) => {
      if (input.operation === "api-keys") commands.push(JSON.parse(new TextDecoder().decode(input.payload)))
      return fixture.request(input)
    } }} />, { width: 80, height: 24, kittyKeyboard: true })
    try {
      await app.renderOnce(); await app.mockInput.pressKey("3"); await app.renderOnce()
      const rows = app.captureCharFrame().split("\n")
      expect(rows.findIndex((row) => row.includes("Add API key N"))).toBeLessThan(rows.findIndex((row) => row.includes("Personal")))
      await app.mockInput.pressKey("n"); await app.renderOnce()
      expect(app.captureCharFrame()).not.toMatch(/Save encrypted|Keep in RAM|› Storage/)
      await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter(); await app.mockInput.pressEnter()
      await app.mockInput.typeText("synthetic-test-key-secret")
      await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.renderOnce()
      expect(commands).toEqual([{ action: ephemeral ? "temporary" : "add", provider: "refuseless", name: "Personal", key: "synthetic-test-key-secret" }])
      expect(app.captureCharFrame()).not.toContain("synthetic-test-key-secret")
    } finally { await app.dispose() }
  })

  test(`privacy selection persists automatically in ${ephemeral ? "RAM" : "encrypted storage"}`, async () => {
    const fixture = preview(() => {})
    if (ephemeral) await fixture.request({ operation: "unlock-ephemeral" })
    const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
    const commands: unknown[] = []
    const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, request: async (input) => {
      if (input.operation === "egress") commands.push(JSON.parse(new TextDecoder().decode(input.payload)))
      return fixture.request(input)
    } }} />, { width: 160, height: 50, kittyKeyboard: true })
    try {
      await app.renderOnce(); await app.mockInput.pressKey("2"); await app.mockInput.pressArrow("right"); await app.mockInput.pressEnter()
      await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter(); await app.renderOnce()
      await app.mockInput.typeText("192.0.2.10:1080")
      for (let i = 0; i < 4; i++) await app.mockInput.pressEnter()
      await app.renderOnce()
      expect(commands).toEqual([{ action: ephemeral ? "select" : "save", transport: { mode: "socks5", endpoint: "192.0.2.10:1080", authentication: null } }])
      expect(app.captureCharFrame()).toContain("[x] SOCKS5 proxy")
      await app.mockInput.pressEnter(); await app.mockInput.pressArrow("up"); await app.mockInput.pressEnter(); await app.renderOnce()
      expect(commands.at(-1)).toEqual({ action: ephemeral ? "select" : "save", transport: { mode: "tor" } })
      expect(app.captureCharFrame()).toContain("[x] Tor")
      expect(app.captureCharFrame()).not.toContain("Apply transport")
      expect(app.captureCharFrame()).toContain("HOST / Network / Privacy")
    } finally { await app.dispose() }
  })
}

test.each([[80, 24], [160, 50]])("system displays hardware and global lock remains in the footer at %ix%i", async (width, height) => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App initial={initial} runtime={runtime} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("5"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("HOST / System")
    expect(app.captureCharFrame()).toContain("ARM64 virtual CPU")
    expect(app.captureCharFrame()).toContain("Memory")
    expect(app.captureCharFrame()).toContain("Boot storage")
    const rows = app.captureCharFrame().split("\n")
    expect(rows.filter((row) => row.includes("Lock Oblivion"))).toHaveLength(1)
    expect(rows.slice(-4).join("\n")).toContain("Lock Oblivion Ctrl+Q")
    await app.mockInput.pressKey("\x1b[6~"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Persistent · Encrypted")
    await app.mockInput.pressKey("q", { ctrl: true }); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Welcome back")
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("loading uses a central modal and blocks navigation at %ix%i", async (width, height) => {
  const fixture = preview(() => {})
  const waiting = Promise.withResolvers<string>()
  const started = Promise.withResolvers<void>()
  const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
  const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, request: (input) => {
    if (input.operation === "connections") { started.resolve(); return waiting.promise }
    return fixture.request(input)
  } }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("2"); await app.mockInput.pressKey("r"); await started.promise
    await app.renderOnce()
    const rows = app.captureCharFrame().split("\n")
    const line = rows.findIndex((row) => row.includes("Refreshing connections"))
    expect(Math.abs(line - height / 2)).toBeLessThan(4)
    expect(rows[line]).toMatch(/[|/−\\]  Refreshing connections/)
    expect(rows.slice(-5).join("\n")).not.toContain("Refreshing connections")
    await app.mockInput.pressKey("3"); await app.mockInput.pressKey("TAB"); await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("HOST / Network / Connection")
    waiting.resolve(""); await waiting.promise; await app.renderOnce()
    expect(app.captureCharFrame()).not.toMatch(/[|/−\\]  Refreshing connections/)
    expect(app.captureCharFrame()).toContain("HOST / Network / Connection")
  } finally { waiting.resolve(""); await app.dispose() }
})
