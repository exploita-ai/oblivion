import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { status } from "../src/state"

test.each([[80, 24], [160, 50]])("debug access stays inside the locked manager at %ix%i", async (width, height) => {
  const fixture = preview(() => {})
  await fixture.request({ operation: "lock" })
  const initial = status.parse({ ...JSON.parse(await fixture.request({ operation: "status" })), debug_available: true })
  const commands: string[] = []
  let active = false
  const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, request: async (input) => {
    if (input.operation === "status") return JSON.stringify(initial)
    if (input.operation !== "debug") return fixture.request(input)
    const action = JSON.parse(new TextDecoder().decode(input.payload)).action
    commands.push(action)
    if (action === "enable-ssh") active = true
    if (action === "disable-ssh") active = false
    return JSON.stringify({ ssh_active: active, addresses: ["192.0.2.10"], fingerprint: "SHA256:synthetic" })
  } }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Welcome back")
    expect(app.captureCharFrame()).toContain("Debug")
    await app.mockInput.pressKey("TAB"); await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("ACCESS / Debug")
    expect(app.captureCharFrame()).toContain("192.0.2.10")
    expect(app.captureCharFrame()).toContain("Network")
    expect(app.captureCharFrame()).toContain("Keyboard")
    await app.mockInput.pressKey("e"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Disable access")
    await app.mockInput.pressKey("e"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Enable access")
    expect(commands).toEqual(["status", "enable-ssh", "disable-ssh"])
    await app.mockInput.pressEscape(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Welcome back")
  } finally { await app.dispose() }
})

test("normal images have no debug entry", async () => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App initial={initial} runtime={runtime} />, { width: 160, height: 50, kittyKeyboard: true })
  try { await app.renderOnce(); expect(app.captureCharFrame()).not.toContain("Debug") }
  finally { await app.dispose() }
})
