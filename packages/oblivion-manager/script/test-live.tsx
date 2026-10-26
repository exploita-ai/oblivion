import assert from "node:assert/strict"
import { randomUUID } from "node:crypto"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { ControlError, request } from "../src/control"
import { status } from "../src/state"

// Development-only integration test. Creates encrypted volumes on a disposable
// laboratory USB through the actual forms and controller, never a physical disk.
assert(process.argv.includes("--scratch-usb"), "Requires an explicitly disposable VM USB")
assert(process.platform === "linux" && process.getuid?.() === 1000)
const initial = status.parse(JSON.parse(await request({ operation: "status" })))
assert(!initial.general_present && !initial.general_incomplete && !initial.general_mounted)
assert.equal(initial.persistence?.plan?.disk_bytes, 8 * 1024 ** 3)
const password = `lab-${randomUUID()}`
const sessionPassword = `lab-${randomUUID()}`
const passed: string[] = []
const errors: string[] = []
function record(message: string) { passed.push(message); process.stdout.write(`PASS ${message}\n`) }
const app = await testRender(() => <App initial={initial} runtime={{
  request: async (input) => {
    try { return await request(input) }
    catch (error) {
      const message = `Controller rejected ${input.operation}: ${error instanceof ControlError ? error.code : "unexpected_error"}`
      errors.push(message)
      process.stdout.write(message + "\n")
      throw error
    }
  },
  console: async () => { throw new Error("This test does not contact a provider") },
  documents: async () => {}, exit: () => {},
}} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })

async function visible(text: string) {
  const deadline = performance.now() + 120_000
  while (performance.now() < deadline) {
    await app.renderOnce()
    assert.equal(errors.length, 0, errors.join("\n"))
    if (app.captureCharFrame().includes(text)) return
    await Bun.sleep(20)
  }
  throw new Error(`Expected screen did not appear: ${text}\n${app.captureCharFrame()}`)
}

async function enterPassword(value: string) {
  await app.mockInput.typeText(value)
  await app.mockInput.pressEnter()
}

try {
  await visible("ACCESS / First-time setup")
  await app.mockInput.pressEnter()
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  await enterPassword(password)
  await enterPassword(password)
  await app.mockInput.pressEnter()
  await visible("Keyboard / Layout")
  assert(status.parse(JSON.parse(await request({ operation: "status" }))).general_mounted)
  record("USB preparation and archive unlock through the form")
  await app.mockInput.pressEscape()
  await visible("+ New protected session")
  await app.mockInput.pressEnter()
  await enterPassword(sessionPassword)
  await enterPassword(sessionPassword)
  await app.mockInput.pressEnter()
  await visible("Close and lock session")
  await visible("Create a protected session completed.")
  assert.equal(status.parse(JSON.parse(await request({ operation: "status" }))).session_mode, "documents")
  record("Session creation and offline opening through the form")
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  await visible("Roots: workspace / imports")
  await visible("workspace/")
  record("Documents browsing on the real offline VM")
  await app.mockInput.pressEscape()
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
  await visible("Close session completed.")
  assert(!status.parse(JSON.parse(await request({ operation: "status" }))).session_open)
  record("Session close confirmation")
  await app.mockInput.pressKey("TAB")
  await app.mockInput.pressArrow("right")
  await visible("HOST / Network")
  await app.mockInput.pressArrow("left")
  await visible("Your protected sessions")
  await app.mockInput.pressEnter()
  record("Distinct Sessions and Network content")
  await app.mockInput.pressKey("c", { ctrl: true })
  await app.mockInput.pressEnter()
  await visible("ACCESS / Unlock archive")
  await app.mockInput.pressEnter()
  await enterPassword(password)
  await app.mockInput.pressEnter()
  await visible("Keyboard / Layout")
  await app.mockInput.pressEscape()
  await visible("Your protected sessions")
  await app.mockInput.pressEnter()
  await enterPassword(sessionPassword)
  await app.mockInput.pressEnter()
  await visible("Close and lock session")
  await visible("Open protected session completed.")
  record("Archive and existing session reopen through password forms")
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
  await visible("Close session completed.")
  assert(!status.parse(JSON.parse(await request({ operation: "status" }))).session_open)
  record("Immediate close after reopening waits for guest readiness")
  await request({ operation: "lock" })
  process.stdout.write(JSON.stringify({ passed }) + "\n")
} finally {
  app.renderer.destroy()
  await app.renderer.closed
}
