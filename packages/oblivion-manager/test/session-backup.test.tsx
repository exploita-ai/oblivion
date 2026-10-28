import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { SessionBackup } from "../src/session-backup"
import { status } from "../src/state"

const media = { configured: true, export_configured: true, active: false, sources: [
  { id: "252:32", name: "import-only", kind: "virtual", read_only: true, bytes: 1024 ** 3 },
  { id: "8:32", name: "sdc", kind: "usb", read_only: false, bytes: 8 * 1024 ** 3 },
] }

test.each([[80, 24], [160, 50]])("backup authorizes a destination and keeps its password hidden at %ix%i", async (width, height) => {
  const operations: { operation: string; password?: string; target?: string }[] = []
  const prepared = Promise.withResolvers<string>()
  const cancelled = Promise.withResolvers<void>()
  const app = await testRender(() => <SessionBackup id={"a".repeat(32)} title="Private session" back={() => {}} request={async (request) => {
    const body = JSON.parse(new TextDecoder().decode(request.payload)) as typeof operations[number]
    operations.push(body)
    if (body.operation === "list") return JSON.stringify(media)
    if (body.operation === "backup") { expect(request.timeoutMs).toBe(360_000); return prepared.promise }
    if (body.operation === "cancel") { cancelled.resolve(); return "true" }
    throw new Error("Unexpected request")
  }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("sdc · USB")
    expect(app.captureCharFrame()).not.toContain("import-only")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Prepare encrypted backup")
    expect(app.captureCharFrame()).toContain("Authorize and prepare")
    expect(operations).toEqual([{ operation: "list" }])
    await app.mockInput.typeText("TEST_PASSWORD_PRIVATE")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("TEST_PASSWORD_PRIVATE")
    expect(operations).toEqual([{ operation: "list" }])
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations.at(-1)).toMatchObject({ operation: "backup", target: "8:32", password: "TEST_PASSWORD_PRIVATE" })
    expect(app.captureCharFrame()).toContain("Preparing session offline")
    expect(app.captureCharFrame()).not.toContain("Session password")
    await app.dispose()
    expect(operations.map((operation) => operation.operation)).toEqual(["list", "backup"])
    prepared.resolve(JSON.stringify({ id: "b".repeat(32), bytes: 512 * 1024 ** 2 }))
    await cancelled.promise
    expect(operations.map((operation) => operation.operation)).toEqual(["list", "backup", "cancel"])
  } finally {
    prepared.resolve(JSON.stringify({ id: "b".repeat(32), bytes: 512 * 1024 ** 2 }))
    await app.dispose()
  }
})

test.each([[80, 24], [160, 50]])("host backup action keeps the sidebar/footer and displays the backup breadcrumb at %ix%i", async (width, height) => {
  const fixture = preview(() => {})
  const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
  const app = await testRender(() => <App initial={{ ...initial, general_mounted: true, general_open: true, general_readonly: false, session_open: false, active_session: null, sessions: ["a".repeat(32)], session_titles: { ["a".repeat(32)]: "Work" } }} runtime={{ ...fixture, request: async (request) => request.operation === "transfers" ? JSON.stringify(media) : fixture.request(request) }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Back up")
    await app.mockInput.pressKey("b"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("HOST / Sessions / Encrypted backup")
    expect(app.captureCharFrame()).toContain("sdc · USB")
    expect(app.captureCharFrame()).toContain("Network")
    expect(app.captureCharFrame()).toContain("System")
    expect(app.captureCharFrame()).not.toContain("import-only")
  } finally { await app.dispose() }
})
