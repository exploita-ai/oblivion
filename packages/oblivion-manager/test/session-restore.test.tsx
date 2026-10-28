import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { ControlError } from "../src/control"
import { preview } from "../src/preview"
import { SessionRestore } from "../src/session-restore"
import { status } from "../src/state"

const media = { configured: true, export_configured: true, active: false, sources: [
  { id: "252:32", name: "import-only", kind: "virtual", read_only: true, bytes: 1024 ** 3 },
  { id: "8:32", name: "sdc", kind: "usb", read_only: false, bytes: 8 * 1024 ** 3 },
] }

test.each([[80, 24], [160, 50]])("restore accepts read-only sources and cleans up a late preparation at %ix%i", async (width, height) => {
  const operations: { operation: string; source?: string; id?: string }[] = []
  const prepared = Promise.withResolvers<string>()
  const discarded = Promise.withResolvers<void>()
  const app = await testRender(() => <SessionRestore back={() => {}} request={async (request) => {
    const body = JSON.parse(new TextDecoder().decode(request.payload)) as typeof operations[number]
    operations.push(body)
    if (body.operation === "list") return JSON.stringify(media)
    if (body.operation === "restore") return prepared.promise
    if (body.operation === "cancel") return "true"
    if (body.operation === "restore-discard") { discarded.resolve(); return "true" }
    throw new Error("Unexpected request")
  }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("import-only · Virtual media")
    expect(app.captureCharFrame()).toContain("sdc · USB")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations).toEqual([{ operation: "list" }, { operation: "restore", source: "252:32" }])
    expect(app.captureCharFrame()).toContain("Opening read-only backup source")
    await app.dispose()
    expect(operations.map((operation) => operation.operation)).toEqual(["list", "restore"])
    prepared.resolve(JSON.stringify({ id: "c".repeat(32), bytes: 768 * 1024 ** 2 }))
    await discarded.promise
    expect(operations.slice(2)).toEqual([{ operation: "cancel" }, { operation: "restore-discard", id: "c".repeat(32) }])
  } finally {
    prepared.resolve(JSON.stringify({ id: "c".repeat(32), bytes: 768 * 1024 ** 2 }))
    await app.dispose()
  }
})

test.each([[80, 24], [160, 50]])("restore is available in an empty writable archive and preserves the host shell at %ix%i", async (width, height) => {
  const fixture = preview(() => {})
  const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
  const app = await testRender(() => <App initial={{ ...initial, general_mounted: true, general_open: true, general_readonly: false, session_open: false, active_session: null, sessions: [], session_titles: {} }} runtime={{ ...fixture, request: async (request) => request.operation === "transfers" ? JSON.stringify(media) : fixture.request(request) }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Restore")
    await app.mockInput.pressKey("o"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("HOST / Sessions / Restore session")
    expect(app.captureCharFrame()).toContain("import-only · Virtual media")
    expect(app.captureCharFrame()).toContain("Network")
    expect(app.captureCharFrame()).toContain("System")
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("failed restore preparation explains low space and releases only its own operation at %ix%i", async (width, height) => {
  const operations: string[] = []
  const app = await testRender(() => <SessionRestore back={() => {}} request={async (request) => {
    const body = JSON.parse(new TextDecoder().decode(request.payload)) as { operation: string }
    operations.push(body.operation)
    if (body.operation === "list") return JSON.stringify(media)
    if (body.operation === "restore") throw new ControlError("insufficient_restore_space")
    if (body.operation === "cancel") return "true"
    throw new Error("Unexpected request")
  }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations).toEqual(["list", "restore", "cancel"])
    expect(app.captureCharFrame()).toContain("enough free space")
    expect(app.captureCharFrame()).toContain("Restore session / Source")
    expect(app.captureCharFrame()).not.toContain("insufficient_restore_space")
  } finally { await app.dispose() }
})

test("entering restore never cancels a transfer owned by another workflow", async () => {
  const operations: string[] = []
  const app = await testRender(() => <SessionRestore back={() => {}} request={async (request) => {
    const body = JSON.parse(new TextDecoder().decode(request.payload)) as { operation: string }
    operations.push(body.operation)
    if (body.operation === "list") return JSON.stringify({ ...media, active: true })
    throw new Error("Unexpected cancellation")
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Another file transfer")
    expect(operations).toEqual(["list"])
  } finally { await app.dispose() }
  expect(operations).toEqual(["list"])
})
