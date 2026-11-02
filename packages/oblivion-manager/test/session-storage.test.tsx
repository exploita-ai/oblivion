import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { Documents } from "../src/documents"
import { preview } from "../src/preview"
import { status } from "../src/state"
import { importSpace, mib, sizeField } from "../src/session-storage"

test("capacity validation reserves a full replacement and import working space", () => {
  expect(sizeField(512, 1024 * mib).value).toBe("512")
  const field = sizeField(2048, 2048 * mib, 512 * mib)
  expect(field.validate!("512", {})).toContain("larger")
  expect(field.validate!("2048", {})).toContain("Not enough")
  expect(field.validate!("1024", {})).toBeUndefined()
  expect(importSpace(800 * mib, 3000)).toBeGreaterThan(864 * mib)
})

test.each([[80, 24], [160, 50]])("increase storage preserves the selected session at %ix%i", async (width, height) => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App initial={initial} runtime={runtime} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("g"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Increase session storage")
    await app.mockInput.pressEnter()
    await app.mockInput.typeText("synthetic-existing-password"); await app.mockInput.pressEnter(); await app.mockInput.pressEnter()
    await app.renderOnce()
    const after = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
    expect(after.sessions).toEqual(initial.sessions)
    expect(after.session_sizes[initial.sessions[0]]).toBe(1024 * mib)
    expect(after.session_open).toBe(false)
  } finally { await app.dispose() }
})

test.each([false, true])("import resumes after growth only for the unchanged selection: changed=%s", async (changed) => {
  const steps: string[] = []
  let grown = false
  let offers = 0
  const manifest = { entries: [{ kind: "file" as const, path: "project.bin", size: 800 * mib, sha256: "a".repeat(64) }], bytes: 800 * mib, sha256: "b".repeat(64) }
  const app = await testRender(() => <Documents session={"a".repeat(32)} chat={true} capacity={512 * mib} available={4096 * mib} back={() => {}}
    grow={async (size, password) => { expect(size).toBeGreaterThan(512); expect(password).toBe("synthetic-password"); steps.push("grow"); grown = true }}
    connect={async () => ({
      browse: async () => ({ path: "", entries: [{ name: "project.bin", directory: false, bytes: manifest.bytes }], next: null, skipped: 0 }),
      offer: async () => { steps.push("offer"); offers++; return { ...manifest, sha256: changed && offers > 1 ? "c".repeat(64) : manifest.sha256 } },
      approve: async (value, progress) => { steps.push("copy"); expect(grown).toBe(true); progress?.(value.bytes); return { id: "d".repeat(32), entries: 1, bytes: value.bytes, manifest_sha256: value.sha256 } },
      recover: async () => ({ result: "inventory" as const, records: [], next: null }), close: () => {},
    })} request={async (request) => {
      if (request.operation === "browse") return JSON.stringify({ path: "", entries: [], next: null, skipped: 0 })
      if (request.operation === "session-storage") return JSON.stringify({ result: "storage", usage: { capacity: 2048 * mib, used: 32 * mib, available: (grown ? 1600 : 64) * mib } })
      const command = JSON.parse(new TextDecoder().decode(request.payload)) as { operation: string }
      if (command.operation === "list") return JSON.stringify({ configured: true, export_configured: true, active: false, sources: [{ id: "8:16", name: "sdb", bytes: 2048 * mib }] })
      steps.push(command.operation)
      return command.operation === "import" ? JSON.stringify({ id: "d".repeat(32) }) : ""
    }} />, { width: 120, height: 40, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("TAB"); await app.mockInput.pressEnter(); await app.renderOnce()
    await app.mockInput.pressEnter(); await app.renderOnce()
    await app.mockInput.pressKey(" "); await app.mockInput.pressKey("TAB"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Review transfer")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Increase storage and import")
    expect(steps).not.toContain("copy")
    await app.mockInput.pressEnter(); await app.mockInput.typeText("synthetic-password"); await app.mockInput.pressEnter(); await app.mockInput.pressEnter()
    await app.renderOnce(); await app.renderOnce()
    expect(steps.slice(0, 5)).toEqual(["import", "offer", "cancel", "grow", "import"])
    expect(offers).toBe(2)
    if (changed) { expect(steps).not.toContain("copy"); expect(app.captureCharFrame()).toContain("source changed") }
    if (!changed) { expect(steps).toContain("copy"); expect(app.captureCharFrame()).toContain("Transfer complete") }
  } finally { await app.dispose() }
})
