import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { Documents } from "../src/documents"

test.each([false, true])("media picker distinguishes virtual inputs and excludes read-only export targets: export=%s", async (exporting) => {
  const operations: string[] = []
  const app = await testRender(() => <Documents session={"a".repeat(32)} chat={false} back={() => {}} request={async (request) => {
    if (request.operation === "browse") return JSON.stringify({ path: "", entries: [{ name: "workspace", directory: true, bytes: 0 }], next: null, skipped: 0 })
    const command = JSON.parse(new TextDecoder().decode(request.payload)) as { operation: string }
    operations.push(command.operation)
    return JSON.stringify({ configured: true, export_configured: true, active: false, sources: [
      { id: "252:32", name: "vdc", kind: "virtual", read_only: true, bytes: 64 * 1024 ** 2 },
      { id: "8:32", name: "sdc", kind: "usb", read_only: false, bytes: 128 * 1024 ** 2 },
    ] })
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    if (exporting) await app.mockInput.pressKey(" ")
    await app.mockInput.pressKey("TAB")
    if (exporting) await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter(); await app.renderOnce()
    const frame = app.captureCharFrame()
    expect(operations).toEqual(["list"])
    expect(frame).toContain("sdc · USB")
    if (!exporting) {
      expect(frame).toContain("vdc · Virtual media")
      expect(frame).toContain("Read-only")
      return
    }
    expect(frame).not.toContain("vdc")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Authorize writing to media")
    expect(app.captureCharFrame().replace(/\s+/g, " ")).toContain("ordinary readable copies")
    expect(operations).toEqual(["list"])
  } finally { await app.dispose() }
})
