import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { Documents } from "../src/documents"

test.each([false, true])("sealed Tor intake reuses document review and the correct cancellation owner: approve=%s", async (approve) => {
  const id = "a".repeat(32)
  const operations: string[] = []
  const page = { path: "", entries: [{ name: "note.txt", directory: false, bytes: 42 }], next: null, skipped: 0 }
  const offer = { entries: [{ kind: "file" as const, path: "note.txt", size: 42, sha256: "b".repeat(64) }], bytes: 42, sha256: "c".repeat(64) }
  const receipt = { id, entries: 1, bytes: 42, manifest_sha256: offer.sha256 }
  const app = await testRender(() => <Documents session={"d".repeat(32)} chat={false} back={() => {}} connect={async (job) => {
    expect(job).toBe(id); operations.push("connect")
    return {
      browse: async () => page,
      offer: async (paths) => { expect(paths).toEqual(["note.txt"]); operations.push("offer"); return offer },
      approve: async (value) => { expect(value).toEqual(offer); operations.push("approve"); return receipt },
      recover: async () => ({ result: "inventory" as const, records: [], next: null }),
      close: () => operations.push("disconnect"),
    }
  }} request={async (request) => {
    if (request.operation === "browse") return JSON.stringify({ ...page, entries: [{ name: "workspace", directory: true, bytes: 0 }] })
    expect(request.operation).toBe("onion")
    const command = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string }
    operations.push(command.action)
    if (command.action === "access") return JSON.stringify({ url: `http://${"b".repeat(56)}.onion/` })
    const phase = command.action === "prepare" ? "ready" : command.action === "freeze" ? "review" : command.action === "import" ? "copying" : command.action === "cancel" ? "closed" : "receiving"
    return JSON.stringify({ configured: true, active: phase !== "closed", id: phase === "closed" ? null : id, phase, tor_progress: 100, tor_ready: true, age_ms: 0, progress: null, receipt: null })
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("TAB")
    for (let index = 0; index < 5; index++) await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Receive over Tor")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Tor address revoked")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("sealed intake")
    expect(app.captureCharFrame()).toContain("note.txt")
    expect(operations).toEqual(["prepare", "receive", "access", "freeze", "import", "connect"])
    if (!approve) return
    await app.mockInput.pressKey(" "); await app.mockInput.pressKey("TAB")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Review transfer")
    expect(operations).toContain("offer")
    expect(operations).not.toContain("approve")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations).toContain("approve")
    expect(operations).toContain("cancel")
    expect(app.captureCharFrame()).toContain("Transfer complete")
  } finally {
    await app.dispose()
    expect(operations.filter((value) => value === "cancel")).toHaveLength(1)
  }
})
