import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { OnionShare } from "../src/onion-share"
import { Shell } from "../src/shell"
import { ControlError } from "../src/control"

test.each([[80, 24], [160, 50]])("share requires manifest approval before publication and revokes on close at %ix%i", async (width, height) => {
  const id = "a".repeat(32)
  const address = `http://${"b".repeat(56)}.onion/`
  const actions: string[] = []
  const offer = { entries: [{ kind: "file" as const, path: "workspace/note.txt", size: 42, sha256: "c".repeat(64) }], bytes: 42, sha256: "d".repeat(64) }
  const app = await testRender(() => <Shell mounted activeSession={id} breadcrumb="SESSION / aaaaaaaa / Documents" page={0} navigation={false} editing network="OFFLINE" host="CONNECTED" blocked={false} connection="available" transport="tor" busy="" notice="" feedback="info"><OnionShare paths={["workspace/note.txt"]} back={() => actions.push("back")} connect={async (job) => {
    expect(job).toBe(id); actions.push("connect")
    return {
      browse: async () => { throw new Error("Unexpected browsing") },
      offer: async (paths) => { expect(paths).toEqual(["workspace/note.txt"]); actions.push("offer"); return offer },
      approve: async (value) => { expect(value).toEqual(offer); actions.push("approve"); return { id, manifest_sha256: offer.sha256, bytes: 42, entries: 1 } },
      recover: async () => { throw new Error("Unexpected recovery") },
      close: () => actions.push("disconnect"),
    }
  }} request={async (request) => {
    expect(request.operation).toBe("onion")
    const command = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string; client_auth?: string }
    actions.push(command.action)
    if (command.action === "access") return JSON.stringify({ url: address })
    if (command.action === "share") expect(command.client_auth).toMatch(/^[A-Z2-7]{51}[AQ]$/)
    const phase = command.action === "prepare" ? "ready" : command.action === "stage" ? "staging" : command.action === "status" ? "staged" : command.action === "share" ? "sharing" : "closed"
    return JSON.stringify({ configured: true, active: phase !== "closed", id: phase === "closed" ? null : id, phase, tor_progress: 100, tor_ready: true, age_ms: 0, progress: null, receipt: null })
  }} /></Shell>, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Review Tor share")
    expect(app.captureCharFrame()).toContain("workspace/note.txt")
    expect(app.captureCharFrame()).toContain("Confirm and start sharing")
    expect(app.captureCharFrame()).toContain("Network [+]")
    expect(actions).toEqual(["prepare", "stage", "connect", "offer"])
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(actions).toEqual(["prepare", "stage", "connect", "offer", "approve", "disconnect", "status", "share", "access"])
    expect(app.captureCharFrame().replace(/\s/g, "")).toContain(address)
    expect(app.captureCharFrame()).toContain("Hidden")
    expect(app.captureCharFrame()).toContain("Stop sharing and return")
    await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Hide access key")
    await app.mockInput.pressEscape(); await app.renderOnce()
    expect(actions.slice(-2)).toEqual(["cancel", "back"])
    expect(app.captureCharFrame()).not.toContain(address)
  } finally { await app.dispose() }
  expect(actions.filter((action) => action === "cancel")).toHaveLength(1)
})

test("unconfigured sharing never publishes or cancels an unowned transfer", async () => {
  const actions: string[] = []
  const app = await testRender(() => <OnionShare paths={["workspace/note.txt"]} back={() => {}} request={async (request) => {
    actions.push((JSON.parse(new TextDecoder().decode(request.payload)) as { action: string }).action)
    throw new ControlError("onion_not_configured")
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("onion_not_configured")
  } finally { await app.dispose() }
  expect(actions).toEqual(["prepare"])
})

test.each([[80, 24], [160, 50]])("encrypted backup sharing needs a password and a separate publish confirmation at %ix%i", async (width, height) => {
  const actions: string[] = []
  const id = "a".repeat(32)
  const app = await testRender(() => <Shell mounted breadcrumb="HOST / Sessions / Encrypted backup" page={0} navigation={false} editing network="OFFLINE" host="CONNECTED" blocked={false} connection="available" transport="tor" busy="" notice="" feedback="info"><OnionShare paths={[]} backup={{ id, title: "Research" }} back={() => actions.push("back")} request={async (request) => {
    const body = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string; password?: string; id?: string; client_auth?: string }
    actions.push(body.action)
    if (body.action === "prepare-backup") {
      expect(body.id).toBe(id)
      expect(body.password).toBe("TEST_PASSWORD_ONLY")
      expect(request.timeoutMs).toBe(360_000)
      return JSON.stringify({ configured: true, active: true, id, tor_progress: 100, tor_ready: true, age_ms: 0, phase: "ready", progress: { files: 1, bytes: 512 * 1024 ** 2, transferred_bytes: 0, rejected: 0 }, receipt: null })
    }
    if (body.action === "share") { expect(body.client_auth).toMatch(/^[A-Z2-7]{52}$/); return JSON.stringify({ configured: true, active: true, id, tor_progress: 100, tor_ready: true, age_ms: 0, phase: "sharing", progress: { files: 1, bytes: 512 * 1024 ** 2, transferred_bytes: 0, rejected: 0 }, receipt: null }) }
    if (body.action === "access") return JSON.stringify({ url: `http://${"b".repeat(56)}.onion/` })
    if (body.action === "cancel") return JSON.stringify({ configured: true, active: false, id: null, tor_progress: null, tor_ready: false, age_ms: 0, phase: "closed", progress: null, receipt: null })
    throw new Error("Unexpected backup request")
  }} /></Shell>, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(actions).toEqual([])
    expect(app.captureCharFrame()).toContain("Share encrypted backup")
    await app.mockInput.typeText("TEST_PASSWORD_ONLY")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("TEST_PASSWORD_ONLY")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(actions).toEqual(["prepare-backup"])
    expect(app.captureCharFrame()).toContain("Review encrypted backup")
    expect(app.captureCharFrame()).toContain("512")
    expect(app.captureCharFrame()).not.toContain(".onion/")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(actions).toEqual(["prepare-backup", "share", "access"])
    expect(app.captureCharFrame()).toContain("Hidden")
    expect(app.captureCharFrame()).toContain("Stop sharing and return")
    await app.mockInput.pressEscape(); await app.renderOnce()
    expect(actions.slice(-2)).toEqual(["cancel", "back"])
  } finally { await app.dispose() }
})
