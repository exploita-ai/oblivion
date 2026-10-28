import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { ControlError } from "../src/control"
import { OnionReceive } from "../src/onion-receive"
import { Shell } from "../src/shell"

const id = "a".repeat(32)
const address = `http://${"b".repeat(56)}.onion/`
const status = (phase: string) => ({ configured: true, active: phase !== "closed", id: phase === "closed" ? null : id, phase, tor_progress: 100, tor_ready: true, age_ms: 0, progress: phase === "receiving" ? { files: 2, bytes: 42, transferred_bytes: 42, rejected: 0 } : null, receipt: null })

test.each([[80, 24], [160, 50]])("receive hides its secret, revokes before review and explicitly hands off import at %ix%i", async (width, height) => {
  const commands: { action: string; client_auth?: string }[] = []
  const imported: string[] = []
  const app = await testRender(() => <Shell mounted activeSession={id} breadcrumb="SESSION / aaaaaaaa / Documents" page={0} navigation={false} editing network="OFFLINE" host="CONNECTED" blocked={false} connection="available" transport="tor" busy="" notice="" feedback="info"><OnionReceive back={() => {}} import={async (value) => { imported.push(value) }} request={async (request) => {
    expect(request.operation).toBe("onion")
    const command = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string; client_auth?: string }
    commands.push(command)
    if (command.action === "access") return JSON.stringify({ url: address })
    if (command.action === "receive") expect(command.client_auth).toMatch(/^[A-Z2-7]{51}[AQ]$/)
    return JSON.stringify(status(command.action === "prepare" ? "ready" : command.action === "freeze" ? "review" : command.action === "import" ? "copying" : command.action === "cancel" ? "closed" : "receiving"))
  }} /></Shell>, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    const frame = app.captureCharFrame()
    expect(frame).toContain("Tor verified")
    expect(frame.replace(/\s/g, "")).toContain(address)
    expect(frame).toContain("Hidden")
    expect(frame).toContain("Cancel transfer")
    expect(frame).toContain("Network [+]")
    expect(commands.map((value) => value.action)).toEqual(["prepare", "receive", "access"])
    await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Hidden")
    expect(app.captureCharFrame()).toContain("Hide access key")
    await app.mockInput.pressArrow("up"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Tor address revoked")
    expect(app.captureCharFrame()).not.toContain(address)
    expect(imported).toEqual([])
    expect(commands.at(-1)?.action).toBe("freeze")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(imported).toEqual([id])
    expect(commands.at(-1)?.action).toBe("import")
    expect(commands.some((value) => Object.hasOwn(value, "private_key"))).toBe(false)
  } finally { await app.dispose() }
  expect(commands.some((value) => value.action === "cancel")).toBe(false)
})

test("cancel during startup waits for preparation and reaps the owned job without publishing", async () => {
  const prepared = Promise.withResolvers<string>()
  const commands: string[] = []
  const backed: boolean[] = []
  const app = await testRender(() => <OnionReceive back={() => backed.push(true)} import={async () => { throw new Error("unexpected import") }} request={async (request) => {
    const command = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string }
    commands.push(command.action)
    if (command.action === "prepare") return prepared.promise
    return JSON.stringify(status("closed"))
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEscape(); await app.renderOnce()
    expect(backed).toEqual([])
    prepared.resolve(JSON.stringify(status("ready")))
    await prepared.promise; await app.renderOnce()
    expect(commands).toEqual(["prepare", "cancel"])
    expect(backed).toEqual([true])
  } finally { prepared.resolve(JSON.stringify(status("ready"))); await app.dispose() }
})

test("an unavailable image reports its error without cancelling a job it never owned", async () => {
  const commands: string[] = []
  const app = await testRender(() => <OnionReceive back={() => {}} import={async () => {}} request={async (request) => {
    const command = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string }
    commands.push(command.action)
    throw new ControlError("onion_not_configured")
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("onion_not_configured")
    expect(commands).toEqual(["prepare"])
  } finally { await app.dispose() }
  expect(commands).toEqual(["prepare"])
})
