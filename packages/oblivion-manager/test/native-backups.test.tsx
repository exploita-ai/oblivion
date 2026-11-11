import { expect, test } from "bun:test"
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { createSignal } from "solid-js"
import { testRender } from "@opentui/solid"
import { NativeBackups, backupStatus } from "../src/native-backups"
import { nativePreview } from "../src/native-control"
import { SafeManager } from "../src/safe-manager"

const safe = "0123456789abcdef0123456789abcdef"
const transaction = "a".repeat(32)
const opening = "b".repeat(32)
const record = { transaction, slot: 2, kind: "import" as const, safe_id: null as string | null, bytes: 512 * 1024 ** 2, outcome: "copied" as const, active: false }

async function visible(app: Awaited<ReturnType<typeof testRender>>, value: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(value)) return
    await Bun.sleep(5)
  }
  throw new Error(`Missing ${value}\n${app.captureCharFrame()}`)
}

async function transfers(app: Awaited<ReturnType<typeof testRender>>) {
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  await visible(app, "Personal backup transfers")
}

test.each([[80, 24], [160, 50]])("personal backup reviews full contents and the chosen output before any command at %ix%i", async (width, height) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-backup-ui-"))
  const fixture = nativePreview(() => {})
  const commands: string[][] = []
  const app = await testRender(() => <NativeBackups runtime={fixture} writable opening={opening} safe={{ id: safe, name: "Research", persistent: true, closed: true }} initialDirectory={directory}
    run={async (args) => { commands.push(args); return 0 }} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await visible(app, "Choose backup destination")
    await app.mockInput.pressKey(".")
    await visible(app, "Name the personal backup")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Review personal backup")
    expect(commands).toHaveLength(0)
    expect(app.captureCharFrame()).toContain("saved logins and installed software")
    expect(app.captureCharFrame()).toContain("Keep the original Safe password")
    expect(app.captureCharFrame()).toContain("Research")
    await app.mockInput.pressEnter()
    await visible(app, "Personal backup saved")
    expect(commands).toEqual([["backup", "export", "--safe", safe, path.join(directory, "oblivion-01234567.luks")]])
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("restore selects a file and treats interruption as unknown until actual transaction status", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-backup-ui-"))
  await mkdir(path.join(directory, "folder"))
  await writeFile(path.join(directory, "selected.luks"), "UI fixture only, not a LUKS volume")
  const fixture = nativePreview(() => {})
  const commands: string[][] = []
  const runtime = { ...fixture, query: async () => ({ transactions: [{ ...record, outcome: "committed", safe_id: safe }] }) }
  const app = await testRender(() => <NativeBackups runtime={runtime} writable opening={opening} initialDirectory={directory}
    run={async (args) => { commands.push(args); return 130 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "folder/")
    await app.mockInput.pressKey(" ")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Choose a personal LUKS2 backup")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review personal restore")
    expect(commands).toHaveLength(0)
    expect(app.captureCharFrame()).toContain("original Safe identity and saved logins")
    expect(app.captureCharFrame()).toContain("restored Safe starts Offline")
    await app.mockInput.pressEnter()
    await visible(app, "Check the transfer outcome")
    expect(commands).toEqual([["backup", "import", path.join(directory, "selected.luks")]])
    expect(app.captureCharFrame()).toContain("does not prove")
    await app.mockInput.pressEnter()
    await visible(app, "Safe restored")
    await app.mockInput.pressEnter()
    await visible(app, "Restored · read-only")
    await app.mockInput.pressEnter()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    expect(commands).toHaveLength(1)
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("a verified import can finish with its exact transaction and private CLI password", async () => {
  const fixture = nativePreview(() => {})
  let complete = false
  const commands: string[][] = []
  const queries: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => { queries.push(args); return { transactions: [{ ...record, ...(complete ? { outcome: "committed", safe_id: safe } : {}) }] } } }
  const app = await testRender(() => <NativeBackups runtime={runtime} writable opening={opening}
    run={async (args) => { commands.push(args); complete = true; return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await transfers(app)
    await visible(app, "Ciphertext verified")
    await app.mockInput.pressEnter()
    await visible(app, "Finish restore")
    await app.mockInput.pressEnter()
    await visible(app, "Safe restored Offline")
    expect(commands).toEqual([["backup", "finish", transaction]])
    expect(queries.every((args) => args.join(" ") === "backup status --json")).toBe(true)
  } finally { await app.dispose() }
})

test("active work and unavailable status cannot authorize discard, and a new unlock clears old records", async () => {
  const fixture = nativePreview(() => {})
  const [epoch, setEpoch] = createSignal(opening)
  let fail = false
  const commands: string[][] = []
  const runtime = { ...fixture, query: async () => { if (fail) throw new Error("unavailable"); return { transactions: [{ ...record, outcome: "copying", active: true }] } } }
  const app = await testRender(() => <NativeBackups runtime={runtime} writable opening={epoch()} run={async (args) => { commands.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await transfers(app)
    await visible(app, "Copy in progress")
    await app.mockInput.pressEnter()
    await visible(app, "Personal backup transfer")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    expect(commands).toHaveLength(0)
    fail = true
    await app.mockInput.pressKey("r")
    await visible(app, "Backup status is unavailable")
    await app.mockInput.pressEnter()
    expect(commands).toHaveLength(0)
    setEpoch("c".repeat(32))
    await visible(app, "Personal backups")
    expect(app.captureCharFrame()).not.toContain(transaction)
  } finally { await app.dispose() }
})

test("closed persistent source and writable mode are checked before choosing a backup path", async () => {
  const fixture = nativePreview(() => {})
  const commands: string[][] = []
  const app = await testRender(() => <NativeBackups runtime={fixture} writable opening={opening} safe={{ id: safe, name: "Research", persistent: true, closed: false }}
    run={async (args) => { commands.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Close and lock the selected Safe")
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("manager Settings exposes personal recovery separately from Share", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const app = await testRender(() => <SafeManager runtime={fixture} initial={initial} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("\x1bOQ")
    await app.renderOnce()
    for (let index = 0; index < 4; index++) await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Create personal backup")
    expect(app.captureCharFrame()).toContain("Use Share to exclude saved provider login")
  } finally { await app.dispose() }
})

test("backup status accepts copied malformed-volume sizes for recovery but rejects secrets and inconsistent completion", () => {
  expect(backupStatus.safeParse({ transactions: [{ ...record, bytes: 32 * 1024 ** 2 + 128 }] }).success).toBe(true)
  expect(backupStatus.safeParse({ transactions: [{ ...record, password: "never-render-this" }] }).success).toBe(false)
  expect(backupStatus.safeParse({ transactions: [{ ...record, outcome: "committed" }] }).success).toBe(false)
  expect(backupStatus.safeParse({ transactions: [{ ...record, active: true }] }).success).toBe(false)
})
