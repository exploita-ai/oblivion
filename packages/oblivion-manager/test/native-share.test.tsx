import { expect, test } from "bun:test"
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { NativeShare, type ShareSelection } from "../src/native-share"
import { SafeManager } from "../src/safe-manager"
import { nativePreview } from "../src/native-control"

const safe = "0123456789abcdef0123456789abcdef"

async function visible(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(text)) return
    await Bun.sleep(5)
  }
  throw new Error(`Missing ${text}\n${app.captureCharFrame()}`)
}

async function reviewExport(app: Awaited<ReturnType<typeof testRender>>) {
  await visible(app, "Choose Share destination")
  await app.mockInput.pressKey(".")
  await visible(app, "Name the encrypted Share")
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
  await visible(app, "Review Share export")
}

test.each([[80, 24], [160, 50]])("Share reviews a closed Safe and an explicit destination before launching the CLI at %ix%i", async (width, height) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-share-ui-"))
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "export", scope: "safe", safe, name: "Research", closed: true }} initialDirectory={directory}
    run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await reviewExport(app)
    expect(calls).toHaveLength(0)
    const frame = app.captureCharFrame().replaceAll("\n", " ")
    expect(frame).toContain("Provider login stores are excluded")
    expect(frame).toContain("Content scan is best effort")
    expect(frame).toContain("Research")
    await app.mockInput.pressEnter()
    await visible(app, "Share exported")
    expect(calls).toEqual([["share", "export", "--safe", safe, path.join(directory, "oblivion-01234567.oblivion-share")]])
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("Import Share selects a file, never a directory, then leaves all passwords to the CLI", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-share-ui-"))
  await mkdir(path.join(directory, "folder"))
  await writeFile(path.join(directory, "payload.oblivion-share"), "synthetic UI fixture, not an encrypted package")
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "import" }} initialDirectory={directory}
    run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "folder/")
    await app.mockInput.pressKey(" ")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Choose an encrypted Share file")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review Share import")
    expect(calls).toHaveLength(0)
    expect(app.captureCharFrame()).toContain("existing Safes are not replaced")
    expect(app.captureCharFrame()).toContain("[ ]")
    expect(app.captureCharFrame()).toContain("Apply shared automatic-lock settings")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Share imported")
    expect(calls).toEqual([["share", "import", path.join(directory, "payload.oblivion-share")]])
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test.each([
  [0, "Share imported", "New encrypted Safes were published offline"],
  [130, "Share cancelled", "Check Share imports and your Safes before retrying"],
  [2, "Safes imported · settings not applied", "Do not import the Share again"],
] as const)("import settings are explicit and exit %i reports its actual outcome", async (code, title, description) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-share-ui-"))
  const file = path.join(directory, "payload.oblivion-share")
  await writeFile(file, "synthetic UI fixture, not an encrypted package")
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "import" }} initialDirectory={directory}
    run={async (args) => { calls.push(args); return code }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "payload.oblivion-share")
    await app.mockInput.pressEnter()
    await visible(app, "Apply shared automatic-lock settings")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressKey(" ")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("[x]")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, title)
    expect(app.captureCharFrame()).toContain(description)
    expect(calls).toEqual([["share", "import", file, "--apply-settings"]])
    expect(calls).toHaveLength(1)
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test.each(["safe", "branch", "all"] as const)("Share %s scope becomes exactly one explicit CLI selector", async (scope) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-share-ui-"))
  const selection: ShareSelection = scope === "all"
    ? { operation: "export", scope: "all", count: 3, closed: true }
    : { operation: "export", scope: "safe", safe, name: "Research", closed: true, branch: { count: 3, closed: true } }
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={selection} initialDirectory={directory}
    run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    if (scope !== "all") {
      expect(app.captureCharFrame()).toContain("Choose Share scope")
      if (scope === "branch") await app.mockInput.pressArrow("down")
      await app.mockInput.pressEnter()
    }
    await reviewExport(app)
    expect(calls).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Share exported")
    expect(calls[0]?.slice(0, -1)).toEqual(scope === "all" ? ["share", "export", "--all"] : ["share", "export", scope === "branch" ? "--branch" : "--safe", safe])
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("Share all explicitly includes lock timers and retains its choices after a cancelled terminal review", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-share-ui-"))
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "export", scope: "all", count: 3, closed: true }} initialDirectory={directory}
    run={async (args) => { calls.push(args); return calls.length === 1 ? 130 : 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await reviewExport(app)
    await visible(app, "Automatic-lock timers · Excluded")
    await app.mockInput.pressKey("i")
    await visible(app, "Automatic-lock timers · Included")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Back to review")
    expect(calls[0]).toEqual(["share", "export", "--all", path.join(directory, "oblivion-all.oblivion-share"), "--include-settings"])
    await app.mockInput.pressEnter()
    await visible(app, "Automatic-lock timers · Included")
    await app.mockInput.pressKey("i")
    await visible(app, "Automatic-lock timers · Excluded")
    await app.mockInput.pressEnter()
    await visible(app, "Share exported")
    expect(calls[1]).toEqual(calls[0].slice(0, -1))
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("cancelled review and a source reopened elsewhere never start export", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-share-ui-"))
  const [closed, setClosed] = createSignal(true)
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "export", scope: "safe", safe, name: "Research", closed: closed() }} initialDirectory={directory}
    run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await reviewExport(app)
    await app.mockInput.pressEscape()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Name the encrypted Share")
    expect(calls).toHaveLength(0)
    setClosed(false)
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Close this Safe before Share")
    await app.mockInput.pressEnter()
    expect(calls).toHaveLength(0)
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("manager offers Share all in Settings and blocks active Safe export and RAM-only import", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  await fixture.run(["safe", "open", safe])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager initial={undefined} runtime={{ ...fixture, run: async (args) => { calls.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    expect(app.captureCharFrame()).toContain("Import Share")
    await app.mockInput.pressKey("s")
    await visible(app, "Close and lock this Safe before Share")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressKey("F2")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Share all Safes")
  } finally { await app.dispose() }
  const ram = nativePreview(() => {})
  await ram.run(["ephemeral"])
  const other = await testRender(() => <SafeManager initial={undefined} runtime={{ ...ram, run: async (args) => { calls.push(args); return ram.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(other, "Your Safes")
    await other.mockInput.pressKey("i")
    await visible(other, "Share requires writable encrypted storage")
    expect(calls).toHaveLength(0)
  } finally { await other.dispose() }
})

test("imported parent edges offer a branch without agent provenance and fence an open descendant", async () => {
  const child = "abcdef0123456789abcdef0123456789"
  const fixture = nativePreview(() => {}, { safe_parents: [{ id: child, parent: safe }] })
  await fixture.run(["unlock"])
  await fixture.run(["safe", "open", child])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return fixture.run(args) } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressKey("s")
    await visible(app, "Choose Share scope")
    expect(app.captureCharFrame()).toContain("This Safe only")
    expect(app.captureCharFrame()).toContain("Safe and descendants")
    await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("branch of 2 persistent Safes")
    expect(app.captureCharFrame()).toContain("Close the included descendant Safes first")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Choose Share scope")
    expect(calls).toHaveLength(0)
  } finally { await app.dispose() }
})
