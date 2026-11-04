import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { NativeImports } from "../src/native-imports"
import { SafeManager } from "../src/safe-manager"
import { nativePreview } from "../src/native-control"

function record(transaction: string, outcome: "pending" | "committed" | "recovery-required") {
  return { transaction, outcome, package_id: "d".repeat(32), metadata_sha256: "e".repeat(64), safes: 2, ready: 1,
    openings: outcome === "committed" ? [] : [{ slot: 0, safe_id: "b".repeat(32), nonce: "f".repeat(32) }] }
}

async function visible(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(text)) return
    await Bun.sleep(5)
  }
  throw new Error(`Missing ${text}\n${app.captureCharFrame()}`)
}

test.each([[80, 24], [160, 50]])("Share imports shows real outcomes and requires explicit discard at %ix%i", async (width, height) => {
  const transaction = "a".repeat(32)
  const [records, setRecords] = createSignal([record(transaction, "recovery-required"), record("b".repeat(32), "committed"), record("c".repeat(32), "pending")])
  const commands: string[][] = []
  const queries: string[][] = []
  const runtime = { ...nativePreview(() => {}), query: async (args: string[]) => { queries.push(args); return records() } }
  const app = await testRender(() => <NativeImports runtime={runtime} writable run={async (args) => { commands.push(args); setRecords((before) => before.filter((entry) => entry.transaction !== transaction)); return 0 }} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "Recovery required")
    expect(app.captureCharFrame()).toContain("Imported")
    expect(app.captureCharFrame()).toContain("Pending · not published")
    expect(app.captureCharFrame()).not.toContain("f".repeat(32))
    expect(queries[0]).toEqual(["share", "imports", "--json"])
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Discard incomplete import?")
    expect(app.captureCharFrame().replaceAll("\n", " ")).toContain("Existing Safes and committed imports cannot be removed")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Incomplete import discarded")
    expect(commands).toEqual([["share", "discard", transaction]])
    expect(app.captureCharFrame()).not.toContain("Import aaaaaaaa")
    expect(app.captureCharFrame()).toContain("Import bbbbbbbb")
  } finally { await app.dispose() }
})

test("committed imports are inspectable but never offered for discard", async () => {
  const commands: string[][] = []
  const runtime = { ...nativePreview(() => {}), query: async () => [record("a".repeat(32), "committed")] }
  const app = await testRender(() => <NativeImports runtime={runtime} writable run={async (args) => { commands.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Imported")
    await app.mockInput.pressEnter()
    await visible(app, "Imported · read-only")
    expect(app.captureCharFrame()).not.toContain("Continue to discard")
    await app.mockInput.pressEnter()
    await visible(app, "Share imports")
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("review cancellation skips the CLI and interrupted discard refreshes authoritative records", async () => {
  const commands: string[][] = []
  const runtime = { ...nativePreview(() => {}), query: async () => [record("a".repeat(32), "pending")] }
  const app = await testRender(() => <NativeImports runtime={runtime} writable run={async (args) => { commands.push(args); return 130 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Pending · not published")
    await app.mockInput.pressEnter()
    await visible(app, "Discard incomplete import?")
    await app.mockInput.pressEscape()
    await visible(app, "Share imports")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Discard interrupted or cancelled")
    expect(app.captureCharFrame()).toContain("Import aaaaaaaa")
    expect(commands).toEqual([["share", "discard", "a".repeat(32)]])
  } finally { await app.dispose() }
})

test("a pending import committed elsewhere loses its discard action after refresh", async () => {
  const [outcome, setOutcome] = createSignal<"pending" | "committed">("pending")
  const commands: string[][] = []
  const runtime = { ...nativePreview(() => {}), query: async () => [record("a".repeat(32), outcome())] }
  const app = await testRender(() => <NativeImports runtime={runtime} writable run={async (args) => { commands.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Pending · not published")
    await app.mockInput.pressEnter()
    await visible(app, "Discard incomplete import?")
    setOutcome("committed")
    await app.mockInput.pressKey("r")
    await visible(app, "Imported · read-only")
    expect(app.captureCharFrame()).not.toContain("Continue to discard")
    await app.mockInput.pressEnter()
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("read-only access and invalid status prevent cleanup rather than using cached authority", async () => {
  const [valid, setValid] = createSignal(true)
  const [writable, setWritable] = createSignal(false)
  const commands: string[][] = []
  const runtime = { ...nativePreview(() => {}), query: async () => valid() ? [record("a".repeat(32), "pending")] : [{ transaction: "invalid" }] }
  const app = await testRender(() => <NativeImports runtime={runtime} writable={writable()} run={async (args) => { commands.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Pending · not published")
    await app.mockInput.pressEnter()
    await visible(app, "Unlock writable encrypted storage")
    expect(app.captureCharFrame()).not.toContain("Continue to discard")
    setWritable(true)
    await visible(app, "Discard incomplete import?")
    setValid(false)
    await app.mockInput.pressKey("r")
    await visible(app, "Import status is unavailable")
    expect(app.captureCharFrame()).not.toContain("Continue to discard")
    await app.mockInput.pressEnter()
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("Settings opens the Share imports lifecycle page and Esc returns without a mutation", async () => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const calls: string[][] = []
  const queries: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, query: async (args) => { queries.push(args); return [] }, run: async (args) => { calls.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressKey("F2")
    for (let index = 0; index < 5; index++) await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Inspect imports")
    await app.mockInput.pressEnter()
    await visible(app, "No Share import records")
    expect(queries).toContainEqual(["share", "imports", "--json"])
    await app.mockInput.pressEscape()
    await visible(app, "Share all Safes")
    expect(calls).toHaveLength(0)
  } finally { await app.dispose() }
})
