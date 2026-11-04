import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { createSignal } from "solid-js"
import { testRender } from "@opentui/solid"
import { NativeFiles } from "../src/native-files"
import { createFileTransfers, fileInventory, type FileInventory } from "../src/native-file-transfers"
import { nativePreview } from "../src/native-control"

const safe = "0123456789abcdef0123456789abcdef"
const operation = "a".repeat(32)
const opening = "d".repeat(32)
const original = "e".repeat(32)
const row = (id = operation, name = "Recovered project") => ({ operation_id: id, source_opening: original, name })

async function fixture() {
  const base = nativePreview(() => {})
  await base.run(["unlock"])
  await base.run(["safe", "open", safe])
  const current = await base.status()
  const [nonce, setNonce] = createSignal(opening)
  const transfers = createFileTransfers()
  const queries: string[][] = []
  const commands: string[][] = []
  let state = "ready"
  let reply = async (args: string[]): Promise<unknown> => ({ safe_id: safe, opening: args[args.indexOf("--opening") + 1],
    direction: args.includes("--destination") ? "export" : "import", entries: [row()], next_cursor: null, skipped: 0 })
  const runtime = { ...base,
    status: async () => ({ ...current, idle_lock: { ...current.idle_lock, safes: current.idle_lock.safes.map((entry) => ({ ...entry, opening: { ...entry.opening, nonce: nonce() } })) } }),
    query: async (args: string[]) => {
      queries.push(args)
      if (args[1] === "transfers") return reply(args)
      if (args[1] !== "status") throw new Error("Unexpected query")
      const id = args[args.indexOf("--operation") + 1]!
      return { operation_id: id, safe_id: safe, opening: nonce(), source_opening: original, state,
        receipt: state === "discarded" ? null : { id, manifest_sha256: "f".repeat(64), entries: 3, bytes: 12 },
        can_recover: state === "ready", can_discard: state === "ready" }
    },
  }
  return { runtime, transfers, queries, commands, nonce, setNonce,
    respond(value: typeof reply) { reply = value },
    run: async (args: string[]) => { commands.push(args); if (args[1] === "recover") state = "published"; if (args[1] === "discard") state = "discarded"; return true },
  }
}

async function visible(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) { await app.renderOnce(); if (app.captureCharFrame().includes(text)) return; await Bun.sleep(5) }
  throw new Error(`Missing ${text}\n${app.captureCharFrame()}`)
}

async function inventory(app: Awaited<ReturnType<typeof testRender>>, ready = true) {
  await app.renderOnce()
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  if (ready) await visible(app, "File transfers")
}

test.each([[80, 24], [160, 50]])("receiver inventory finds an earlier opening without RAM sources and verifies status before recovery at %ix%i", async (width, height) => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await inventory(app)
    await visible(app, "Recovered project")
    expect(state.transfers.entries()).toEqual([])
    expect(state.commands).toEqual([])
    expect(state.queries).toEqual([["files", "transfers", "--safe", safe, "--opening", opening, "--limit", "8", "--json"]])
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
    await app.mockInput.pressEnter()
    await visible(app, "Recover verified copy")
    expect(state.queries.at(-1)).toEqual(["files", "status", "--safe", safe, "--operation", operation, "--opening", opening, "--json"])
    expect(app.captureCharFrame()).toContain("earlier opening")
    expect(app.captureCharFrame()).not.toContain("From ·")
    expect(app.captureCharFrame()).not.toContain("undefined")
    await app.mockInput.pressKey("c")
    await visible(app, "Publish verified copy?")
    expect(state.commands).toEqual([["safe", "open", safe]])
    await app.mockInput.pressEnter()
    await visible(app, "Copy completed and verified")
    expect(state.commands.at(-1)).toEqual(["files", "recover", "--safe", safe, "--operation", operation, "--opening", opening, "--json"])
    expect(state.queries.filter((args) => args[1] === "transfers")).toHaveLength(2)
    expect(state.transfers.entries()).toEqual([])
  } finally { await app.dispose() }
})

test("empty pages and a cursor beyond the last valid record remain navigable", async () => {
  const state = await fixture()
  const second = "b".repeat(32)
  const third = "e".repeat(32)
  state.respond(async (args) => {
    const after = args.includes("--cursor") ? args[args.indexOf("--cursor") + 1] : undefined
    return { safe_id: safe, opening, direction: "import", entries: !after ? [] : after === second ? [row("c".repeat(32), "Middle record")] : [row("f".repeat(32), "Last record")],
      next_cursor: !after ? second : after === second ? third : null, skipped: !after ? 2 : after === second ? 1 : 0 }
  })
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inventory(app)
    await visible(app, "No records for this Safe on this page")
    expect(app.captureCharFrame()).toContain("2 receiver records skipped")
    await app.mockInput.pressKeys(["\x1b[6~"])
    await visible(app, "Middle record")
    await app.mockInput.pressKeys(["\x1b[6~"])
    await visible(app, "Last record")
    expect(state.queries.at(-1)).toContain(third)
    await app.mockInput.pressKeys(["\x1b[5~"])
    await visible(app, "Middle record")
    expect(state.queries.at(-1)).toContain(second)
    expect(state.commands).toEqual([])
  } finally { await app.dispose() }
})

test("export discovery chooses a local folder and retains neither invented sources nor destination across an opening change", async () => {
  const state = await fixture()
  const folder = await mkdtemp(path.join(os.tmpdir(), "oblivion-export-records-"))
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inventory(app)
    await visible(app, "Recovered project")
    await app.mockInput.pressKey("e")
    await visible(app, "Find exported transfers")
    await app.mockInput.pressKey("p")
    await visible(app, "Enter local path")
    await app.mockInput.pasteBracketedText(folder)
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Review local path")
    await app.mockInput.pressEnter()
    await visible(app, "Recovered project")
    expect(state.queries.at(-1)).toEqual(["files", "transfers", "--safe", safe, "--opening", opening, "--destination", folder, "--limit", "8", "--json"])
    await app.mockInput.pressEnter()
    await visible(app, "Recover verified copy")
    expect(state.queries.at(-1)).toContain(folder)
    expect(app.captureCharFrame()).not.toContain("From ·")
    expect(state.transfers.entries()).toEqual([])
    state.setNonce("b".repeat(32))
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain(folder)
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
    await app.mockInput.pressKey("r")
    await visible(app, "Recovered project")
    expect(state.queries.at(-1)).not.toContain("--destination")
    expect(state.queries.at(-1)).toContain(state.nonce())
  } finally { await app.dispose(); await rm(folder, { recursive: true }) }
})

test("a late inventory from the previous opening cannot populate or authorize the new page", async () => {
  const state = await fixture()
  const pending = Promise.withResolvers<unknown>()
  const requested = Promise.withResolvers<void>()
  state.respond(async () => { requested.resolve(); return pending.promise })
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inventory(app, false)
    await requested.promise
    state.setNonce("b".repeat(32))
    await app.renderOnce()
    pending.resolve({ safe_id: safe, opening, direction: "import", entries: [row()], next_cursor: null, skipped: 0 })
    await visible(app, "Refresh to read")
    expect(app.captureCharFrame()).not.toContain("Recovered project")
    await app.mockInput.pressEnter()
    await app.mockInput.pressKey("c")
    expect(state.commands).toEqual([])
    expect(state.queries).toHaveLength(1)
  } finally { await app.dispose() }
})

test.each(["safe", "opening", "direction", "authority"])("invalid inventory %s cannot provide an operation to inspect", async (field) => {
  const state = await fixture()
  state.respond(async () => ({ safe_id: field === "safe" ? "b".repeat(32) : safe, opening: field === "opening" ? "b".repeat(32) : opening,
    direction: field === "direction" ? "export" : "import", entries: [row()], next_cursor: null, skipped: 0, ...(field === "authority" ? { can_recover: true } : {}) }))
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inventory(app)
    await visible(app, "Receiver records are unavailable")
    expect(app.captureCharFrame()).not.toContain("Recovered project")
    await app.mockInput.pressEnter()
    await app.mockInput.pressKey("c")
    expect(state.commands).toEqual([])
  } finally { await app.dispose() }
})

test("inventory preserves native publication spelling and rejects unordered IDs or extra rows", () => {
  const page: FileInventory = { safe_id: safe, opening, direction: "import", entries: [row(operation, "citta\u0300.txt")], next_cursor: "f".repeat(32), skipped: 3 }
  expect(fileInventory.parse(page).entries[0]?.name).toBe("citta\u0300.txt")
  expect(fileInventory.safeParse({ ...page, entries: [row("b".repeat(32)), row()] }).success).toBe(false)
  expect(fileInventory.safeParse({ ...page, entries: Array.from({ length: 9 }, (_, index) => row(index.toString().padStart(32, "0"))) }).success).toBe(false)
  expect(fileInventory.safeParse({ ...page, next_cursor: "0".repeat(32) }).success).toBe(false)
  expect(fileInventory.safeParse({ ...page, skipped: 0 }).success).toBe(false)
  expect(fileInventory.safeParse({ ...page, skipped: 16385 }).success).toBe(false)
})

test("receiver references stay separate from optional recent source details", async () => {
  const state = await fixture()
  state.transfers.remember({ id: operation, safe, opening: original, kind: "import", name: "Recovered project", destination: "workspace/Recovered project", sources: ["/private/local-source"] })
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inventory(app)
    await visible(app, "Recovered project")
    await app.mockInput.pressEnter()
    await visible(app, "Recover verified copy")
    expect(app.captureCharFrame()).not.toContain("/private/local-source")
    await app.mockInput.pressEscape()
    await app.mockInput.pressKey("m")
    await visible(app, "Recent operations")
    await app.mockInput.pressEnter()
    await visible(app, "/private/local-source")
  } finally { await app.dispose() }
})
