import { expect, test } from "bun:test"
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { createSignal, Show } from "solid-js"
import { testRender } from "@opentui/solid"
import { InputRenderable } from "@opentui/core"
import { NativeFiles } from "../src/native-files"
import { createFileTransfers } from "../src/native-file-transfers"
import { nativePreview } from "../src/native-control"
import type { FileCopyRequest, FileEvent, FileFinished, FileMappingEntry, NativeFileClient } from "../src/native-file-events"

const safe = "0123456789abcdef0123456789abcdef"
const opening = "d".repeat(32)
const digest = "f".repeat(64)

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "oblivion-copy-ui-"))
  const source = path.join(root, "project")
  await Promise.all([mkdir(path.join(source, "a"), { recursive: true }), mkdir(path.join(source, "b"), { recursive: true })])
  await Promise.all([writeFile(path.join(source, "zero.txt"), ""), writeFile(path.join(source, "a/note.txt"), "note"), writeFile(path.join(source, "b/code.txt"), "12345678")])
  const base = nativePreview(() => {})
  await base.run(["unlock"])
  const transfers = createFileTransfers()
  const commands: string[][] = []
  const queries: string[][] = []
  const approvals: string[] = []
  const requests: FileCopyRequest[] = []
  const started = Promise.withResolvers<void>()
  const approved = Promise.withResolvers<void>()
  const completion = Promise.withResolvers<{ code: number; finished?: FileFinished }>()
  const [nonce, setNonce] = createSignal<string | undefined>(opening)
  const [blocked, setBlocked] = createSignal<string>()
  let backendNonce = opening
  let emit = (_event: FileEvent) => {}
  let published = false
  let cancelled = 0
  let finished = false
  let cleanupFailed = false
  const request = () => { const value = requests[0]; if (!value) throw new Error("No copy started"); return value }
  const receipt = () => ({ id: request().identity.operation_id, manifest_sha256: digest, entries: 6, bytes: 12 })
  const files: NativeFileClient = {
    start(input, event) {
      requests.push(input); emit = event; started.resolve()
      return {
        async approve(hash) { approvals.push(hash); approved.resolve() },
        async cancel() {
          cancelled++
          if (cleanupFailed) throw new Error("Cleanup not confirmed")
          if (finished) return
          finished = true
          const event: FileFinished = { event: "finished", identity: input.identity, outcome: approvals.length ? "interrupted" : "cancelled-before-copy", receipt: null }
          emit(event); completion.resolve({ code: 130, finished: event })
        },
        done: completion.promise,
      }
    },
    async close() {},
  }
  const runtime = { ...base, files,
    status: async () => { const state = await base.status(); return { ...state, idle_lock: { ...state.idle_lock, safes: state.idle_lock.safes.map((safe) => ({ ...safe, opening: { ...safe.opening, nonce: backendNonce } })) } } },
    query: async (args: string[]) => { queries.push(args); return { operation_id: request().identity.operation_id, safe_id: safe, opening: backendNonce,
      source_opening: published ? request().identity.opening : null, state: published ? "published" : "unknown", receipt: published ? receipt() : null, can_recover: false, can_discard: false } },
  }
  return { root, source, runtime, transfers, commands, queries, approvals, requests, started: started.promise, approved: approved.promise, nonce, blocked, setBlocked,
    cancelled: () => cancelled,
    backend(value: string) { backendNonce = value },
    reopen(value: string) { backendNonce = value; setNonce(value) },
    review(entries: FileMappingEntry[] = request().sources.map((_, input_index) => ({ input_index, alias: "project", covered_by: null }))) {
      const selected = entries.length === 1 ? "project" : "selection"
      const mapping_sha256 = new Bun.CryptoHasher("sha256").update(JSON.stringify([selected, entries.map((entry) => [entry.input_index, entry.alias, entry.covered_by])])).digest("hex")
      emit({ event: "mapping", identity: request().identity, selected, start: 0, total: entries.length, entries, mapping_sha256 })
      emit({ event: "review", identity: request().identity, direction: request().direction, name: request().name, summary: { manifest_sha256: digest, mapping_sha256, entries: 6, files: 3, directories: entries.length === 1 ? 3 : 2, bytes: 12 } })
    },
    progress(bytes: number, phase: "copying" | "finalizing" = "copying") { emit({ event: "progress", identity: request().identity, phase, bytes, total_bytes: 12 }) },
    publish() { published = true },
    failCleanup() { cleanupFailed = true; completion.reject(new Error("Lost protocol")) },
    preparationFailed() { finished = true; const event: FileFinished = { event: "finished", identity: request().identity, outcome: "interrupted", receipt: null }; emit(event); completion.resolve({ code: 1, finished: event }) },
    finish(proof = true) { finished = true; const event: FileFinished = { event: "finished", identity: request().identity, outcome: "completed", receipt: receipt() }; if (proof) emit(event); completion.resolve({ code: proof ? 0 : 1, finished: proof ? event : undefined }) },
    run: async (args: string[]) => { commands.push(args); return await base.run(args) === 0 },
  }
}

async function visible(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) { await app.renderOnce(); if (app.captureCharFrame().includes(text)) return; await Bun.sleep(5) }
  throw new Error(`Missing ${text}\n${app.captureCharFrame()}`)
}

async function prepare(app: Awaited<ReturnType<typeof testRender>>, state: Awaited<ReturnType<typeof fixture>>) {
  await app.renderOnce()
  await app.mockInput.pressEnter()
  await visible(app, "Enter path")
  await app.mockInput.pressKey("p")
  await visible(app, "Enter local path")
  expect(app.renderer.currentFocusedRenderable).toBeInstanceOf(InputRenderable)
  await app.mockInput.pasteBracketedText(state.source)
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
  await visible(app, "Review local path")
  await app.mockInput.pressEnter()
  await visible(app, "1 selected")
  await app.mockInput.pressKey("c")
  await visible(app, "Name the imported copy")
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
  await state.started
  await visible(app, "Preparing recursive copy review")
}

test("USB selection waits for browser detachment before preparing the reviewed import", async () => {
  const state = await fixture()
  const device = { id: "a".repeat(64), name: "sdb1", bytes: 1024 ** 3, read_only: false }
  const released = Promise.withResolvers<void>()
  const requested = Promise.withResolvers<void>()
  const runtime = {
    ...state.runtime,
    async query(args: string[]) {
      if (args[0] === "runtime") return { version: 1, devices: [device] }
      return state.runtime.query(args)
    },
    usb: {
      open(id: string, selected: string, nonce: string) {
        expect([id, selected, nonce]).toEqual([safe, device.id, opening])
        return {
          async page() { return { path: "", next_cursor: null, entries: [{ name: "notes.md", path: "notes.md", kind: "file", bytes: 12 }] } },
          close() { requested.resolve(); return released.promise },
        }
      },
      async operate() { throw new Error("Import must not open USB export records") },
      async close() {},
    },
  }
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "sdb1")
    await app.mockInput.pressEnter()
    await visible(app, "notes.md")
    await app.mockInput.pressKey(" ")
    await visible(app, "1 selected")
    await app.mockInput.pressKey("c")
    await visible(app, "Disconnecting USB device")
    await requested.promise
    expect(state.requests).toHaveLength(0)
    released.resolve()
    await visible(app, "Name the imported copy")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Preparing recursive copy review")
    await state.started
    expect(state.requests[0]?.args).toContain(device.id)
    expect(state.requests[0]?.sources).toEqual(["notes.md"])
    expect(state.approvals).toHaveLength(0)
  } finally { released.resolve(); await app.dispose(); await rm(state.root, { recursive: true }) }
})

test("USB export reviews the Safe selection and displays the verified removal receipt", async () => {
  const state = await fixture()
  const device = { id: "a".repeat(64), name: "sdb1", bytes: 1024 ** 3, read_only: false }
  const runtime = {
    ...state.runtime,
    async query(args: string[]) {
      if (args[0] === "runtime") return { version: 1, devices: [device] }
      if (args[0] === "files" && args[1] === "list") {
        const inside = args.includes("workspace")
        return { path: inside ? "workspace" : "", next_cursor: null, entries: inside
          ? [{ name: "report.md", path: "workspace/report.md", kind: "file", bytes: 12 }]
          : [{ name: "workspace", path: "workspace", kind: "directory", bytes: 0 }] }
      }
      return state.runtime.query(args)
    },
    usb: {
      open() { throw new Error("Export must browse only Safe files") },
      async operate() { throw new Error("Export must not open USB export records") },
      async close() {},
    },
  }
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    for (let index = 0; index < 3; index++) await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "workspace/")
    await app.mockInput.pressEnter()
    await visible(app, "report.md")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await visible(app, "1 selected")
    await app.mockInput.pressKey("c")
    await visible(app, "sdb1")
    await app.mockInput.pressEnter()
    await visible(app, "Preparing recursive copy review")
    const request = state.requests[0]!
    expect(request.args).toContain(device.id)
    expect(request.args).not.toContain("--destination")
    expect(request.sources).toEqual(["workspace/report.md"])
    expect(request.name).toBe(`Oblivion-${request.identity.operation_id}`)
    state.review([{ input_index: 0, alias: "report.md", covered_by: null }])
    await visible(app, "Write to USB")
    expect(state.approvals).toHaveLength(0)
    await app.mockInput.pressEnter()
    await state.approved
    state.finish()
    await visible(app, "USB export verified and device released.")
    expect(state.queries).toHaveLength(0)
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})

test.each([[80, 24], [160, 50]])("recursive manifest approval and actual progress remain in the rendered Files page at %ix%i", async (width, height) => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await prepare(app, state)
    expect(state.approvals).toHaveLength(0)
    expect(state.commands).toEqual([["safe", "open", safe]])
    expect(state.transfers.entries()[0]?.id).toBe(state.requests[0]?.identity.operation_id)
    state.review()
    await visible(app, "Confirm import")
    expect(app.captureCharFrame()).toContain("3 selected files")
    expect(app.captureCharFrame()).toContain("3 selected folders")
    expect(app.captureCharFrame()).toContain("12 B total")
    expect(app.captureCharFrame()).toContain(digest)
    expect(state.approvals).toHaveLength(0)
    await app.mockInput.pressEnter()
    await state.approved
    state.progress(5)
    await visible(app, "5 B / 12 B transferred")
    expect(state.approvals).toEqual([digest])
    state.progress(12, "finalizing")
    await visible(app, "Finalizing copy")
    expect(app.captureCharFrame()).not.toContain("Copy completed")
    expect(app.captureCharFrame()).toContain("Cancel copy")
    state.publish(); state.finish()
    await visible(app, "Copy completed and verified.")
    expect(state.queries.at(-1)).toContain(state.requests[0]!.identity.operation_id)
    expect(state.commands.some((args) => args[0] === "files")).toBe(false)
  } finally { state.finish(false); await app.dispose(); await rm(state.root, { recursive: true }) }
})

test.each(["preparing", "review"])("Cancel during %s uses the no-contents proof without looking up a nonexistent receiver", async (phase) => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state)
    if (phase === "review") { state.review(); await visible(app, "Confirm import"); await app.mockInput.pressArrow("right"); await app.mockInput.pressEnter() }
    else await app.mockInput.pressEscape()
    await visible(app, "Cancelled before copying. No file contents were copied.")
    expect(state.cancelled()).toBe(1)
    expect(state.approvals).toHaveLength(0)
    expect(state.queries).toHaveLength(0)
    expect(state.transfers.entries()).toHaveLength(0)
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})

test("cancellation after payload progress reconciles an already published destination", async () => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state); state.review(); await visible(app, "Confirm import")
    await app.mockInput.pressEnter(); await state.approved
    state.progress(12, "finalizing"); await visible(app, "Finalizing copy")
    state.publish()
    await app.mockInput.pressEscape()
    await visible(app, "Copy completed and verified.")
    expect(state.queries).toHaveLength(1)
    expect(app.captureCharFrame()).not.toContain("No file contents were copied")
    expect(state.transfers.entries()).toHaveLength(1)
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})

test.each(["reopened", "stale-parent", "host-closing", "unmounted"])("%s cannot approve or leave its prepared copy running", async (scenario) => {
  const state = await fixture()
  const [mounted, setMounted] = createSignal(true)
  const app = await testRender(() => <Show when={mounted()}><NativeFiles safe={safe} name="Research" opening={state.nonce()} blocked={state.blocked()} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} /></Show>, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state); state.review(); await visible(app, "Confirm import")
    if (scenario === "reopened") state.reopen("b".repeat(32))
    if (scenario === "stale-parent") { state.backend("b".repeat(32)); await app.mockInput.pressEnter() }
    if (scenario === "host-closing") state.setBlocked("The host is closing and locking.")
    if (scenario === "unmounted") setMounted(false)
    await app.renderOnce()
    expect(state.cancelled()).toBe(1)
    expect(state.approvals).toHaveLength(0)
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})

test("a missing finished event cannot turn process exit into verified completion", async () => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state); state.review(); await visible(app, "Confirm import")
    await app.mockInput.pressEnter(); await state.approved
    state.finish(false)
    await visible(app, "Outcome unknown")
    expect(app.captureCharFrame()).not.toContain("Copy completed and verified")
    expect(state.queries).toHaveLength(1)
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})

test("periodic parent refresh with an unchanged opening does not cancel a live copy", async () => {
  const state = await fixture()
  const [tick, setTick] = createSignal(0)
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={(tick(), opening)} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state); state.review(); await visible(app, "Confirm import")
    setTick(1); await app.renderOnce()
    expect(state.cancelled()).toBe(0)
    await app.mockInput.pressEnter(); await state.approved
    state.progress(5); await visible(app, "5 B / 12 B transferred")
    setTick(2); await app.renderOnce()
    expect(state.cancelled()).toBe(0)
    expect(app.captureCharFrame()).toContain("5 B / 12 B transferred")
    state.publish(); state.finish()
    await visible(app, "Copy completed and verified.")
  } finally { state.finish(false); await app.dispose(); await rm(state.root, { recursive: true }) }
})

test("unconfirmed child cleanup retains the operation and fences new copy actions", async () => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state); state.review(); await visible(app, "Confirm import")
    await app.mockInput.pressEnter(); await state.approved
    state.failCleanup()
    await visible(app, "Copy cleanup is not confirmed")
    expect(state.transfers.entries()).toHaveLength(1)
    expect(state.queries).toHaveLength(0)
    await app.mockInput.pressEnter()
    expect(state.requests).toHaveLength(1)
    expect(app.captureCharFrame()).not.toContain("Copy completed")
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})

test("a validated preparation failure before approval does not imply a copied destination", async () => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await prepare(app, state)
    state.preparationFailed()
    await visible(app, "Preparation stopped before approval")
    expect(state.transfers.entries()).toHaveLength(0)
    expect(state.queries).toHaveLength(0)
    expect(state.approvals).toHaveLength(0)
    expect(app.captureCharFrame()).not.toContain("destination may already contain")
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})


test.each([[80, 24], [160, 50]])("collection review shows every backend alias and overlap without starting payload at %ix%i", async (width, height) => {
  const state = await fixture()
  const other = path.join(state.root, "elsewhere", "project")
  await mkdir(other, { recursive: true })
  await writeFile(path.join(other, "other.txt"), "other")
  const sources = [state.source, path.join(state.source, "a", "note.txt"), other]
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    for (const source of sources) {
      await visible(app, "Enter path")
      await app.mockInput.pressKey("p")
      await visible(app, "Enter local path")
      await app.mockInput.pressKey("u", { ctrl: true })
      await app.mockInput.pasteBracketedText(source)
      await app.mockInput.pressEnter()
      await app.mockInput.pressEnter()
      await visible(app, "Review local path")
      await app.mockInput.pressEnter()
    }
    await visible(app, "3 selected")
    expect(state.requests).toHaveLength(0)
    await app.mockInput.pressKey("c")
    await visible(app, "Name the collection")
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await state.started
    expect(state.requests[0]?.sources).toEqual(sources)
    expect(state.requests[0]?.args.slice(0, 12)).toEqual(["files", "import", "--safe", safe, "--source", sources[0]!, "--source", sources[1]!, "--source", sources[2]!, "--name", "Imported files"])
    expect(state.transfers.entries()[0]?.sources).toEqual(sources)
    state.review([{ input_index: 0, alias: "project", covered_by: null }, { input_index: 1, alias: null, covered_by: 0 }, { input_index: 2, alias: "project~2", covered_by: null }])
    await visible(app, "Confirm import")
    await app.mockInput.pressKeys(["\x1b[6~"])
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Included in selection 1")
    expect(app.captureCharFrame()).toContain("Imported files/project~2")
    expect(state.approvals).toHaveLength(0)
    expect(state.commands.every((args) => args[0] !== "files")).toBe(true)
    await app.mockInput.pressEnter()
    await state.approved
    expect(state.approvals).toEqual([digest])
    state.progress(5)
    await visible(app, "5 B / 12 B transferred")
    state.publish(); state.finish()
    await visible(app, "Copy completed and verified")
  } finally { await app.dispose(); await rm(state.root, { recursive: true }) }
})
