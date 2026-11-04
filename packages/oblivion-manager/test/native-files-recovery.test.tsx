import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal, Show } from "solid-js"
import { NativeFiles } from "../src/native-files"
import { createFileTransfers, type FileOutcome } from "../src/native-file-transfers"
import { nativePreview } from "../src/native-control"

const safe = "0123456789abcdef0123456789abcdef"
const operation = "a".repeat(32)
const opening = "d".repeat(32)
const receipt = { id: operation, manifest_sha256: "f".repeat(64), entries: 3, bytes: 1024 }

async function fixture() {
  const preview = nativePreview(() => {})
  await preview.run(["unlock"])
  await preview.run(["safe", "open", safe])
  const current = await preview.status()
  const [nonce, setNonce] = createSignal(opening)
  const [blocked, setBlocked] = createSignal<string>()
  const transfers = createFileTransfers()
  transfers.remember({ id: operation, safe, opening, kind: "export", source: "workspace/project", destination: "/tmp/explicit-export" })
  const commands: string[][] = []
  const queries: string[][] = []
  let response: FileOutcome = { operation_id: operation, safe_id: safe, opening, source_opening: opening, state: "ready", receipt, can_recover: true, can_discard: true }
  let fail = false
  let onRun = (_args: string[]) => {}
  const runtime = { ...preview,
    status: async () => ({ ...current, idle_lock: { ...current.idle_lock, safes: current.idle_lock.safes.map((entry) => ({ ...entry, opening: { ...entry.opening, nonce: nonce() } })) } }),
    query: async (args: string[]) => { queries.push(args); if (fail) throw new Error("Lost response"); return response },
  }
  return { transfers, commands, queries, runtime, nonce, setNonce, blocked, setBlocked,
    setResponse(value: Partial<FileOutcome>) { response = { ...response, ...value } },
    fail() { fail = true }, onRun(run: typeof onRun) { onRun = run },
    run: async (args: string[]) => { commands.push(args); onRun(args); return args[0] !== "files" },
  }
}

async function visible(app: Awaited<ReturnType<typeof testRender>>, value: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(value)) return
    await Bun.sleep(5)
  }
  throw new Error(`Missing ${value}\n${app.captureCharFrame()}`)
}

async function inspect(app: Awaited<ReturnType<typeof testRender>>) {
  await app.renderOnce()
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressArrow("down")
  await app.mockInput.pressEnter()
  await visible(app, "File transfers")
  await app.mockInput.pressEnter()
}

test.each([[80, 24], [160, 50]])("verified recovery uses the original operation and explicit destination at %ix%i", async (width, height) => {
  const state = await fixture()
  state.onRun((args) => { if (args[0] === "files") state.setResponse({ state: "published", can_recover: false, can_discard: false }) })
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await inspect(app)
    await visible(app, "publication unconfirmed")
    expect(app.captureCharFrame()).toContain(operation)
    expect(app.captureCharFrame()).toContain("/tmp/explicit-export")
    await app.mockInput.pressKey("c")
    await visible(app, "Publish verified copy?")
    expect(state.commands).toEqual([["safe", "open", safe]])
    await app.mockInput.pressEnter()
    await visible(app, "Copy completed and verified.")
    expect(state.commands.at(-1)).toEqual(["files", "recover", "--safe", safe, "--operation", operation, "--opening", opening, "--destination", "/tmp/explicit-export", "--json"])
    expect(state.queries.every((args) => args.join(" ") === ["files", "status", "--safe", safe, "--operation", operation, "--opening", opening, "--destination", "/tmp/explicit-export", "--json"].join(" "))).toBe(true)
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
    expect(app.captureCharFrame()).not.toContain("Discard staging")
  } finally { await app.dispose() }
})

test.each(["unknown", "unavailable", "wrong-safe", "wrong-operation", "wrong-opening", "wrong-source", "invalid-authority", "missing-source", "empty-receipt"])("%s copy status never grants recovery or claims the destination is unchanged", async (scenario) => {
  const state = await fixture()
  if (scenario === "unknown") state.setResponse({ state: "unknown", source_opening: null, receipt: null, can_recover: false, can_discard: false })
  if (scenario === "unavailable") state.fail()
  if (scenario === "wrong-safe") state.setResponse({ safe_id: "b".repeat(32) })
  if (scenario === "wrong-operation") state.setResponse({ operation_id: "b".repeat(32) })
  if (scenario === "wrong-opening") state.setResponse({ opening: "b".repeat(32) })
  if (scenario === "invalid-authority") state.setResponse({ state: "unknown", receipt: null })
  if (scenario === "wrong-source") state.setResponse({ source_opening: "b".repeat(32) })
  if (scenario === "missing-source") state.setResponse({ state: "published", source_opening: null, can_recover: false, can_discard: false })
  if (scenario === "empty-receipt") state.setResponse({ receipt: { ...receipt, entries: 0 } })
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inspect(app)
    await visible(app, "Outcome unknown")
    expect(app.captureCharFrame()).not.toContain("destination was not replaced")
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
    expect(app.captureCharFrame()).not.toContain("Discard staging")
    await app.mockInput.pressKey("c")
    await app.mockInput.pressKey("d")
    expect(state.commands).toEqual([["safe", "open", safe]])
  } finally { await app.dispose() }
})

test("a changed outcome at confirmation never replays or discards a published copy", async () => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inspect(app)
    await visible(app, "Recover verified copy")
    await app.mockInput.pressKey("c")
    await visible(app, "Publish verified copy?")
    state.setResponse({ state: "published", can_recover: false, can_discard: false })
    await app.mockInput.pressEnter()
    await visible(app, "The recorded outcome changed")
    expect(app.captureCharFrame()).toContain("Copy completed and verified.")
    expect(state.commands).toEqual([["safe", "open", safe]])
  } finally { await app.dispose() }
})

test("incomplete staging can only be discarded after an explicit current review", async () => {
  const state = await fixture()
  state.setResponse({ state: "incomplete", receipt: null, can_recover: false, can_discard: true })
  state.onRun((args) => { if (args[0] === "files") state.setResponse({ state: "discarded", can_recover: false, can_discard: false }) })
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inspect(app)
    await visible(app, "Copy incomplete")
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
    await app.mockInput.pressKey("d")
    await visible(app, "Discard incomplete copy?")
    expect(state.commands).toHaveLength(1)
    await app.mockInput.pressEnter()
    await visible(app, "Private staging discarded")
    expect(state.commands.at(-1)).toEqual(["files", "discard", "--safe", safe, "--operation", operation, "--opening", opening, "--destination", "/tmp/explicit-export", "--json"])
  } finally { await app.dispose() }
})

test("a reopened Safe drops old positive authority and confirms against its fresh opening", async () => {
  const state = await fixture()
  const app = await testRender(() => <NativeFiles safe={safe} name="Research" opening={state.nonce()} transfers={state.transfers} blocked={state.blocked()} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inspect(app)
    await visible(app, "Recover verified copy")
    await app.mockInput.pressKey("c")
    await visible(app, "Publish verified copy?")
    state.setNonce("b".repeat(32))
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Publish verified copy?")
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
    await app.mockInput.pressKey("c")
    expect(state.commands).toHaveLength(1)
    state.setResponse({ opening: state.nonce() })
    await app.mockInput.pressKey("r")
    await visible(app, "Recover verified copy")
    expect(state.queries.at(-1)).toContain(state.nonce())
    expect(app.captureCharFrame()).toContain("earlier opening")
    await app.mockInput.pressKey("c")
    await visible(app, "Publish verified copy?")
    state.setBlocked("The Safe is closing and locking.")
    await app.mockInput.pressEnter()
    expect(state.commands).toHaveLength(1)
  } finally { await app.dispose() }
})

test("operation IDs and destinations survive leaving Files but are explicitly cleared by the owner", async () => {
  const state = await fixture()
  const [mounted, setMounted] = createSignal(true)
  const app = await testRender(() => <Show when={mounted()}><NativeFiles safe={safe} name="Research" opening={opening} transfers={state.transfers} runtime={state.runtime} run={state.run} back={() => {}} /></Show>, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await inspect(app)
    await visible(app, "Recover verified copy")
    setMounted(false)
    await app.renderOnce()
    setMounted(true)
    await inspect(app)
    await visible(app, "Recover verified copy")
    expect(state.transfers.entries()).toHaveLength(1)
    state.transfers.clear()
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain(operation)
    expect(app.captureCharFrame()).not.toContain("Recover verified copy")
  } finally { await app.dispose() }
})

test("recent copy metadata remains bounded and clears when its manager owner locks", () => {
  const transfers = createFileTransfers()
  for (let index = 0; index < 40; index++) transfers.remember({ id: index.toString(16).padStart(32, "0"), safe, opening, kind: "export", source: "workspace/project", destination: "/tmp/explicit-export" })
  expect(transfers.entries()).toHaveLength(32)
  expect(transfers.entries()[0]?.id).toBe((39).toString(16).padStart(32, "0"))
  transfers.clear()
  expect(transfers.entries()).toHaveLength(0)
})
