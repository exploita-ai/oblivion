import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { SafeManager } from "../src/safe-manager"
import { nativePreview, nativeStatus, type NativeStatus } from "../src/native-control"

const parent = "0123456789abcdef0123456789abcdef"
const child = "abcdef0123456789abcdef0123456789"
const provenance: NativeStatus["agent_safes"][number] = { id: child, parent, created_by_agent: true, agent: "claude", ephemeral: false, mib: 2048, state: "awaiting-start" }

async function visible(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(text)) return
    await Bun.sleep(5)
  }
  throw new Error(`Missing ${text}\n${app.captureCharFrame()}`)
}

test.each([[80, 24], [160, 50]])("agent-created Safes show lineage and require review before interactive launch at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {}, { agent_safes: [provenance], safe_parents: [{ id: child, parent }] })
  await fixture.run(["unlock"])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return 0 } }} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("└─ Development")
    expect(app.captureCharFrame()).toContain("Agent-created")
    await app.mockInput.pressEnter()
    await visible(app, "Review Safe · Development")
    const frame = app.captureCharFrame().replace(/\s+/g, " ")
    expect(frame).toContain("Parent · Research (01234567)")
    expect(frame).toContain("Requested client: Claude Code")
    expect(frame).toContain("Creation record · awaiting-start")
    expect(frame).not.toContain("Created by Claude")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Your Safes")
    expect(calls).toEqual([["run", "--safe", child, "claude"]])
  } finally { await app.dispose() }
})

test("choosing a different agent stays within the reviewed Safe and Back returns to its inspector", async () => {
  const fixture = nativePreview(() => {}, { agent_safes: [provenance], safe_parents: [{ id: child, parent }] })
  await fixture.run(["unlock"])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review Safe · Development")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Choose an agent")
    await app.mockInput.pressEscape()
    await visible(app, "Review Safe · Development")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Your Safes")
    expect(calls).toEqual([["run", "--safe", child, "opencode2"]])
  } finally { await app.dispose() }
})

test("imported parent relations do not fabricate local agent provenance", async () => {
  const fixture = nativePreview(() => {}, { safe_parents: [{ id: child, parent }] })
  await fixture.run(["unlock"])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey("d")
    await visible(app, "Review Safe · Development")
    expect(app.captureCharFrame()).toContain("No local agent-creation record")
    expect(app.captureCharFrame()).toContain("Parent · Research")
    expect(app.captureCharFrame()).not.toContain("Open requested agent")
    expect(app.captureCharFrame()).not.toContain("Agent-created")
    expect(calls).toHaveLength(0)
  } finally { await app.dispose() }
})

test.each(["failed", "recovery-required"] as const)("a %s creation record is visible but cannot launch a client", async (state) => {
  const fixture = nativePreview(() => {}, { sessions: [parent], agent_safes: [{ ...provenance, state }], safe_parents: [{ id: child, parent }] })
  await fixture.run(["unlock"])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review Safe · Development")
    expect(app.captureCharFrame()).toContain(`Creation record · ${state}`)
    expect(app.captureCharFrame()).toContain("Unavailable:")
    await app.mockInput.pressEnter()
    expect(calls).toHaveLength(0)
    await app.mockInput.pressEscape()
    await visible(app, "Your Safes")
    await app.mockInput.pressKey("w")
    expect(calls).toHaveLength(0)
  } finally { await app.dispose() }
})

test("a closed RAM child can launch only while its parent stays open", async () => {
  const fixture = nativePreview(() => {}, { sessions: [], agent_safes: [{ ...provenance, ephemeral: true, mib: 512 }] })
  await fixture.run(["ephemeral"])
  await fixture.run(["safe", "open", parent])
  const calls: string[][] = []
  const app = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review Safe · Development")
    expect(app.captureCharFrame()).toContain("RAM only")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Your Safes")
    expect(calls).toEqual([["run", "--safe", child, "claude"]])
  } finally { await app.dispose() }
  await fixture.run(["close", parent])
  const other = await testRender(() => <SafeManager runtime={{ ...fixture, run: async (args) => { calls.push(args); return 0 } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(other, "Your Safes")
    await other.mockInput.pressEnter()
    await visible(other, "Review Safe · Development")
    expect(other.captureCharFrame()).toContain("The parent Safe must stay open")
    await other.mockInput.pressEnter()
    expect(calls).toHaveLength(1)
  } finally { await other.dispose() }
})

test("current VM activity is separate from an awaiting-start creation journal", async () => {
  const fixture = nativePreview(() => {}, { agent_safes: [provenance] })
  await fixture.run(["unlock"])
  await fixture.run(["safe", "open", child])
  const app = await testRender(() => <SafeManager runtime={fixture} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review Safe · Development")
    expect(app.captureCharFrame()).toContain("Current · Open · Files VM")
    expect(app.captureCharFrame()).toContain("awaiting-start (not the current process state)")
    expect(app.captureCharFrame()).not.toContain("task is running")
  } finally { await app.dispose() }
})

test("the status boundary requires current agent metadata without synthesizing unsupported clients", async () => {
  const state = await nativePreview(() => {}).status()
  expect(nativeStatus.safeParse({ ...state, agent_safes: [{ ...provenance, agent: "unknown" }] }).success).toBe(false)
  expect(nativeStatus.safeParse({ ...state, agent_safes: [{ ...provenance, state: "running" }] }).success).toBe(false)
  const { agent_safes, ...missing } = state
  expect(agent_safes).toEqual([])
  expect(nativeStatus.safeParse(missing).success).toBe(false)
})
