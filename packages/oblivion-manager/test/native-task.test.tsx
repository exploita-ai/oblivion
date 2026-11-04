import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { NativeTask, taskStatus } from "../src/native-task"
import { nativePreview, type NativeStatus } from "../src/native-control"
import { SafeManager } from "../src/safe-manager"

const parent = "0123456789abcdef0123456789abcdef"
const safe = "abcdef0123456789abcdef0123456789"
const request = "e".repeat(32)
const task = "Sensitive canary · città\nRead workspace/project.\tLiteral ESC: \x1b[31m and direction: \u202e."
const origin: NativeStatus["agent_safes"][number] = { id: safe, parent, created_by_agent: true, agent: "claude", ephemeral: false, mib: 2048, state: "awaiting-start" }

function status(state?: "queued" | "running" | "completed" | "failed" | "cancelled") {
  return taskStatus.parse({ version: 1, safe_id: safe, agent: "claude", request_id: request,
    attempt_request_id: state ? request : null, attempts: state ? 1 : 0, attempt_limit: 16,
    phase: state ? "submitted" : "not-started",
    job: state ? { job_id: "a".repeat(32), request_id: request, agent: "claude", state, native_chat_id: "12345678-1234-4234-8234-123456789abc", reason: state === "failed" ? "needs-auth" : null } : null,
    can_start: !state, can_retry: state === "failed" || state === "cancelled", can_cancel: state === "queued" || state === "running", blocked: null })
}

async function opened() {
  const fixture = nativePreview(() => {}, { agent_safes: [origin], safe_parents: [{ id: safe, parent }] })
  await fixture.run(["unlock"])
  await fixture.run(["safe", "open", safe])
  return fixture
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

test.each([[80, 24], [160, 50]])("saved task review is explicit, literal and never enters process arguments at %ix%i", async (width, height) => {
  const fixture = await opened()
  const current = await fixture.status()
  const [response, setResponse] = createSignal(status())
  const queries: string[][] = []
  const commands: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => { queries.push(args); return args[2] === "review" ? { status: response(), task } : response() } }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current} safe={safe} name="Development" back={() => {}} run={async (args) => { commands.push(args); setResponse(status("running")); return 0 }} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "Task · not started")
    expect(queries).toEqual([["safe", "task", "status", safe, "--json"]])
    expect(app.captureCharFrame()).not.toContain("Sensitive canary")
    await app.mockInput.pressEnter()
    await visible(app, "Review saved task")
    expect(app.captureCharFrame()).toContain("Sensitive canary")
    expect(app.captureCharFrame()).toContain("\\u001b[31m")
    expect(app.captureCharFrame()).toContain("\\u202e")
    expect(app.captureCharFrame()).toContain("\\u0009")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressKey("s")
    await visible(app, "Task · running")
    expect(app.captureCharFrame()).not.toContain("Sensitive canary")
    expect(commands).toEqual([["safe", "task", "start", safe, "--request", request, "--json"]])
    expect(commands.flat().join(" ")).not.toContain("Read workspace")
    expect(queries.filter((args) => args[2] === "review")).toHaveLength(1)
    await app.mockInput.pressKey("j")
    await visible(app, "Managed job · Development")
    expect(app.captureCharFrame()).toContain("Job: " + "a".repeat(32))
    expect(app.captureCharFrame()).toContain("Request: " + request)
    expect(app.captureCharFrame()).toContain("Agent: claude")
    expect(app.captureCharFrame()).toContain("State: running")
    expect(app.captureCharFrame()).toContain("Native chat: 12345678-1234-4234-8234-123456789abc")
    expect(app.captureCharFrame()).toContain("Reason: None")
    await app.mockInput.pressEscape()
    await visible(app, "Task · running")
  } finally { await app.dispose() }
})

test("start routes through review and native login sends no task before authoritative refresh", async () => {
  const fixture = await opened()
  const current = await fixture.status()
  const commands: string[][] = []
  const queries: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => { queries.push(args); return args[2] === "review" ? { status: status(), task } : status() } }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current} safe={safe} name="Development" back={() => {}} run={async (args) => { commands.push(args); return 0 }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Task · not started")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review saved task")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressKey("a")
    await visible(app, "Client closed")
    expect(commands).toEqual([["run", "--safe", safe, "claude"]])
    expect(app.captureCharFrame()).not.toContain("Sensitive canary")
    expect(app.captureCharFrame()).toContain("Task · not started")
    expect(queries.at(-1)).toEqual(["safe", "task", "status", safe, "--json"])
  } finally { await app.dispose() }
})

test("retry requires task review and confirmation and then shows the new actual attempt", async () => {
  const fixture = await opened()
  const current = await fixture.status()
  const [response, setResponse] = createSignal(status("failed"))
  const commands: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => args[2] === "review" ? { status: response(), task } : response() }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current} safe={safe} name="Development" back={() => {}} run={async (args) => {
    commands.push(args)
    setResponse({ ...status("running"), attempts: 2, attempt_request_id: "f".repeat(32), job: { ...status("running").job!, request_id: "f".repeat(32) } })
    return 0
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "needs-auth")
    for (let index = 0; index < 3; index++) await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review saved task")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressKey("s")
    await visible(app, "Retry saved task?")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Task · running")
    expect(app.captureCharFrame()).toContain("Attempt 2/16")
    expect(commands).toEqual([["safe", "task", "retry", safe, "--request", request, "--json"]])
  } finally { await app.dispose() }
})

test("cancel never claims success from exit130 and refreshes the managed result", async () => {
  const fixture = await opened()
  const current = await fixture.status()
  const [response, setResponse] = createSignal(status("running"))
  const [code, setCode] = createSignal(130)
  const commands: string[][] = []
  const runtime = { ...fixture, query: async () => response() }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current} safe={safe} name="Development" back={() => {}} run={async (args) => { commands.push(args); if (code() === 0) setResponse(status("cancelled")); return code() }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Task · running")
    for (let index = 0; index < 3; index++) await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Cancel running task?")
    await app.mockInput.pressEscape()
    await visible(app, "Task · running")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Cancel running task?")
    await app.mockInput.pressEnter()
    await visible(app, "Command interrupted")
    expect(app.captureCharFrame()).toContain("Task · running")
    expect(app.captureCharFrame()).not.toContain("Task · cancelled")
    setCode(0)
    await app.mockInput.pressEnter()
    await visible(app, "Cancel running task?")
    await app.mockInput.pressEnter()
    await visible(app, "Task · cancelled")
    expect(commands).toEqual(Array.from({ length: 2 }, () => ["safe", "task", "cancel", safe, "--request", request, "--json"]))
  } finally { await app.dispose() }
})

test("a changed opening or invalid status clears plaintext and removes stale actions", async () => {
  const fixture = await opened()
  const [current, setCurrent] = createSignal(await fixture.status())
  const [valid, setValid] = createSignal(true)
  const commands: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => args[2] === "review" ? { status: status(), task } : valid() ? status() : { ...status(), version: 0 } }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current()} safe={safe} name="Development" back={() => {}} run={async (args) => { commands.push(args); return 0 }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Task · not started")
    await app.mockInput.pressEnter()
    await visible(app, "Sensitive canary")
    setValid(false)
    await app.mockInput.pressKey("r")
    await visible(app, "Saved task status is unavailable")
    expect(app.captureCharFrame()).not.toContain("Sensitive canary")
    await app.mockInput.pressEnter()
    expect(commands).toHaveLength(0)
    setValid(true)
    await app.mockInput.pressKey("r")
    await visible(app, "Task · not started")
    await app.mockInput.pressEnter()
    await visible(app, "Sensitive canary")
    setCurrent((before) => ({ ...before, app_open: false, open_sessions: [], idle_lock: { ...before.idle_lock, host: null, safes: [] } }))
    await visible(app, "This Safe is locked")
    expect(app.captureCharFrame()).not.toContain("Sensitive canary")
    await app.mockInput.pressKey("s")
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("late plaintext review cannot survive its Safe's lock", async () => {
  const fixture = await opened()
  const [current, setCurrent] = createSignal(await fixture.status())
  const pending = Promise.withResolvers<unknown>()
  const runtime = { ...fixture, query: async (args: string[]) => args[2] === "review" ? pending.promise : status() }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current()} safe={safe} name="Development" back={() => {}} run={async () => 0} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Task · not started")
    await app.mockInput.pressEnter()
    setCurrent((before) => ({ ...before, app_open: false, open_sessions: [], idle_lock: { ...before.idle_lock, host: null, safes: [] } }))
    pending.resolve({ status: status(), task })
    await visible(app, "This Safe is locked")
    expect(app.captureCharFrame()).not.toContain("Sensitive canary")
    expect(app.captureCharFrame()).not.toContain("Review saved task ·")
  } finally { pending.resolve({ status: status(), task }); await app.dispose() }
})

test.each([[80, 24], [160, 50]])("manager opens task review offline and retains host navigation at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {}, { agent_safes: [origin], safe_parents: [{ id: safe, parent }] })
  await fixture.run(["unlock"])
  const commands: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => args[0] === "safe" ? args[2] === "review" ? { status: status(), task: Array.from({ length: 50 }, (_, index) => `Task line ${index}`).join("\n") } : status() : fixture.query(args), run: async (args: string[]) => { commands.push(args); return fixture.run(args) } }
  const app = await testRender(() => <SafeManager runtime={runtime} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "Your Safes")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "Review Safe · Development")
    await app.mockInput.pressEnter()
    await visible(app, "Saved task · Development")
    expect(commands).toEqual([["safe", "open", safe]])
    await app.mockInput.pressEnter()
    await visible(app, "Review saved task · Development")
    expect(app.captureCharFrame()).toContain("OBLIVION")
    expect(app.captureCharFrame()).toContain("Network")
    expect(app.captureCharFrame()).toContain("Lock Oblivion")
    expect(app.captureCharFrame()).toContain("Task line 0")
    await app.mockInput.pressKey("\u001b[6~")
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Task line 0")
    await app.mockInput.pressEscape()
    await visible(app, "Saved task · Development")
    expect(app.captureCharFrame()).not.toContain("Task line 0")
    await app.mockInput.pressEscape()
    await visible(app, "Review Safe · Development")
  } finally { await app.dispose() }
})

test("task status rejects a foreign attempt or a false retry capability", () => {
  expect(taskStatus.safeParse({ ...status("running"), attempt_request_id: "f".repeat(32) }).success).toBe(false)
  expect(taskStatus.safeParse({ ...status("running"), can_retry: true }).success).toBe(false)
  expect(taskStatus.safeParse({ ...status("completed"), can_cancel: true }).success).toBe(false)
  expect(taskStatus.safeParse({ ...status(), unexpected: true }).success).toBe(false)
  expect(taskStatus.safeParse({ ...status("running"), phase: "unknown" }).success).toBe(false)
})

test("an unknown attempt is reconciled with its existing identity instead of offering a retry", async () => {
  const fixture = await opened()
  const current = await fixture.status()
  const [response, setResponse] = createSignal(taskStatus.parse({ ...status(), phase: "unknown", attempts: 1, attempt_request_id: request }))
  const commands: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => args[2] === "review" ? { status: response(), task } : response() }
  const app = await testRender(() => <NativeTask runtime={runtime} state={current} safe={safe} name="Development" back={() => {}} run={async (args) => { commands.push(args); setResponse(status("completed")); return 0 }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "outcome not yet observed")
    expect(app.captureCharFrame()).toContain("Start or reconcile saved task")
    expect(app.captureCharFrame()).not.toContain("Retry failed task")
    await app.mockInput.pressEnter()
    await visible(app, "Review saved task")
    await app.mockInput.pressKey("s")
    await visible(app, "Task · completed")
    expect(commands).toEqual([["safe", "task", "start", safe, "--request", request, "--json"]])
    expect(app.captureCharFrame()).toContain("Attempt 1/16")
  } finally { await app.dispose() }
})
