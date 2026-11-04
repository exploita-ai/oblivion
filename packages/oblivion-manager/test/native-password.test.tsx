import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { nativePreview } from "../src/native-control"
import { NativePassword } from "../src/native-password"
import { SafeManager } from "../src/safe-manager"

const host = "a".repeat(32)
const family = "f".repeat(32)
const transaction = "b".repeat(32)
const digest = "c".repeat(64)

function fixture(count = 3) {
  const members = Array.from({ length: count }, (_, index) => ({ safe_id: (index + 1).toString(16).padStart(32, "0"), title: `Family member ${String(index).padStart(2, "0")}` }))
  const [opening, setOpening] = createSignal<string | undefined>(host)
  const [openIds, setOpenIds] = createSignal<string[]>([])
  const [writable, setWritable] = createSignal(true)
  const [blocked, setBlocked] = createSignal<string>()
  const [sha, setSha] = createSignal(digest)
  const [valid, setValid] = createSignal(true)
  const [records, setRecords] = createSignal<{ transaction: string; family_id: string; members: typeof members; outcome: "pending" | "complete" | "rolled-back" }[]>([])
  const [code, setCode] = createSignal(0)
  const queries: string[][] = []
  const commands: string[][] = []
  const entry = (outcome: "pending" | "complete" | "rolled-back") => ({ transaction, family_id: family, members, outcome })
  const runtime = { ...nativePreview(() => {}), query: async (args: string[]) => {
    queries.push(args)
    if (!valid()) throw new Error("Unavailable")
    if (args[2] === "status") return { host_opening: host, transactions: records() }
    return { host_opening: host, family_id: family, members, sha256: sha() }
  } }
  return { members, opening, setOpening, openIds, setOpenIds, writable, setWritable, blocked, setBlocked, setSha, setValid, records, setRecords, code, setCode, queries, commands, entry, runtime,
    run: async (args: string[]) => { commands.push(args); setRecords([entry(code() === 0 ? args.at(-1) === "--rollback" ? "rolled-back" : "complete" : "pending")]); return code() } }
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

test.each([[80, 24], [160, 50]])("password review scrolls real family members and binds the exact plan at %ix%i", async (width, height) => {
  const state = fixture(40)
  state.setOpenIds(["e".repeat(32)])
  const app = await testRender(() => <NativePassword safe={{ id: state.members[0].safe_id, name: "Research", persistent: true, closed: true }} opening={state.opening()} openIds={state.openIds()} writable={state.writable()} runtime={state.runtime} run={state.run} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "40 local family member(s)")
    expect(app.captureCharFrame()).toContain("Family member 00")
    expect(app.captureCharFrame()).not.toContain("Family member 39")
    expect(app.captureCharFrame()).toContain("Change password")
    for (let index = 0; index < 39; index++) await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Family member 39")
    expect(app.captureCharFrame()).toContain(state.members[39].safe_id)
    expect(app.captureCharFrame()).not.toContain("Family member 00")
    expect(state.commands).toHaveLength(0)
    await app.mockInput.pressKey("c")
    await visible(app, "Change family password?")
    expect(state.queries).toEqual([
      ["safe", "password", "status", "--json"], ["safe", "password", "preview", state.members[0].safe_id, "--json"],
      ["safe", "password", "status", "--json"], ["safe", "password", "preview", state.members[0].safe_id, "--json"],
    ])
    expect(app.captureCharFrame()).toContain("No password is collected")
    await app.mockInput.pressEnter()
    await visible(app, "Complete · read-only")
    expect(state.commands).toEqual([["safe", "password", state.members[0].safe_id, "--confirmed-plan", digest]])
    expect(state.queries.at(-1)).toEqual(["safe", "password", "status", "--json"])
    await app.mockInput.pressEnter()
    await visible(app, "affected local Safe(s)")
    await app.mockInput.pressEscape()
    await visible(app, "Password recovery")
    await app.mockInput.pressEscape()
    await visible(app, "Family member 00")
    await app.mockInput.pressKey("c")
    await visible(app, "Change family password?")
    await app.mockInput.pressEscape()
    await visible(app, "40 local family member(s)")
    expect(app.captureCharFrame()).not.toContain("affected local Safe(s)")
    expect(state.commands).toHaveLength(1)
  } finally { await app.dispose() }
})

test("a changed plan must be reviewed again and cannot use an old confirmation digest", async () => {
  const state = fixture()
  const app = await testRender(() => <NativePassword safe={{ id: state.members[0].safe_id, name: "Research", persistent: true, closed: true }} opening={host} openIds={[]} writable runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Family member 00")
    state.setSha("d".repeat(64))
    await app.mockInput.pressKey("c")
    await visible(app, "The family review changed")
    expect(app.captureCharFrame()).not.toContain("Change family password?")
    expect(state.commands).toHaveLength(0)
    await app.mockInput.pressKey("c")
    await visible(app, "Change family password?")
    state.setSha("e".repeat(64))
    await app.mockInput.pressEnter()
    await visible(app, "The reviewed operation changed")
    expect(state.commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("global barriers and every open family member prevent confirmation from mutating", async () => {
  const state = fixture()
  const app = await testRender(() => <NativePassword safe={{ id: state.members[0].safe_id, name: "Research", persistent: true, closed: true }} opening={host} openIds={state.openIds()} writable blocked={state.blocked()} runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Family member 00")
    await app.mockInput.pressKey("c")
    await visible(app, "Change family password?")
    state.setBlocked("Host is closing.")
    await app.mockInput.pressEnter()
    await visible(app, "The reviewed operation is no longer available")
    expect(state.commands).toHaveLength(0)
    state.setBlocked(undefined)
    state.setOpenIds([state.members[1].safe_id])
    await app.mockInput.pressEnter()
    await visible(app, "The reviewed operation is no longer available")
    expect(state.commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("Settings can recover a password-fenced Safe without opening an agent at %ix%i", async (width, height) => {
  const safe = "0123456789abcdef0123456789abcdef"
  const fixture = nativePreview(() => {}, { family_password_pending: [safe] })
  await fixture.run(["unlock"])
  const initial = await fixture.status()
  const commands: string[][] = []
  const runtime = { ...fixture, query: async (args: string[]) => args[0] === "safe" && args[1] === "password" && args[2] === "status"
    ? { host_opening: initial.idle_lock.host!.nonce, transactions: [{ transaction, family_id: family, members: [{ safe_id: safe, title: "Research" }], outcome: "pending" }] }
    : fixture.query(args), run: async (args: string[]) => { commands.push(args); return fixture.run(args) } }
  const app = await testRender(() => <SafeManager initial={initial} runtime={runtime} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "Password recovery")
    await app.mockInput.pressEnter()
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("pending password change")
    expect(app.captureCharFrame()).not.toContain("Choose an agent")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressKey("\x1bOQ")
    for (let index = 0; index < 7; index++) await app.mockInput.pressArrow("down")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Family passwords")
    await app.mockInput.pressEnter()
    await visible(app, "This family has a pending password update")
    await app.mockInput.pressKey("t")
    await visible(app, "Pending · recovery required")
    await app.mockInput.pressEnter()
    await visible(app, "affected local Safe(s)")
    expect(app.captureCharFrame()).toContain("Research")
    expect(app.captureCharFrame()).toContain("Complete")
    expect(app.captureCharFrame()).toContain("Roll back")
    expect(commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test.each(["complete", "rollback"] as const)("pending recovery requires member review and fresh status before %s", async (direction) => {
  const state = fixture()
  state.setRecords([state.entry("pending")])
  state.setOpenIds(["e".repeat(32)])
  const app = await testRender(() => <NativePassword safe={{ id: state.members[0].safe_id, name: "Research", persistent: true, closed: true }} opening={host} openIds={state.openIds()} writable runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "This family has a pending password update")
    await app.mockInput.pressKey("c")
    expect(state.commands).toHaveLength(0)
    await app.mockInput.pressKey("t")
    await visible(app, "Pending · recovery required")
    await app.mockInput.pressEnter()
    await visible(app, "affected local Safe(s)")
    expect(app.captureCharFrame()).toContain("Family member 00")
    await app.mockInput.pressKey(direction === "complete" ? "c" : "b")
    await visible(app, direction === "complete" ? "Complete password update?" : "Roll back password update?")
    await app.mockInput.pressEnter()
    await visible(app, direction === "complete" ? "Complete · read-only" : "Rolled back · read-only")
    expect(state.commands).toEqual([["safe", "password", "recover", transaction, direction === "complete" ? "--complete" : "--rollback"]])
    expect(state.queries.filter((args) => args[2] === "preview")).toHaveLength(0)
    expect(state.queries.at(-1)).toEqual(["safe", "password", "status", "--json"])
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("completed transactions are inspectable and read-only at %ix%i", async (width, height) => {
  const state = fixture()
  state.setRecords([state.entry("complete")])
  const app = await testRender(() => <NativePassword opening={host} openIds={[]} writable={state.writable()} runtime={state.runtime} run={state.run} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "Choose a persistent Safe")
    await app.mockInput.pressKey("t")
    await visible(app, "Complete · read-only")
    await app.mockInput.pressEnter()
    await visible(app, "Family member 00")
    expect(app.captureCharFrame()).toContain("This finished transaction is read-only")
    state.setWritable(false)
    await app.mockInput.pressKey("c")
    await app.mockInput.pressKey("b")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("These records are read-only")
    expect(app.captureCharFrame()).not.toContain("Continue privately")
    expect(state.commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("status failure and a new host opening remove authority instead of using cached review", async () => {
  const state = fixture()
  const app = await testRender(() => <NativePassword safe={{ id: state.members[0].safe_id, name: "Research", persistent: true, closed: true }} opening={state.opening()} openIds={[]} writable runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Family member 00")
    state.setValid(false)
    await app.mockInput.pressKey("c")
    await visible(app, "Password information is unavailable")
    expect(app.captureCharFrame()).not.toContain("Family member 00")
    expect(state.commands).toHaveLength(0)
    state.setValid(true)
    await app.mockInput.pressKey("r")
    await visible(app, "Family member 00")
    await app.mockInput.pressKey("c")
    await visible(app, "Change family password?")
    state.setOpening("e".repeat(32))
    await visible(app, "Password information is unavailable")
    await app.mockInput.pressEnter()
    expect(app.captureCharFrame()).not.toContain("Continue privately")
    expect(state.commands).toHaveLength(0)
  } finally { await app.dispose() }
})

test("exit130 and a lost change response require authoritative pending recovery, not an automatic retry", async () => {
  const state = fixture()
  state.setCode(130)
  const app = await testRender(() => <NativePassword safe={{ id: state.members[0].safe_id, name: "Research", persistent: true, closed: true }} opening={host} openIds={[]} writable runtime={state.runtime} run={state.run} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Family member 00")
    await app.mockInput.pressKey("c")
    await visible(app, "Change family password?")
    await app.mockInput.pressEnter()
    await visible(app, "Pending · recovery required")
    expect(app.captureCharFrame()).toContain("interrupted or not completed")
    expect(app.captureCharFrame()).not.toContain("Complete · read-only")
    expect(state.commands).toHaveLength(1)
    await app.mockInput.pressEnter()
    await visible(app, "Family member 00")
    expect(state.commands).toHaveLength(1)
    expect(state.queries.at(-1)).toEqual(["safe", "password", "status", "--json"])
  } finally { await app.dispose() }
})
