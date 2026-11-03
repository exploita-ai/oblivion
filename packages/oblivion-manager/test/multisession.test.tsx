import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App, type Runtime } from "../src/app"
import { preview } from "../src/preview"
import { status, type Status } from "../src/state"
import { ControlError, type Request } from "../src/control"
import { createSignal } from "solid-js"
import { SessionTabs, sessionSocket } from "../src/session-tabs"
import type { ChatConnect } from "../src/chat"

async function fixture(closeWarning = false) {
  const base = status.parse(JSON.parse(await preview(() => {}).request({ operation: "status" })))
  const sessions = new Map<number, Status>([1, 2, 3].map((slot) => [slot, {
    ...structuredClone(base), slot, session_open: true, active_session: String(slot).repeat(32), session_mode: "chat" as const,
    settings: { saved: null, current: { ...base.settings!.current, web_access: slot === 2 ? "strict" as const : "open" as const } },
    egress: { selected: slot === 2 ? { mode: "socks5" as const, endpoint: "127.0.0.1:9050", authenticated: false } : { mode: "tor" as const }, temporary: false, saved: { mode: "tor" as const } },
  } satisfies Status]))
  const requests: Request[] = []
  const connected: number[] = []
  const detached: number[] = []
  const frames = new Map<number, Parameters<ChatConnect>[0]>()
  const snapshot = (slot: number) => ({ ...base, ...sessions.get(slot), slot, session_slot_limit: 32,
    session_titles: { ["1".repeat(32)]: "Alpha", ["2".repeat(32)]: "Beta", ["3".repeat(32)]: "Gamma" },
    sessions: ["1".repeat(32), "2".repeat(32), "3".repeat(32)],
    open_sessions: [...sessions].map(([slot, current]) => ({ slot, id: current.active_session, mode: current.session_mode, recovery_required: false })),
  })
  const runtime: Runtime = {
    exit: () => {}, console: async () => "sessions", documents: async () => {},
    connectChat: (receive, _, slot = 0) => {
      connected.push(slot); frames.set(slot, receive)
      return { input: () => {}, close: () => { detached.push(slot) }, resize: (cols, rows) => receive({ type: "frame", full: true, cols, rows, data: `\x1b[2J\x1b[HWorkspace ${slot}` }) }
    },
    request: async (request) => {
      requests.push(request)
      const slot = request.slot ?? 0
      const session = sessions.get(slot)
      if (request.expectedSession && session?.active_session !== request.expectedSession) throw new ControlError("session_changed")
      if (request.operation === "status") return JSON.stringify(snapshot(slot))
      if (request.operation === "close") { sessions.delete(slot); if (closeWarning) throw new ControlError("locked_without_tor_state"); return "" }
      if (request.operation === "lock") { sessions.clear(); base.general_mounted = false; return "" }
      if (request.operation === "browse") return JSON.stringify({ path: "", entries: [{ name: `workspace-${slot}`, directory: true, bytes: 0 }], next: null, skipped: 0 })
      if (request.operation === "settings") {
        const mode = JSON.parse(new TextDecoder().decode(request.payload)).mode
        session!.settings!.current.web_access = mode
        return ""
      }
      if (request.operation === "network-policy") return ""
      if (request.operation === "transfers") return JSON.stringify({ configured: true, export_configured: true, active: false, sources: [] })
      if (request.operation === "onion") return JSON.stringify({ configured: false, active: false, state: "idle" })
      throw new Error(`Unexpected request: ${request.operation}`)
    },
  }
  return { initial: snapshot(1), runtime, requests, connected, detached, sessions, frames }
}

test.each([[80, 24], [160, 50]])("three tabs target the right workspace, documents and close operation at %ix%i", async (width, height) => {
  const value = await fixture()
  const app = await testRender(() => <App initial={value.initial} runtime={value.runtime} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("F6"); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame().split("\n")[0]).toContain("Alpha")
    expect(app.captureCharFrame()).toContain("Workspace 1")
    await app.mockInput.pressKeys(["\x1b[6;5~"]); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Workspace 2")
    expect(value.connected).toEqual([1, 2])
    expect(value.detached).toEqual([1])
    expect(app.captureCharFrame()).toContain("Workspace 2")
    expect(app.captureCharFrame()).toContain("Network [+] Strict")
    // A late frame/action from the detached console must not overwrite or lock B.
    value.frames.get(1)!({ type: "frame", full: true, cols: width, rows: 4, data: "STALE ALPHA" })
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("STALE ALPHA")
    await app.mockInput.pressKey("F7"); await app.renderOnce(); await app.renderOnce()
    expect(value.requests.findLast((request) => request.operation === "browse")).toMatchObject({ slot: 2, expectedSession: "2".repeat(32) })
    expect(app.captureCharFrame()).toContain("workspace-2")
    const line = app.captureCharFrame().split("\n")[0]
    await app.mockMouse.click(line.indexOf("Gamma") + 1, 0); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Workspace 3")
    await app.mockInput.pressKey("q", { ctrl: true }); await app.renderOnce()
    await app.mockInput.pressEnter(); await app.renderOnce(); await app.renderOnce()
    expect(value.requests.filter((request) => request.operation === "close")).toMatchObject([{ slot: 3, expectedSession: "3".repeat(32) }])
    expect([...value.sessions.keys()]).toEqual([1, 2])
    expect(app.captureCharFrame()).toContain("Your protected sessions")
    expect(app.captureCharFrame()).not.toContain("Gamma ·")
    app.resize(width === 80 ? 160 : 80, height === 24 ? 50 : 24)
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Alpha")
    expect(app.captureCharFrame()).toContain("Beta")
  } finally { await app.dispose() }
})

test("the network command changes only the selected session, and the host lock closes all", async () => {
  const value = await fixture()
  const app = await testRender(() => <App initial={value.initial} runtime={value.runtime} />, { width: 100, height: 30, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("F9"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("SESSION / Alpha / Network")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Session network access")
    await app.mockInput.pressArrow("down"); await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.renderOnce(); await app.renderOnce()
    expect(value.sessions.get(1)!.settings!.current.web_access).toBe("offline")
    expect(value.sessions.get(2)!.settings!.current.web_access).toBe("strict")
    expect(value.sessions.get(3)!.settings!.current.web_access).toBe("open")
    expect(value.requests.find((request) => request.operation === "settings")).toMatchObject({ slot: 1, expectedSession: "1".repeat(32) })
    await app.mockInput.pressKeys(["\x1b[5;5~"]); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Your protected sessions")
    await app.mockInput.pressKey("q", { ctrl: true }); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("all open sessions")
    await app.mockInput.pressEnter(); await app.renderOnce(); await app.renderOnce()
    expect(value.sessions.size).toBe(0)
    expect(value.requests.filter((request) => request.operation === "lock")).toMatchObject([{ slot: 0 }])
  } finally { await app.dispose() }
})

test("document sockets remain slot-specific while keeping legacy paths", () => {
  expect(sessionSocket("/run/oblivion-transfer-host/control.sock")).toBe("/run/oblivion-transfer-host/control.sock")
  expect(sessionSocket("/run/oblivion-transfer-host/control.sock", 3)).toBe("/run/oblivion-transfer-host-s3/control.sock")
  expect(sessionSocket("/run/oblivion-onion-host/control.sock", 2)).toBe("/run/oblivion-onion-host-s2/control.sock")
  for (const invalid of [-1, 32, 1.5, NaN]) expect(() => sessionSocket("/run/oblivion-transfer-host/control.sock", invalid)).toThrow("invalid_session_slot")
})

test("many open tabs keep the keyboard-selected session visible after resizing", async () => {
  const value = createSignal(12)
  const sessions = Array.from({ length: 12 }, (_, index) => ({ slot: index + 1, title: `Session ${index + 1}`, mode: "chat", recovery: false }))
  const app = await testRender(() => <SessionTabs sessions={sessions} selected={value[0]()} disabled={false} select={value[1]} />, { width: 80, height: 24 })
  try {
    await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("› Session 12")
    value[1](1)
    await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("› Session 1")
    value[1](12)
    await app.renderOnce(); await app.renderOnce()
    app.resize(45, 24)
    await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("› Session 12")
  } finally { await app.dispose() }
})

test("recovering a failed tab closes only that session", async () => {
  const value = await fixture()
  value.sessions.get(1)!.recovery_required = true
  const app = await testRender(() => <App initial={{ ...value.initial, recovery_required: true }} runtime={value.runtime} />, { width: 100, height: 30, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Close and recover session")
    await app.mockInput.pressEnter(); await app.renderOnce(); await app.renderOnce()
    expect([...value.sessions.keys()]).toEqual([2, 3])
    expect(value.requests.filter((request) => request.operation === "close")).toMatchObject([{ slot: 1, expectedSession: "1".repeat(32) }])
    expect(value.requests.some((request) => request.operation === "lock")).toBe(false)
  } finally { await app.dispose() }
})

test("a checkpoint warning after successful closure returns to the host without closing other sessions", async () => {
  const value = await fixture(true)
  const app = await testRender(() => <App initial={value.initial} runtime={value.runtime} />, { width: 100, height: 30, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("q", { ctrl: true }); await app.mockInput.pressEnter()
    await app.renderOnce(); await app.renderOnce()
    expect([...value.sessions.keys()]).toEqual([2, 3])
    expect(app.captureCharFrame()).toContain("Your protected sessions")
    expect(app.captureCharFrame()).toContain("The requested volumes are locked")
    expect(value.requests.findLast((request) => request.operation === "status")?.slot).toBe(0)
  } finally { await app.dispose() }
})
