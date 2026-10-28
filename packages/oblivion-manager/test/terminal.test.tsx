import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { status } from "../src/state"
import type { ChatConnect } from "../src/chat"

test.each([[80, 24], [160, 50]])("offline terminal stays alive across views and closes only with the session at %ix%i", async (width, height) => {
  const fixture = preview(() => {})
  await fixture.request({ operation: "open-documents", session: "a".repeat(32) })
  const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
  const operations: string[] = []
  const input: number[] = []
  let attachments = 0
  let detachments = 0
  let closed = false
  const connectTerminal: ChatConnect = (receive) => {
    attachments++
    return {
      input: (bytes) => input.push(...bytes),
      resize: (cols, rows) => {
        receive({ type: "frame", full: true, cols, rows, data: "\x1b[2J\x1b[Hoblivion@session /vault/workspace\x1b[3;1H$ \x1b[?2004h" })
        receive({ type: "startup", status: "started" })
        receive({ type: "request", action: "close" })
      },
      close: () => { detachments++ },
    }
  }
  const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, connectTerminal,
    request: async (request) => {
      operations.push(request.operation)
      if (request.operation === "status" && !closed) return JSON.stringify(initial)
      if (request.operation === "close") closed = true
      return fixture.request(request)
    },
  }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("F8"); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame().split("\n")[0]).toContain("oblivion@session /vault/workspace")
    expect(app.captureCharFrame()).toContain("Terminal F8")
    expect(app.captureCharFrame()).toContain("Close Ctrl+Q")
    expect(app.captureCharFrame()).not.toContain("Close and lock session")
    expect(operations).not.toContain("start-chat")
    expect(operations).not.toContain("api-keys")
    await app.mockInput.typeText("pwd")
    await app.mockInput.pressKey("c", { ctrl: true })
    expect(Buffer.from(input).toString()).toContain("pwd\x03")
    expect(operations).not.toContain("close")
    await app.mockInput.pressKey("F7"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Documents")
    expect(detachments).toBe(0)
    await app.mockInput.pressKey("F8"); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("oblivion@session /vault/workspace")
    expect(attachments).toBe(1)
    app.resize(width === 80 ? 160 : 80, height === 24 ? 50 : 24)
    await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Close Ctrl+Q")
    await app.mockInput.pressKey("q", { ctrl: true }); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Stop all chats, terminals and jobs")
    expect(operations).not.toContain("close")
    await app.mockInput.pressEscape(); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("oblivion@session /vault/workspace")
    expect(detachments).toBe(0)
    await app.mockInput.pressKey("q", { ctrl: true }); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations).toContain("close")
    expect(detachments).toBe(1)
    expect(app.captureCharFrame()).toContain("Your protected sessions")
  } finally { await app.dispose() }
})
