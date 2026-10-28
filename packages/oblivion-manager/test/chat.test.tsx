import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { status } from "../src/state"
import type { ChatConnect } from "../src/chat"
import { ChatViewport, type ChatFrame } from "../src/chat"

test.each([[80, 24], [160, 50]])("chat fills the window and keeps host actions in the footer at %ix%i", async (width, height) => {
  const fixture = preview(() => {})
  await fixture.request({ operation: "open-documents", session: "a".repeat(32) })
  const initial = { ...status.parse(JSON.parse(await fixture.request({ operation: "status" }))), session_mode: "chat" as const,
    network_status: { label: "TOR READY" as const, host_link: "CONNECTED" as const, age_ms: 0, direct_blocked: true } }
  const inputs: number[] = []
  const sizes: number[][] = []
  const operations: string[] = []
  let detached = 0
  let locked = false
  let clipboardClears = 0
  const connectChat: ChatConnect = (receive) => ({
    input: (data) => inputs.push(...data),
    resize: (cols, rows) => {
      sizes.push([cols, rows])
      receive({ type: "frame", full: true, cols, rows, data: "\x1b[2J\x1b[HConversation in the guest\x1b[3;1HYour existing OpenCode chat\x1b[?2004h" })
    },
    close: () => { detached++ },
  })
  const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, connectChat, clearClipboard: () => { clipboardClears++ }, request: async (request) => {
    operations.push(request.operation)
    if (request.operation === "status" && !locked) return JSON.stringify(initial)
    if (request.operation === "close") locked = true
    return fixture.request(request)
  } }} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("F6"); await app.renderOnce(); await app.renderOnce()
    const frame = app.captureCharFrame()
    expect(frame.split("\n")[0]).toStartWith("Conversation in the guest")
    expect(frame).not.toContain("SESSION /")
    expect(frame).not.toContain("Sessions")
    expect(frame).not.toContain("API keys")
    expect(frame).not.toContain("OBLIVION")
    expect(frame).toContain("Tor [+]")
    expect(frame).toMatch(/Chat F6\s+Documents F7\s+Terminal F8\s+Close Ctrl\+Q/)
    expect(sizes.at(-1)![0]).toBe(width)
    expect(sizes.at(-1)![1]).toBeGreaterThanOrEqual(height - 4)
    await app.mockInput.typeText("12345"); await app.mockInput.pressKey("TAB")
    expect(Buffer.from(inputs).toString()).toBe("12345\t")
    await app.mockInput.pasteBracketedText("paste\x1d\x1e")
    expect(operations).not.toContain("close")
    await app.mockInput.pressKey("F7"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("SESSION / aaaaaaaa / Documents")
    expect(app.captureCharFrame()).toContain("workspace/")
    expect(detached).toBe(0)
    const rows = app.captureCharFrame().split("\n")
    const footer = rows.findIndex((row) => row.includes("Chat F6"))
    await app.mockMouse.click(rows[footer].indexOf("Chat") + 1, footer)
    await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Conversation in the guest")
    expect(detached).toBe(0)
    expect(clipboardClears).toBe(0)
    app.resize(120, 36); await app.renderOnce(); await app.renderOnce()
    expect(sizes.at(-1)![0]).toBe(120)
    expect(app.captureCharFrame()).toContain("Conversation in the guest")
    await app.mockInput.pressKey("q", { ctrl: true }); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Close and lock session")
    expect(operations).not.toContain("close")
    expect(inputs).not.toContain(17)
    await app.mockInput.pressEscape(); await app.renderOnce(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Conversation in the guest")
    await app.mockInput.pressKey("q", { ctrl: true }); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(operations).toContain("close")
    expect(detached).toBe(1)
    expect(clipboardClears).toBeGreaterThan(0)
    expect(app.captureCharFrame()).toContain("Your protected sessions")
    expect(app.captureCharFrame()).toContain("Lock Oblivion Ctrl+Q")
  } finally { await app.dispose() }
})

test("embedded chat applies every streaming delta and forwards wheel and paging to OpenCode", async () => {
  let draw: ((frame: ChatFrame) => void) | undefined
  let cols = 0
  let rows = 0
  const input: number[] = []
  const app = await testRender(() => <ChatViewport focused activate={() => {}} attach={(receive) => { draw = receive }} connection={{
    close: () => {}, input: (data) => input.push(...data), resize: (width, height) => { cols = width; rows = height },
  }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    draw!({ type: "frame", full: true, cols, rows, data: "\x1b[HOriginal transcript\x1b[?1002h\x1b[?1006h\x1b[?2004h" })
    draw!({ type: "frame", full: false, cols, rows, data: "\x1b[2;1HFirst streamed token" })
    draw!({ type: "frame", full: false, cols, rows, data: "\x1b[3;1HSecond streamed token" })
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Original transcript")
    expect(app.captureCharFrame()).toContain("First streamed token")
    expect(app.captureCharFrame()).toContain("Second streamed token")
    await app.mockInput.pressKey("\x1b[5~")
    await app.mockInput.pressKey("\x1b[6~")
    await app.mockMouse.scroll(5, 5, "up")
    expect(Buffer.from(input).toString()).toContain("\x1b[5~")
    expect(Buffer.from(input).toString()).toContain("\x1b[6~")
    expect(Buffer.from(input).toString()).toContain("\x1b[<64;")
  } finally { await app.dispose() }
})
