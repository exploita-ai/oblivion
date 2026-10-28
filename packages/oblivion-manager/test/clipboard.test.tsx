import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createManagerClipboard } from "../src/clipboard"
import { ChatViewport, type ChatFrame } from "../src/chat"

test("host selection copies explicitly, paste remains text and session close clears it", async () => {
  let draw: ((frame: ChatFrame) => void) | undefined
  let cols = 0, rows = 0
  const inputs: number[] = []
  const app = await testRender(() => <ChatViewport focused activate={() => {}} attach={(receive) => { draw = receive }} connection={{
    close() {}, input: (data) => inputs.push(...data), resize: (width, height) => { cols = width; rows = height },
  }} />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  await app.renderer.setupTerminal()
  const clipboard = createManagerClipboard(app.renderer)
  try {
    await app.renderOnce()
    draw!({ type: "frame", full: true, cols, rows, data: "\x1b[HCopy this text\x1b[?1002h\x1b[?1006h\x1b[?2004h" })
    await app.renderOnce()
    await app.mockMouse.drag(0, 0, 13, 0); await app.renderOnce()
    expect(app.renderer.getSelection()?.getSelectedText()).toContain("Copy this text")
    await app.mockInput.pressKey("c", { ctrl: true })
    inputs.length = 0
    await app.mockInput.pressKey("v", { ctrl: true })
    expect(Buffer.from(inputs).toString()).toContain("\x1b[200~Copy this text\x1b[201~")
    expect(inputs).not.toContain(3)
    inputs.length = 0
    clipboard.paste("A\x1b[201~\x11B\nline")
    expect(Buffer.from(inputs).toString()).toBe("\x1b[200~A[201~B\nline\x1b[201~")
    clipboard.clear(); inputs.length = 0
    await app.mockInput.pressKey("v", { ctrl: true })
    expect(Buffer.from(inputs).toString()).not.toContain("Copy this text")
    inputs.length = 0
    await app.mockInput.pressKey("c", { ctrl: true })
    expect(inputs).toContain(3)
  } finally { clipboard.dispose(); await app.dispose() }
})
