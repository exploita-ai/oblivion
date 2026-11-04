import { expect, test } from "bun:test"
import { testRender, usePaste } from "@opentui/solid"
import { createManagerClipboard } from "../src/clipboard"

test("manager selection copies explicitly and paste strips terminal controls", async () => {
  const pasted: string[] = []
  function Fixture() {
    usePaste((event) => pasted.push(new TextDecoder().decode(event.bytes)))
    return <text>Copy this text</text>
  }
  const app = await testRender(() => <Fixture />, { width: 80, height: 24, kittyKeyboard: true, exitOnCtrlC: false })
  await app.renderer.setupTerminal()
  const clipboard = createManagerClipboard(app.renderer)
  try {
    await app.renderOnce()
    await app.mockMouse.drag(0, 0, 13, 0)
    await app.renderOnce()
    expect(app.renderer.getSelection()?.getSelectedText()).toContain("Copy this text")
    await app.mockInput.pressKey("c", { ctrl: true })
    await app.mockInput.pressKey("v", { ctrl: true })
    expect(pasted).toEqual(["Copy this text"])
    clipboard.paste("A\x1b[201~\x11B\nline")
    expect(pasted.at(-1)).toBe("A[201~B\nline")
    clipboard.clear()
    expect(app.renderer.getSelection()).toBeNull()
    await app.mockInput.pressKey("v", { ctrl: true })
    expect(pasted.at(-1)).not.toContain("Copy this text")
  } finally { clipboard.dispose(); await app.dispose() }
})
