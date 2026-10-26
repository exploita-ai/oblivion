import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { parseThemeDocument, resolveThemeDocument } from "@opencode/theme/tui"
import { oblivion } from "@opencode/theme/tui/themes"
import { ActionItem, SelectList } from "../src"

const theme = resolveThemeDocument(parseThemeDocument(oblivion), "dark")

test.each([[80, 24], [160, 50]])("reveals the saved selection when opened at %ix%i", async (width, height) => {
  const app = await testRender(() => <SelectList theme={theme} focused selected={95}
    items={Array.from({ length: 100 }, (_, i) => ({ title: `Layout ${String(i).padStart(3, "0")}` }))} />,
  { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Layout 095")
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("selection, wheel and click work at %ix%i and after resize", async (width, height) => {
  const selected: number[] = []
  const [focused, setFocused] = createSignal(true)
  const app = await testRender(() => <SelectList theme={theme} focused={focused()} onFocus={() => setFocused(true)}
    items={Array.from({ length: 100 }, (_, i) => ({ title: `Document ${String(i).padStart(3, "0")}` }))} onSelect={(index) => selected.push(index)} />,
  { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressKey("END")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Document 099")
    await app.mockInput.pressEnter()
    expect(selected).toEqual([99])
    await app.mockInput.pressKey("HOME")
    await app.renderOnce()
    const before = app.captureCharFrame()
    await app.mockMouse.scroll(12, 8, "down")
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toBe(before)
    expect(app.captureCharFrame().split("\n")[0]).not.toContain("Document 000")
    const lines = app.captureCharFrame().split("\n")
    const row = lines.findIndex((line) => /Document \d{3}/.test(line))
    const index = Number(/Document (\d{3})/.exec(lines[row])![1])
    setFocused(false)
    await app.renderOnce()
    await app.mockMouse.click(lines[row].indexOf("Document") + 3, row)
    await app.renderOnce()
    expect(focused()).toBe(true)
    expect(selected).toEqual([99, index])
    app.resize(44, 12)
    await app.renderOnce()
    await app.mockInput.pressKey("END")
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Document 099")
  } finally { await app.dispose() }
})

test("empty and disabled lists do not activate actions", async () => {
  const selected: number[] = []
  const [items, setItems] = createSignal<{ title: string }[]>([])
  const [disabled, setDisabled] = createSignal(false)
  const app = await testRender(() => <SelectList theme={theme} focused disabled={disabled()} items={items()} onSelect={(index) => selected.push(index)} />,
  { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    setItems([{ title: "Do not run" }]); setDisabled(true)
    await app.renderOnce()
    await app.mockInput.pressEnter()
    const lines = app.captureCharFrame().split("\n")
    const row = lines.findIndex((line) => line.includes("Do not run"))
    await app.mockMouse.click(lines[row].indexOf("Do not run"), row)
    expect(selected).toEqual([])
  } finally { await app.dispose() }
})

test.each([false, true])("shared dialog action respects disabled state (modern=%s)", async (modern) => {
  let count = 0
  const [disabled, setDisabled] = createSignal(true)
  const app = await testRender(() => <ActionItem theme={theme} modern={modern} variant="primary"
    action={{ title: "Confirm", key: "Enter", disabled: disabled(), onTrigger: () => count++ }} />, { width: 40, height: 10, kittyKeyboard: true })
  try {
    await app.renderOnce()
    const row = app.captureCharFrame().split("\n")[0]
    await app.mockMouse.click(row.indexOf("Confirm"), 0)
    expect(count).toBe(0)
    setDisabled(false); app.renderer.clearSelection()
    await app.renderOnce()
    await app.mockMouse.click(row.indexOf("Confirm") + 3, 0)
    expect(count).toBe(1)
  } finally { await app.dispose() }
})
