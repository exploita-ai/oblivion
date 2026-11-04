import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { FilePicker } from "../src/vendor/termcn/file-picker"

test("termcn picker retains multiple selections while opening a directory", async () => {
  const [selected, setSelected] = createSignal<string[]>([])
  const navigated: string[] = []
  const app = await testRender(() => <FilePicker currentDir="workspace" entries={[{ name: "a.txt", path: "workspace/a.txt", directory: false, bytes: 12 }, { name: "folder", path: "workspace/folder", directory: true, bytes: 0 }]} selected={selected()} focused onChange={setSelected} onNavigate={(value) => navigated.push(value)} onNext={() => {}} onBack={() => {}} />, { width: 80, height: 20, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await app.renderOnce()
    expect(selected()).toEqual(["workspace/a.txt", "workspace/folder"])
    expect(app.captureCharFrame()).toContain("2 selected")
    await app.mockInput.pressEnter()
    expect(navigated).toEqual(["workspace/folder"])
  } finally { app.renderer.destroy(); await app.renderer.closed }
})
