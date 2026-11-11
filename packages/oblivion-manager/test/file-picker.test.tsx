import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { FilePicker } from "../src/vendor/termcn/file-picker"

test("termcn picker retains multiple selections while opening a directory", async () => {
  const [selected, setSelected] = createSignal<string[]>([])
  const navigated: string[] = []
  const app = await testRender(() => <FilePicker currentDir="/workspace" parentDir="" entries={[{ name: "a.txt", path: "workspace/a.txt", directory: false, bytes: 12 }, { name: "folder", path: "workspace/folder", directory: true, bytes: 0 }]} selected={selected()} focused onChange={setSelected} onNavigate={(value) => navigated.push(value)} onNext={() => {}} onBack={() => {}} />, { width: 80, height: 20, kittyKeyboard: true })
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

test.each([
  ["C:\\Users\\Ada\\Project", "C:\\Users\\Ada"],
  ["\\\\server\\share\\Project", "\\\\server\\share\\"],
  ["/home/ada/project", "/home/ada"],
  ["/workspace/project", "workspace"],
  ["/workspace", ""],
])("the picker displays %s and navigates only to the caller's explicit parent", async (currentDir, parentDir) => {
  const navigated: string[] = []
  const app = await testRender(() => <FilePicker currentDir={currentDir} parentDir={parentDir} entries={[]} selected={[]} focused onChange={() => { throw new Error("A parent cannot be selected") }} onNavigate={(value) => navigated.push(value)} onNext={() => {}} onBack={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain(currentDir)
    expect(app.captureCharFrame()).not.toContain(`/C:\\`)
    await app.mockInput.pressKey(" ")
    await app.mockInput.pressEnter()
    expect(navigated).toEqual([parentDir])
  } finally { await app.dispose() }
})

test.each(["C:\\", "/"])("a native root %s has no invented parent", async (currentDir) => {
  const chosen: string[][] = []
  const app = await testRender(() => <FilePicker currentDir={currentDir} parentDir={null} entries={[{ name: "file.txt", path: "literal-file", directory: false, bytes: 0 }]} selected={[]} focused onChange={(value) => chosen.push(value)} onNavigate={() => { throw new Error("No parent destination was supplied") }} onNext={() => {}} onBack={() => {}} />, { width: 160, height: 50, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    expect(chosen).toEqual([["literal-file"]])
    expect(app.captureCharFrame()).not.toContain("../")
  } finally { await app.dispose() }
})
