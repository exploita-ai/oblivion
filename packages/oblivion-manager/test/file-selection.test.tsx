import { expect, test } from "bun:test"
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { createSignal } from "solid-js"
import { testRender } from "@opentui/solid"
import { GuestChooser, LocalChooser } from "../src/native-files"
import { selectionError } from "../src/file-selection"
import { nativePreview } from "../src/native-control"

async function visible(app: Awaited<ReturnType<typeof testRender>>, text: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) { await app.renderOnce(); if (app.captureCharFrame().includes(text)) return; await Bun.sleep(5) }
  throw new Error(`Missing ${text}\n${app.captureCharFrame()}`)
}

test.each([[80, 24], [160, 50]])("local multi-selection retains unrelated paths and pages, and the basket removes explicitly at %ix%i", async (width, height) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "oblivion-file-basket-"))
  await Promise.all([mkdir(path.join(root, "left")), mkdir(path.join(root, "right"))])
  await Promise.all(Array.from({ length: 101 }, (_, index) => writeFile(path.join(root, "left", `${String(index).padStart(3, "0")}.txt`), "file")))
  await writeFile(path.join(root, "right", "città.txt"), "other")
  const [paths, setPaths] = createSignal<string[]>([])
  const continued: string[][] = []
  const single: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={path.join(root, "left")}
    selection={{ paths: paths(), change: setPaths, continue: () => continued.push(paths()) }} choose={(value) => single.push(value)} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await visible(app, "000.txt")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    expect(paths()).toEqual([path.join(root, "left", "000.txt")])
    await app.mockInput.pressKeys(["\x1b[6~"])
    await visible(app, "100.txt")
    await app.mockInput.pressKey(" ")
    expect(paths()).toEqual([path.join(root, "left", "000.txt"), path.join(root, "left", "100.txt")])
    await app.mockInput.pressKey("p")
    await visible(app, "Enter local path")
    await app.mockInput.pasteBracketedText(path.join(root, "right", "città.txt"))
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Review local path")
    await app.mockInput.pressEnter()
    await visible(app, "3 selected")
    expect(continued).toEqual([])
    expect(single).toEqual([])
    await app.mockInput.pressKey("b")
    await visible(app, "Selected items")
    await app.mockInput.pressEnter()
    await visible(app, "2 selected")
    await app.mockInput.pressKey("c")
    expect(continued).toEqual([[path.join(root, "left", "100.txt"), path.join(root, "right", "città.txt")]])
  } finally { await app.dispose(); await rm(root, { recursive: true }) }
})

test("guest selection retains workspace and imports across paginated directory queries", async () => {
  const [paths, setPaths] = createSignal<string[]>([])
  const continued: string[][] = []
  const queries: string[][] = []
  const base = nativePreview(() => {})
  const runtime = { ...base, query: async (args: string[]) => {
    queries.push(args)
    const current = args[4] === "--json" ? "" : args[4]!
    const next = args.includes("page2")
    const entry = (name: string, kind: "directory" | "file") => ({ name, path: current ? `${current}/${name}` : name, kind, bytes: 0 })
    return { path: current, entries: current === "" ? [entry("workspace", "directory"), entry("imports", "directory")]
      : current === "workspace" ? [entry(next ? "second.txt" : "first.txt", "file")]
      : [entry("other.txt", "file")], next_cursor: current === "workspace" && !next ? "page2" : null }
  } }
  const app = await testRender(() => <GuestChooser safe={"a".repeat(32)} runtime={runtime} selection={{ paths: paths(), change: setPaths, continue: () => continued.push(paths()) }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "workspace/")
    await app.mockInput.pressEnter()
    await visible(app, "first.txt")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "second.txt")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    await app.mockInput.pressArrow("up")
    await app.mockInput.pressEnter()
    await visible(app, "imports/")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressEnter()
    await visible(app, "other.txt")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey(" ")
    expect(paths()).toEqual(["workspace/first.txt", "workspace/second.txt", "imports/other.txt"])
    expect(continued).toEqual([])
    expect(queries.some((args) => args.includes("--cursor") && args.includes("page2"))).toBe(true)
    await app.mockInput.pressKey("c")
    expect(continued).toEqual([paths()])
  } finally { await app.dispose() }
})

test("selection budget counts UTF-8 bytes and rejects extra entries without pruning overlaps", () => {
  expect(selectionError(Array.from({ length: 128 }, (_, index) => `/file/${index}`))).toBeUndefined()
  expect(selectionError(Array.from({ length: 129 }, (_, index) => `/file/${index}`))).toContain("128")
  expect(selectionError(["é".repeat(32768)])).toBeUndefined()
  expect(selectionError(["é".repeat(32769)])).toContain("64 KiB")
  expect(selectionError(["workspace/project", "workspace/project/file.txt", "imports/project"])).toBeUndefined()
})

test("local manual path review preserves the full basket and explains a rejected 129th selection", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "oblivion-file-limit-"))
  const existing = Array.from({ length: 129 }, (_, index) => path.join(root, `${index}.txt`))
  await Promise.all(existing.map((value) => writeFile(value, "file")))
  const [paths, setPaths] = createSignal(existing.slice(0, 128))
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={root} selection={{ paths: paths(), change: setPaths, continue: () => {} }} choose={() => { throw new Error("Single selection is not enabled") }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Enter path")
    await app.mockInput.pressKey("p")
    await visible(app, "Enter local path")
    await app.mockInput.pasteBracketedText(existing[128]!)
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Review local path")
    await app.mockInput.pressEnter()
    await visible(app, "Choose at most 128")
    expect(paths()).toEqual(existing.slice(0, 128))
    expect(app.captureCharFrame()).toContain("Review local path")
  } finally { await app.dispose(); await rm(root, { recursive: true }) }
})
