import { expect, test } from "bun:test"
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { InputRenderable } from "@opentui/core"
import { testRender } from "@opentui/solid"
import { LocalChooser, NativeFiles } from "../src/native-files"
import { nativePreview } from "../src/native-control"

async function files() {
  const root = await mkdtemp(path.join(os.tmpdir(), "oblivion-path-"))
  const file = path.join(root, "Notes città with spaces.txt")
  const folder = path.join(root, "Project città")
  await mkdir(folder)
  await Promise.all([writeFile(file, "synthetic local file"), writeFile(path.join(folder, "child.txt"), "synthetic child"), writeFile(path.join(root, "$(touch literal-only).txt"), "literal name")])
  await symlink(file, path.join(root, "linked.txt"))
  return { root, file, folder }
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

async function enter(app: Awaited<ReturnType<typeof testRender>>, value: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes("Enter path") && !app.captureCharFrame().includes("Reading local path")) break
    await Bun.sleep(5)
  }
  await app.mockInput.pressKey("p")
  await visible(app, "Enter local path")
  expect(app.renderer.currentFocusedRenderable).toBeInstanceOf(InputRenderable)
  await app.mockInput.pressKey("END")
  await app.mockInput.pressKey("u", { ctrl: true })
  await app.mockInput.pasteBracketedText(value)
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
}

test.each([[80, 24], [160, 50]])("pasted UTF-8 paths and local file URLs require an explicit choice at %ix%i", async (width, height) => {
  const fixture = await files()
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await enter(app, fixture.file)
    await visible(app, "Review local path")
    expect(app.captureCharFrame().replace(/\s+/g, " ")).toContain("Notes città with spaces.txt")
    expect(app.captureCharFrame()).toContain("Regular file")
    expect(app.captureCharFrame()).toContain("Choose file")
    expect(chosen).toHaveLength(0)
    await app.mockInput.pressEscape()
    await visible(app, "Enter path")
    await enter(app, pathToFileURL(fixture.file).href)
    await visible(app, "Review local path")
    expect(chosen).toHaveLength(0)
    await app.mockInput.pressEnter()
    expect(chosen).toEqual([fixture.file])
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test("a files-only directory can be browsed but cannot be chosen as a file", async () => {
  const fixture = await files()
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} filesOnly initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await enter(app, `'${fixture.folder}' `)
    await visible(app, "Review local path")
    expect(app.captureCharFrame()).toContain("This operation accepts files")
    expect(app.captureCharFrame()).toContain("Browse folder")
    expect(app.captureCharFrame()).not.toContain("Choose folder")
    await app.mockInput.pressEnter()
    await visible(app, "child.txt")
    expect(chosen).toHaveLength(0)
    await app.mockInput.pressKey(" ")
    expect(chosen).toEqual([path.join(fixture.folder, "child.txt")])
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test("directory-only path review offers explicit choose or browse actions", async () => {
  const fixture = await files()
  const chosen: string[] = []
  const destination = await testRender(() => <LocalChooser directoryOnly initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await enter(destination, fixture.folder)
    await visible(destination, "Choose folder")
    expect(chosen).toHaveLength(0)
    expect(destination.captureCharFrame()).toContain("Browse folder")
    await destination.mockInput.pressEnter()
    expect(chosen.at(-1)).toBe(fixture.folder)
  } finally { await destination.dispose(); await rm(fixture.root, { recursive: true }) }
})

test.each(["missing", "symlink", "directory-only", "remote-url", "multiple", "decoded-control"])("path inspection rejects %s without choosing or copying", async (scenario) => {
  const fixture = await files()
  const chosen: string[] = []
  const value = scenario === "missing" ? path.join(fixture.root, "missing.txt")
    : scenario === "symlink" ? path.join(fixture.root, "linked.txt")
    : scenario === "directory-only" ? fixture.file
    : scenario === "remote-url" ? "file://remote.invalid/tmp/Notes.txt"
    : scenario === "multiple" ? `'${fixture.file}' '${fixture.folder}'`
    : `${pathToFileURL(fixture.file).href}%0A`
  const app = await testRender(() => <LocalChooser directoryOnly={scenario === "directory-only"} initialDirectory={fixture.root} choose={(selected) => chosen.push(selected)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await enter(app, value)
    await visible(app, scenario === "symlink" ? "Symbolic links are not selectable" : scenario === "directory-only" ? "This operation requires a directory" : "Enter one existing local path")
    expect(app.captureCharFrame()).not.toContain("Review local path")
    expect(chosen).toHaveLength(0)
    await app.mockInput.pressEscape()
    await visible(app, "Enter path")
    expect(app.captureCharFrame()).toContain("Project città/")
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test("multi-line paste is rejected and cancelling path entry preserves the browser selection", async () => {
  const fixture = await files()
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Notes città with spaces.txt")
    await app.mockInput.pressArrow("down")
    await app.mockInput.pressKey("p")
    await visible(app, "Enter local path")
    await app.mockInput.pasteBracketedText(fixture.file + "\n" + fixture.folder)
    await visible(app, "Paste one path without control characters")
    await app.mockInput.pressEscape()
    await visible(app, "Enter path")
    expect(chosen).toHaveLength(0)
    await app.mockInput.pressKey(" ")
    expect(chosen).toEqual([path.join(fixture.root, "$(touch literal-only).txt")])
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test("an import path is literal and cannot mutate a Safe before the existing transfer review", async () => {
  const fixture = await files()
  const source = path.join(fixture.root, "$(touch literal-only).txt")
  const commands: string[][] = []
  const app = await testRender(() => <NativeFiles safe="0123456789abcdef0123456789abcdef" name="Research" runtime={nativePreview(() => {})} run={async (args) => { commands.push(args); return true }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await enter(app, source)
    await visible(app, "Review local path")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Name the imported copy")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await app.mockInput.pressEnter()
    await visible(app, "Confirm import")
    expect(app.captureCharFrame()).toContain("$(touch literal-only).txt")
    expect(commands).toHaveLength(0)
    await app.mockInput.pressEnter()
    await visible(app, "Copy completed and verified")
    expect(commands).toEqual([["safe", "open", "0123456789abcdef0123456789abcdef"], ["files", "import", "--safe", "0123456789abcdef0123456789abcdef", source, "--name", path.basename(source)]])
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})
