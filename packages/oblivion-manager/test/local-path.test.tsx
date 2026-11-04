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

test.each(["missing", "symlink", "directory-only", "remote-url", "multiple", "decoded-control", "decoded-bidi", "decoded-line"])("path inspection rejects %s without choosing or copying", async (scenario) => {
  const fixture = await files()
  const chosen: string[] = []
  const value = scenario === "missing" ? path.join(fixture.root, "missing.txt")
    : scenario === "symlink" ? path.join(fixture.root, "linked.txt")
    : scenario === "directory-only" ? fixture.file
    : scenario === "remote-url" ? "file://remote.invalid/tmp/Notes.txt"
    : scenario === "multiple" ? `'${fixture.file}' '${fixture.folder}'`
    : `${pathToFileURL(fixture.file).href}${scenario === "decoded-bidi" ? "%E2%80%AE" : scenario === "decoded-line" ? "%E2%80%A8" : "%0A"}`
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

test.each(["literal", "terminal-drop"])("an import %s path cannot mutate a Safe before the existing transfer review", async (spelling) => {
  const fixture = await files()
  const source = path.join(fixture.root, "$(touch literal-only).txt")
  const commands: string[][] = []
  const app = await testRender(() => <NativeFiles safe="0123456789abcdef0123456789abcdef" name="Research" runtime={nativePreview(() => {})} run={async (args) => { commands.push(args); return true }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    await app.mockInput.pressEnter()
    await enter(app, spelling === "literal" ? source : `${fixture.root}/\\$\\(touch\\ literal-only\\).txt `)
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

test.each([[80, 24], [160, 50]])("terminal-escaped dropped paths keep Unicode and require a choice at %ix%i", async (width, height) => {
  const fixture = await files()
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width, height, kittyKeyboard: true })
  try {
    await enter(app, `${fixture.root}/Notes\\ città\\ with\\ spaces.txt `)
    await visible(app, "Review local path")
    expect(app.captureCharFrame().replace(/\s+/g, " ")).toContain("Notes città with spaces.txt")
    expect(chosen).toHaveLength(0)
    await app.mockInput.pressEnter()
    expect(chosen).toEqual([fixture.file])
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test.each(["escaped", "single-quoted", "double-quoted", "raw-backslash", "raw-quotes", "raw-whitespace", "long-escaped"])("native path inspection preserves %s filenames", async (spelling) => {
  const fixture = await files()
  const filename = spelling === "raw-backslash" ? "literal\\ name.txt" : spelling === "raw-quotes" ? `literal'"$name.txt` : spelling === "raw-whitespace" ? " leading trailing " : spelling === "long-escaped" ? "report" + " ".repeat(130) + ".txt" : "Plans d'Italia $5.txt"
  const target = path.join(fixture.root, filename)
  await writeFile(target, "selected literal file")
  // Both spellings exist: a raw native backslash must remain authoritative,
  // rather than silently choosing the unescaped filename.
  await writeFile(path.join(fixture.root, "literal name.txt"), "not selected")
  const value = spelling === "escaped" ? `${fixture.root}/Plans\\ d\\'Italia\\ \\$5.txt`
    : spelling === "single-quoted" ? `'${fixture.root}/Plans d'\\''Italia $5.txt' `
    : spelling === "double-quoted" ? `"${fixture.root}/Plans d'Italia \\$5.txt"`
    : spelling === "long-escaped" ? target.replaceAll(" ", "\\ ")
    : target
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width: 160, height: 50, kittyKeyboard: true })
  try {
    await enter(app, value)
    await visible(app, "Review local path")
    expect(chosen).toHaveLength(0)
    if (spelling !== "long-escaped") expect(app.captureCharFrame()).toContain(target)
    await app.mockInput.pressEnter()
    expect(chosen).toEqual([target])
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test.each(["two-drops", "command", "environment", "home", "glob", "unclosed-quote", "trailing-escape", "substitution"])("terminal path spelling rejects %s without a selection", async (scenario) => {
  const fixture = await files()
  const source = `${fixture.root}/Notes\\ città\\ with\\ spaces.txt`
  const value = scenario === "two-drops" ? `${source} ${fixture.root}/Project\\ città`
    : scenario === "command" ? `${source}; pwd`
    : scenario === "environment" ? "$HOME"
    : scenario === "home" ? "~"
    : scenario === "glob" ? `${fixture.root}/Notes*.txt`
    : scenario === "unclosed-quote" ? `'${fixture.file}`
    : scenario === "trailing-escape" ? `${source}\\`
    : `${fixture.root}/$(touch injected-file)`
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await enter(app, value)
    await visible(app, "Enter one existing local path")
    expect(app.captureCharFrame()).not.toContain("Review local path")
    expect(chosen).toHaveLength(0)
    expect(await Bun.file(path.join(fixture.root, "injected-file")).exists()).toBe(false)
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})

test.each(["\n", "\r", "\x1b", "\x00", "\u202e", "\u2066", "\u200e", "\u061c", "\u2028", "\u2029"])("terminal paste rejects forbidden character %j", async (character) => {
  const fixture = await files()
  const chosen: string[] = []
  const app = await testRender(() => <LocalChooser directoryOnly={false} initialDirectory={fixture.root} choose={(value) => chosen.push(value)} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await visible(app, "Enter path")
    await app.mockInput.pressKey("p")
    await visible(app, "Enter local path")
    await app.mockInput.pasteBracketedText(fixture.file + character)
    await visible(app, "Paste one path without control characters")
    expect(app.captureCharFrame()).not.toContain("Review local path")
    expect(chosen).toHaveLength(0)
  } finally { await app.dispose(); await rm(fixture.root, { recursive: true }) }
})
