import { expect, test } from "bun:test"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { NativeShare, type ShareSelection } from "../src/native-share"

const safe = "0123456789abcdef0123456789abcdef"
const chat = "12345678-1234-4234-8234-123456789abc"

async function visible(app: Awaited<ReturnType<typeof testRender>>, value: string) {
  const deadline = performance.now() + 2000
  while (performance.now() < deadline) {
    await app.renderOnce()
    if (app.captureCharFrame().includes(value)) return
    await Bun.sleep(5)
  }
  throw new Error(`Missing ${value}\n${app.captureCharFrame()}`)
}

async function review(app: Awaited<ReturnType<typeof testRender>>) {
  await visible(app, "Choose Share destination")
  await app.mockInput.pressKey(".")
  await visible(app, "Name the encrypted Share")
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
  await visible(app, "Review Share export")
}

async function add(app: Awaited<ReturnType<typeof testRender>>, kind: "path" | "exclude" | "exclude-chat", value: string) {
  await app.mockInput.pressKey(kind === "path" ? "p" : kind === "exclude" ? "x" : "h")
  await visible(app, kind === "path" ? "Include one path" : kind === "exclude" ? "Exclude one path" : "Exclude one conversation")
  await app.mockInput.pasteBracketedText(value)
  await app.mockInput.pressEnter()
  await app.mockInput.pressEnter()
}

test.each([[80, 24], [160, 50]])("Share filters preserve literal repeated arguments and scope at %ix%i", async (width, height) => {
  for (const scope of ["safe", "branch", "all"] as const) {
    const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-filter-"))
    const calls: string[][] = []
    const selection: ShareSelection = scope === "all" ? { operation: "export", scope: "all", count: 3, closed: true }
      : { operation: "export", scope: "safe", safe, name: "Research", closed: true, branch: { count: 3, closed: true } }
    const app = await testRender(() => <NativeShare selection={selection} opening={"a".repeat(32)} initialDirectory={directory} run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width, height, kittyKeyboard: true })
    try {
      if (scope !== "all") { await app.renderOnce(); if (scope === "branch") await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter() }
      await review(app)
      await app.mockInput.pressKey("f")
      await visible(app, "Share content filters")
      await add(app, "path", "workspace/Project, città")
      await visible(app, "1/32 filters")
      await add(app, "path", "imports/Notes, final.txt")
      await visible(app, "2/32 filters")
      await add(app, "exclude", "workspace/Project, città/private file.txt")
      await visible(app, "3/32 filters")
      await add(app, "exclude-chat", chat)
      await visible(app, "4/32 filters")
      await add(app, "exclude", "imports/remove me.txt")
      await visible(app, "5/32 filters")
      await app.mockInput.pressKey("d")
      await visible(app, "4/32 filters")
      await app.mockInput.pressKey("c")
      await visible(app, "Conversations excluded")
      expect(calls).toHaveLength(0)
      await app.mockInput.pressEscape()
      await visible(app, "Review Share export")
      const first = app.captureCharFrame()
      expect(first).toContain(scope === "all" ? "--all" : scope === "branch" ? "--branch" : "--safe")
      await app.mockInput.pressKey("tab")
      await app.mockInput.pressKey("END")
      await app.renderOnce()
      const full = (first + app.captureCharFrame()).replace(/\s+/g, " ")
      expect(full).toContain("--path workspace/Project, città")
      expect(full).toContain("--path imports/Notes, final.txt")
      expect(full).toContain("--exclude workspace/Project, città/private file.txt")
      expect(full).toContain("--exclude-chat " + chat)
      expect(full).toContain("No (--no-chats)")
      expect(full).not.toContain("remove me.txt")
      expect(calls).toHaveLength(0)
      await app.mockInput.pressKey("tab")
      await app.mockInput.pressEnter()
      await visible(app, "Share exported")
      expect(calls).toEqual([["share", "export", ...(scope === "all" ? ["--all"] : [scope === "branch" ? "--branch" : "--safe", safe]), path.join(directory, scope === "all" ? "oblivion-all.oblivion-share" : "oblivion-01234567.oblivion-share"),
        "--path", "workspace/Project, città", "--path", "imports/Notes, final.txt", "--exclude", "workspace/Project, città/private file.txt", "--exclude-chat", chat, "--no-chats"]])
    } finally { await app.dispose(); await rm(directory, { recursive: true }) }
  }
})

test("filter entry rejects invalid roots, traversal, malformed UUIDs and multiline paste without exporting", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-filter-"))
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "export", scope: "safe", safe, name: "Research", closed: true }} initialDirectory={directory} run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await review(app)
    await app.mockInput.pressKey("f")
    await visible(app, "Share content filters")
    for (const value of ["/workspace/file", "home/file", "workspace/../secret", "workspace/./file", "workspace//file", "workspace/file/", "workspace\\file", "workspace/" + "a".repeat(256), "workspace/" + Array.from({ length: 32 }, () => "a").join("/")]) {
      await add(app, "path", value)
      await visible(app, "Enter one literal workspace or imports path")
      await app.mockInput.pressEscape()
      await visible(app, "0/32 filters")
    }
    await add(app, "exclude-chat", "ses_nativeID")
    await visible(app, "Enter one lowercase Share conversation reference")
    await app.mockInput.pressEscape()
    await app.mockInput.pressKey("p")
    await visible(app, "Include one path")
    await app.mockInput.pasteBracketedText("workspace/one\nimports/two")
    await visible(app, "Paste one literal entry without control")
    await app.mockInput.pressEscape()
    await visible(app, "0/32 filters")
    expect(calls).toHaveLength(0)
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("filter lists are bounded, removable and keep glob characters literal", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-filter-"))
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={{ operation: "export", scope: "safe", safe, name: "Research", closed: true }} initialDirectory={directory} run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await review(app)
    await app.mockInput.pressKey("f")
    for (let index = 0; index < 32; index++) { await add(app, "exclude", `workspace/literal [${index}]*, ?.txt`); await visible(app, `${index + 1}/32 filters`) }
    await app.mockInput.pressKey("p")
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Include one path")
    await app.mockInput.pressKey("END")
    await app.mockInput.pressKey("d")
    await visible(app, "31/32 filters")
    await app.mockInput.pressEscape()
    await visible(app, "Review Share export")
    await app.mockInput.pressEnter()
    await visible(app, "Share exported")
    expect(calls[0].filter((value) => value === "--exclude")).toHaveLength(31)
    expect(calls[0]).toContain("workspace/literal [0]*, ?.txt")
    expect(calls[0]).not.toContain("workspace/literal [31]*, ?.txt")
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test("the filter text budget rejects another whole path instead of truncating it", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-filter-"))
  const app = await testRender(() => <NativeShare selection={{ operation: "export", scope: "safe", safe, name: "Research", closed: true }} initialDirectory={directory} run={async () => { throw new Error("No export expected") }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await review(app)
    await app.mockInput.pressKey("f")
    for (let index = 0; index < 9; index++) {
      await add(app, "exclude", `workspace/${index}/${Array.from({ length: 4 }, () => "a".repeat(240)).join("/")}`)
      await visible(app, index < 8 ? `${index + 1}/32 filters` : "Use at most 32 filters and 8192 UTF-8 bytes")
    }
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})

test.each(["host", "safe", "scope", "operation"])("a changed %s clears filters and requires a fresh Share review", async (change) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oblivion-filter-"))
  const file = path.join(directory, "payload.oblivion-share")
  await writeFile(file, "synthetic package fixture")
  const [opening, setOpening] = createSignal("a".repeat(32))
  const [selection, setSelection] = createSignal<ShareSelection>({ operation: "export", scope: "safe", safe, name: "Research", closed: true, ...(change === "scope" ? { branch: { count: 2, closed: true } } : {}) })
  const calls: string[][] = []
  const app = await testRender(() => <NativeShare selection={selection()} opening={opening()} initialDirectory={directory} run={async (args) => { calls.push(args); return 0 }} back={() => {}} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    if (change === "scope") await app.mockInput.pressEnter()
    await review(app)
    await app.mockInput.pressKey("f")
    await add(app, "path", "workspace/only-this")
    await visible(app, "1/32 filters")
    await app.mockInput.pressKey("c")
    if (change === "host") setOpening("b".repeat(32))
    if (change === "safe") setSelection({ operation: "export", scope: "safe", safe: "e".repeat(32), name: "Another", closed: true })
    if (change === "operation") setSelection({ operation: "import" })
    if (change === "scope") {
      for (const page of ["Review Share export", "Name the encrypted Share", "Choose Share destination", "Choose Share scope"]) {
        await app.mockInput.pressEscape()
        await visible(app, page)
      }
      await app.mockInput.pressArrow("down")
      await app.mockInput.pressEnter()
    }
    if (change === "operation") {
      await visible(app, "payload.oblivion-share")
      await app.mockInput.pressEnter()
      await visible(app, "Review Share import")
      expect(app.captureCharFrame()).not.toContain("Content filters")
      expect(app.captureCharFrame()).toContain("[ ]")
      await app.mockInput.pressEnter()
      await app.mockInput.pressEnter()
      await visible(app, "Share imported")
      expect(calls).toEqual([["share", "import", file]])
      return
    }
    await review(app)
    expect(app.captureCharFrame()).not.toContain("only-this")
    expect(app.captureCharFrame()).toContain("Include conversations: Yes")
    expect(calls).toHaveLength(0)
    await app.mockInput.pressEscape()
    await visible(app, "Name the encrypted Share")
    expect(calls).toHaveLength(0)
  } finally { await app.dispose(); await rm(directory, { recursive: true }) }
})
