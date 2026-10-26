import { expect, test } from "bun:test"
import { InputRenderable, TextareaRenderable } from "@opentui/core"
import { createTestRenderer } from "@opentui/core/testing"
import { Oblivion } from "@opencode/util/oblivion"
import { createTuiClipboard } from "../src/clipboard"
import { createAppFixture } from "./fixture/app"
import { directory, json } from "./fixture/tui-client"

// Run with bun test --define OBLIVION_PROFILE=true --timeout 30000 test/oblivion.test.tsx.
// The normal suite exercises upstream behavior with the profile compiled out.
test.skipIf(!Oblivion.enabled)("Oblivion never exposes the shared clipboard boundary", async () => {
  const setup = await createTestRenderer({ width: 80, height: 24, kittyKeyboard: true })
  const clipboard = createTuiClipboard(setup.renderer)
  try {
    expect(await clipboard.read()).toBeUndefined()
    await expect(clipboard.write("synthetic clipboard marker")).rejects.toThrow("Shared clipboard is unavailable")
  } finally {
    await clipboard.dispose()
    setup.renderer.destroy()
  }
})

test.skipIf(!Oblivion.enabled).each([100, 44])("Oblivion limits the actual app surface at width %i", async (width) => {
  const location = { directory, project: { id: "project", directory, canonical: directory } }
  const mutations: string[] = []
  await using setup = await createAppFixture({
    width,
    height: 30,
    config: {
      animations: false,
      tabs: { enabled: true, mode: "on" },
      debug: { devtools: true },
      keybinds: { "command.palette.show": "f2", "model.list": "f3", "agent.list": "f4" },
    },
    fetch: (url, request) => {
      if (request.method === "POST") mutations.push(url.pathname)
      if (url.pathname === "/api/location") return json(location)
      if (url.pathname === "/api/agent")
        return json({ location, data: [{ id: "build", mode: "primary", hidden: false, permissions: [] }] })
      if (url.pathname === "/api/provider")
        return json({
          location,
          data: [
            { id: Oblivion.providerID, name: "Allowed provider" },
            { id: "other", name: "Other" },
          ],
        })
      if (url.pathname === "/api/model")
        return json({
          location,
          data: [Oblivion.providerID, "other"].map((providerID) => ({
            id: "fixture",
            providerID,
            name: providerID === Oblivion.providerID ? "Allowed model" : "Excluded model",
            variants: [],
            cost: [],
            time: { released: 0 },
          })),
        })
    },
  })
  await setup.ready
  await visible(
    setup,
    (frame) =>
      frame.includes("OBLIVION") &&
      frame.includes("Allowed model") &&
      setup.renderer.currentFocusedRenderable instanceof TextareaRenderable,
  )
  expect(setup.captureCharFrame()).toContain("Conversations and documents")
  expect(setup.captureCharFrame()).not.toContain("DevTools")
  setup.mockInput.pressKey("F4")
  await setup.renderOnce()
  expect(setup.captureCharFrame()).not.toContain("Select agent")
  setup.mockInput.pressKey("F2")
  await visible(
    setup,
    (frame) =>
      frame.includes("New chat") && setup.renderer.currentFocusedRenderable instanceof InputRenderable,
  )
  const palette = setup.captureCharFrame()
  expect(palette).toContain("Resume chat")
  expect(palette).not.toContain("Connect integration")
  expect(palette).not.toContain("Switch agent")
  expect(palette).not.toContain("worktree")
  setup.mockInput.pressEscape()
  await visible(setup, () => setup.renderer.currentFocusedRenderable instanceof TextareaRenderable)
  setup.mockInput.pressKey("F3")
  await visible(
    setup,
    (frame) => frame.includes("Select model") && setup.renderer.currentFocusedRenderable instanceof InputRenderable,
  )
  expect(setup.captureCharFrame()).toContain("Allowed model")
  expect(setup.captureCharFrame()).not.toContain("Excluded model")
  expect(mutations).toEqual([])
})

async function visible(setup: Awaited<ReturnType<typeof createAppFixture>>, predicate: (frame: string) => boolean) {
  const deadline = Date.now() + 3_000
  while (!predicate(setup.captureCharFrame())) {
    if (Date.now() >= deadline) throw new Error(`Oblivion frame not ready:\n${setup.captureCharFrame()}`)
    await Bun.sleep(10)
  }
}

test.skipIf(!Oblivion.enabled)("Oblivion resume manages chats in the same server without protected-session actions", async () => {
  const sessions = ["First chat", "Second chat"].map((title, index) => ({
    id: `ses_chat${index}`, title, projectID: "proj_test", location: { directory },
    cost: 0, tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
    time: { created: 1, updated: 2 - index },
  }))
  const removed: string[] = []
  const renamed: string[] = []
  await using setup = await createAppFixture({
    config: { animations: false, keybinds: { "session.list": "f5", "session.new": "f6" } },
    fetch: async (url, request) => {
      if (url.pathname === "/api/session") return json({ data: sessions.filter((session) => !removed.includes(session.id)), cursor: {} })
      if (url.pathname.startsWith("/api/session/") && request.method === "DELETE") { removed.push(url.pathname.split("/").at(-1)!); return new Response(null, { status: 204 }) }
      if (url.pathname.startsWith("/api/session/") && request.method === "PATCH") { renamed.push((await request.json()).title); return new Response(null, { status: 204 }) }
    },
  })
  await setup.ready
  await visible(setup, () => setup.renderer.currentFocusedRenderable instanceof TextareaRenderable)
  setup.mockInput.pressKey("F5")
  await visible(setup, (frame) => frame.includes("First chat") && frame.includes("Second chat") && setup.renderer.currentFocusedRenderable instanceof InputRenderable)
  expect(setup.captureCharFrame()).toContain("Chats in this session")
  expect(setup.captureCharFrame()).not.toContain("Switch protected session")
  setup.mockInput.pressKey("r", { ctrl: true })
  await visible(setup, (frame) => frame.includes("Rename chat") && setup.renderer.currentFocusedRenderable instanceof TextareaRenderable)
  setup.mockInput.pressKey("HOME"); setup.mockInput.pressKey("END", { shift: true }); setup.mockInput.typeText("Renamed chat"); setup.mockInput.pressEnter()
  await visible(setup, () => renamed.length === 1)
  expect(renamed).toEqual(["Renamed chat"])
  setup.mockInput.pressKey("F5")
  await visible(setup, (frame) => frame.includes("First chat") && setup.renderer.currentFocusedRenderable instanceof InputRenderable)
  setup.mockInput.pressKey("d", { ctrl: true })
  await visible(setup, (frame) => frame.includes("again to confirm"))
  expect(removed).toHaveLength(0)
  setup.mockInput.pressKey("d", { ctrl: true })
  await visible(setup, (frame) => removed.length === 1 && !frame.includes("First chat") && frame.includes("Second chat"))
  expect(removed).toEqual(["ses_chat0"])
  setup.mockInput.pressEscape(); setup.mockInput.pressKey("F6")
  await visible(setup, (frame) => frame.includes("/new new chat") && setup.renderer.currentFocusedRenderable instanceof TextareaRenderable)
  setup.mockInput.typeText("/")
  await visible(setup, (frame) => frame.includes("/resume"))
  expect(setup.captureCharFrame()).not.toContain("/sessions")
  expect(setup.captureCharFrame()).not.toContain("/continue")
})
