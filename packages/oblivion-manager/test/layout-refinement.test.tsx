import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { FormView } from "../src/form"
import { preview } from "../src/preview"
import { status } from "../src/state"

for (const mode of ["open", "create", "ephemeral"] as const) {
  test(`${mode} enters chat immediately using the global default key`, async () => {
    const fixture = preview(() => {})
    if (mode === "ephemeral") await fixture.request({ operation: "unlock-ephemeral" })
    const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
    const operations: string[] = []
    const selected: string[] = []
    let running = false
    const app = await testRender(() => <App initial={initial} runtime={{ ...fixture,
      request: async (input) => {
        operations.push(input.operation)
        if (input.operation === "start-chat") { running = true; return "" }
        if (input.operation === "api-keys") selected.push(JSON.parse(new TextDecoder().decode(input.payload)).id)
        const output = await fixture.request(input)
        return input.operation === "status" && running ? JSON.stringify({ ...JSON.parse(output), session_mode: "chat" }) : output
      },
      connectChat: (receive) => ({ input: () => {}, close: () => {}, resize: (cols, rows) => receive({ type: "frame", full: true, cols, rows, data: "\x1b[2J\x1b[HRestored conversation" }) }),
    }} />, { width: 160, height: 50, kittyKeyboard: true })
    try {
      await app.renderOnce()
      if (mode === "open") await app.mockInput.pressEnter()
      if (mode !== "open") await app.mockInput.pressKey("n")
      if (mode !== "open") { await app.mockInput.typeText("Research session"); await app.mockInput.pressEnter() }
      if (mode !== "ephemeral") {
        await app.mockInput.typeText("synthetic-session-password"); await app.mockInput.pressEnter()
        if (mode === "create") { await app.mockInput.typeText("synthetic-session-password"); await app.mockInput.pressEnter() }
        await app.mockInput.pressEnter()
      }
      if (mode === "ephemeral") await app.mockInput.pressEnter()
      await app.renderOnce(); await app.renderOnce()
      expect(app.captureCharFrame()).toStartWith("Restored conversation")
      expect(app.captureCharFrame()).not.toContain("workspace/")
      expect(app.captureCharFrame()).toContain("Documents F7")
      expect(selected).toEqual([initial.api_keys!.default!])
      expect(operations.filter((value) => value === "start-chat")).toHaveLength(1)
      await app.mockInput.pressKey("F7"); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("workspace/")
    } finally { await app.dispose() }
  })
}

test("form content spans the page and descriptions align with actions across resize", async () => {
  const app = await testRender(() => <FormView form={{ title: "Close and lock session", description: "Stop the running response and lock the session.", fields: [], submit: "Close and lock", run: async () => {} }} cancel={() => {}} submit={() => {}} />, { width: 160, height: 50, kittyKeyboard: true })
  try {
    await app.renderOnce()
    const wide = app.captureCharFrame().split("\n")
    expect(wide.find((row) => row.includes("─"))!.lastIndexOf("─")).toBe(159)
    for (const [width, height] of [[160, 50], [80, 24]]) {
      app.resize(width, height); await app.renderOnce()
      const rows = app.captureCharFrame().split("\n")
      expect(rows.find((row) => row.includes("Stop the running"))!.indexOf("Stop")).toBe(rows.find((row) => row.includes("Close and lock Enter"))!.indexOf("Close"))
      expect(rows.join("\n")).toContain("Cancel Esc")
    }
  } finally { await app.dispose() }
})

test.each([[80, 24], [160, 50]])("session explanation aligns with its command at %ix%i", async (width, height) => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App initial={initial} runtime={runtime} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    const rows = app.captureCharFrame().split("\n")
    expect(rows.find((row) => row.includes("Unlock to resume"))!.indexOf("Unlock")).toBe(rows.find((row) => row.includes("Unlock session Enter"))!.indexOf("Unlock"))
  } finally { await app.dispose() }
})

test("session titles can be renamed without opening the encrypted session", async () => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  const app = await testRender(() => <App initial={initial} runtime={runtime} />, { width: 160, height: 50, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("r"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Rename session")
    await app.mockInput.pressKey("HOME"); await app.mockInput.pressKey("END", { shift: true }); await app.mockInput.typeText("Ricerca città")
    await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.renderOnce()
    const saved = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
    expect(saved.session_titles[initial.sessions[0]]).toBe("Ricerca città")
    expect(saved.session_open).toBe(false)
    expect(app.captureCharFrame()).toContain("Ricerca città")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("HOST / Sessions / Ricerca città")
    expect(app.captureCharFrame()).toContain("All chats and shared documents")
  } finally { await app.dispose() }
})
