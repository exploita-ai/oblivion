import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { status } from "../src/state"
import type { ChatEvent } from "../src/chat"

for (const outcome of ["started", "storage-failed", "client-failed"] as const) {
  test(`chat startup waits for the application and handles ${outcome}`, async () => {
    const fixture = preview(() => {})
    const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
    const operations: string[] = []
    let receive: ((event: ChatEvent) => void) | undefined
    let detached = false
    const app = await testRender(() => <App initial={initial} runtime={{ ...fixture,
      request: async (input) => { operations.push(input.operation); return fixture.request(input) },
      connectChat: (callback) => {
        receive = callback
        return { input: () => {}, close: () => { detached = true }, resize: (cols, rows) => callback({ type: "frame", full: true, cols, rows, data: "Application still loading" }) }
      },
    }} />, { width: 80, height: 24, kittyKeyboard: true })
    try {
      await app.renderOnce()
      await app.mockInput.pressEnter()
      await app.mockInput.typeText("synthetic-session-password")
      await app.mockInput.pressEnter(); await app.mockInput.pressEnter()
      await app.renderOnce(); await app.renderOnce()
      expect(receive).toBeDefined()
      expect(operations).toContain("start-chat")
      expect(operations).not.toContain("chat-ready")
      expect(app.captureCharFrame()).toContain("Starting chat")
      expect(status.parse(JSON.parse(await fixture.request({ operation: "status" }))).session_mode).toBe("starting")
      receive!({ type: "startup", status: outcome })
      for (let frame = 0; frame < 10; frame++) {
        await app.renderOnce()
        if (operations.includes(outcome === "started" ? "chat-ready" : "chat-recover")) break
      }
      await app.renderOnce()
      const current = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
      expect(current.session_mode).toBe(outcome === "started" ? "chat" : "documents")
      expect(operations.filter((value) => value === "open-documents")).toHaveLength(1)
      expect(operations).not.toContain("close")
      expect(detached).toBe(outcome !== "started")
      if (outcome !== "started") {
        expect(operations).not.toContain("chat-ready")
        expect(app.captureCharFrame().replaceAll(/\s+/g, " ")).toContain("original data was preserved")
      }
    } finally { await app.dispose() }
  })
}
