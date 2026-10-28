import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { ChatExport } from "../src/chat-export"

test.each([[80, 24], [160, 50]])("chat export requires explicit format and confirmation at %ix%i", async (width, height) => {
  const requests: object[] = []
  const saved: string[] = []
  const path = `workspace/chat-exports/${"a".repeat(32)}.json`
  const app = await testRender(() => <ChatExport back={() => {}} saved={async (path) => { saved.push(path) }} request={async (request) => {
    expect(request.operation).toBe("chat-export")
    const payload = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string }
    requests.push(payload)
    return JSON.stringify(payload.action === "list" ? { result: "chats", entries: [{ id: "ses_example", title: "Private conversation" }], next: null } : { result: "exported", path, bytes: 1024 })
  }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Private conversation")
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Export chat / Format")
    await app.mockInput.typeText("json"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Create transcript")
    expect(app.captureCharFrame()).toContain("not a session backup")
    expect(requests).toEqual([{ action: "list", cursor: null }])
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(requests).toEqual([{ action: "list", cursor: null }, { action: "export", id: "ses_example", format: "json" }])
    expect(saved).toEqual([path])
  } finally { await app.dispose() }
})
