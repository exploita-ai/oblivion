// Local UX harness: displays the real OpenTUI framebuffer in a browser.
// Uses only the in-memory preview runtime. Never connects to the host controller.
import { testRender } from "@opentui/solid"
import { z } from "zod"
import { App } from "../src/app"
import { preview } from "../src/preview"
import { status } from "../src/state"

const input = z.discriminatedUnion("action", [
  z.object({ action: z.literal("key"), key: z.string().max(32), ctrl: z.boolean(), shift: z.boolean() }),
  z.object({ action: z.literal("paste"), text: z.string().max(1024) }),
  z.object({ action: z.literal("resize"), width: z.number().int().min(60).max(200), height: z.number().int().min(20).max(60) }),
  z.object({ action: z.literal("reset"), locked: z.boolean() }),
])
let width = 120
let height = 36
// Keep async status acquisition outside the synchronous component factory.
async function mount(locked = false) {
  const runtime = preview(() => {})
  if (locked) await runtime.request({ operation: "lock" })
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  return testRender(() => <App runtime={runtime} preview initial={initial} />, { width, height, kittyKeyboard: true, exitOnCtrlC: false })
}
let app = await mount()
const server = Bun.serve({
  hostname: "127.0.0.1", port: Number(process.env.OBLIVION_PREVIEW_PORT ?? 0),
  async fetch(request) {
    const url = new URL(request.url)
    if (url.pathname === "/") return new Response(Bun.file(new URL("preview-ui.html", import.meta.url)), { headers: { "Content-Type": "text/html; charset=utf-8" } })
    if (url.pathname === "/input" && request.method === "POST") {
      const value = input.parse(await request.json())
      if (value.action === "resize") { width = value.width; height = value.height; app.resize(width, height) }
      if (value.action === "key") app.mockInput.pressKey(value.key, { ctrl: value.ctrl, shift: value.shift })
      if (value.action === "paste") await app.mockInput.pasteBracketedText(value.text)
      if (value.action === "reset") { await app.dispose(); app = await mount(value.locked) }
    }
    if (url.pathname !== "/frame" && url.pathname !== "/input") return new Response("Not found", { status: 404 })
    await app.renderOnce()
    const frame = app.captureSpans()
    return Response.json({ cols: frame.cols, rows: frame.rows, lines: frame.lines.map((line) => line.spans.map((span) => ({ text: span.text, fg: span.fg.toInts().slice(0, 3), bg: span.bg.toInts().slice(0, 3), bold: !!(span.attributes & 1) }))) })
  },
})
console.log(`Oblivion UI preview: ${server.url}`)
process.on("SIGINT", async () => { await app.dispose(); server.stop(); process.exit(0) })
