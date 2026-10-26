import { createConnection, createServer } from "node:net"
import { chmod, unlink } from "node:fs/promises"
import type { CliRenderer, KeyEvent } from "@opentui/core"
import { z } from "zod"

const limit = 256 * 1024
const endpoint = "/run/oblivion-manager/clipboard.sock"
const message = z.discriminatedUnion("action", [
  z.object({ action: z.literal("copy") }).strict(),
  z.object({ action: z.literal("paste"), text: z.string().max(limit) }).strict(),
])

// The trusted manager owns selection and explicit paste. The guest cannot read
// this socket or issue clipboard requests through its filtered terminal output.
export function createManagerClipboard(renderer: CliRenderer) {
  let text = ""
  const copy = () => {
    const selected = renderer.getSelection()?.getSelectedText() ?? ""
    if (!selected || Buffer.byteLength(selected) > limit) return ""
    text = selected
    renderer.copyToClipboardOSC52(selected)
    return selected
  }
  const paste = (value = text) => {
    if (Buffer.byteLength(value) > limit) throw new RangeError("Clipboard text is too long")
    // Plain text only. In particular a pasted escape cannot end bracketed paste.
    renderer.keyInput.processPaste(new TextEncoder().encode(value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")))
  }
  const clear = () => { text = ""; renderer.clearSelection(); renderer.clearClipboardOSC52() }
  const keyboard = (event: KeyEvent) => {
    if (!(event.ctrl || event.super) || !["c", "v"].includes(event.name)) return
    event.preventDefault(); event.stopPropagation()
    if (event.name === "c") { copy(); return }
    paste()
  }
  renderer.keyInput.on("keypress", keyboard)
  return { copy, paste, clear, dispose() { clear(); renderer.keyInput.off("keypress", keyboard) } }
}

export async function serveClipboard(clipboard: ReturnType<typeof createManagerClipboard>, path = endpoint) {
  // The containing runtime directory is private to the manager. No network port.
  await unlink(path).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error })
  const server = createServer((socket) => {
    socket.setTimeout(3000, () => socket.destroy())
    const chunks: Buffer[] = []
    let size = 0
    socket.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size > limit * 6 + 128) { socket.destroy(); return }
      chunks.push(chunk)
    })
    socket.on("end", () => {
      try {
        const request = message.parse(JSON.parse(Buffer.concat(chunks).toString("utf8")))
        if (request.action === "paste") clipboard.paste(request.text)
        socket.end(JSON.stringify({ text: request.action === "copy" ? clipboard.copy() : "" }))
      } catch { socket.end(JSON.stringify({ error: "clipboard_request_failed" })) }
      finally { chunks.forEach((chunk) => chunk.fill(0)) }
    })
    socket.on("error", () => {})
    socket.on("close", () => chunks.forEach((chunk) => chunk.fill(0)))
  })
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(path, resolve) })
  await chmod(path, 0o600)
  return () => { server.close(); void unlink(path).catch(() => {}) }
}

// Development-only SSH adapter used by the Mac laboratory's explicit Cmd+C/V.
// Payloads use pipes, never arguments, files, logs, or automatic synchronization.
export async function clipboardClient(action: string, path = endpoint) {
  if (!["copy", "paste"].includes(action)) throw new Error("Invalid clipboard action")
  const bytes = action === "paste" ? await Bun.stdin.bytes() : new Uint8Array()
  if (bytes.length > limit) throw new RangeError("Clipboard text is too long")
  const input = JSON.stringify({ action, ...(action === "paste" ? { text: new TextDecoder().decode(bytes) } : {}) })
  bytes.fill(0)
  return new Promise<string>((resolve, reject) => {
    const socket = createConnection(path)
    const chunks: Buffer[] = []
    let size = 0
    socket.setTimeout(5000, () => socket.destroy(new Error("Clipboard unavailable")))
    socket.on("connect", () => socket.end(input))
    socket.on("data", (chunk: Buffer) => { size += chunk.length; if (size > limit * 6 + 128) { socket.destroy(new Error("Clipboard response too long")); return }; chunks.push(chunk) })
    socket.on("error", reject)
    socket.on("end", () => {
      try {
        const result = z.object({ text: z.string().max(limit) }).parse(JSON.parse(Buffer.concat(chunks).toString("utf8")))
        resolve(result.text)
      } catch { reject(new Error("Clipboard unavailable")) }
      finally { chunks.forEach((chunk) => chunk.fill(0)) }
    })
  })
}
