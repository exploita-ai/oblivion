import { EmbeddedTerminalRenderable } from "@opentui/core"
import { extend } from "@opentui/solid"
import { createEffect, createSignal, onCleanup } from "solid-js"
import { z } from "zod"
import { ControlError } from "./control"

declare module "@opentui/solid" {
  interface OpenTUIComponents { oblivionChat: typeof EmbeddedTerminalRenderable }
}
extend({ oblivionChat: EmbeddedTerminalRenderable })

const event = z.discriminatedUnion("type", [
  z.object({ type: z.literal("frame"), full: z.boolean(), cols: z.number().int().min(24).max(512), rows: z.number().int().min(5).max(297), data: z.string().max(16_000_000) }),
  z.object({ type: z.literal("startup"), status: z.enum(["started", "storage-failed", "client-failed"]) }),
  z.object({ type: z.literal("request"), action: z.enum(["new", "sessions", "close"]) }),
])
export type ChatEvent = z.infer<typeof event>
export type ChatFrame = Extract<ChatEvent, { type: "frame" }>
export type ChatConnection = { input: (data: Uint8Array) => void; resize: (cols: number, rows: number) => void; close: () => void }
export type ChatConnect = (receive: (event: ChatEvent) => void, failed: () => void) => ChatConnection

export const connectChat: ChatConnect = (receive, failed) => connectScreen("--screen", receive, failed)
export const connectTerminal: ChatConnect = (receive, failed) => connectScreen("--terminal-screen", receive, failed)

function connectScreen(mode: string, receive: Parameters<ChatConnect>[0], failed: () => void): ChatConnection {
  const child = Bun.spawn(["/usr/bin/oblivion-console", mode], {
    stdin: "pipe", stdout: "pipe", stderr: "ignore",
    env: { PATH: "/usr/bin:/bin", HOME: "/run/oblivion-manager" },
  })
  let closed = false
  const fail = () => { if (closed) return; closed = true; child.kill(); failed() }
  const send = (value: object) => {
    if (closed) return
    try { child.stdin.write(JSON.stringify(value) + "\n") } catch { fail() }
  }
  // These frames contain conversation text. Keep only the visible screen in RAM;
  // never log child output, parser failures or the underlying exception.
  void (async () => {
    const decoder = new TextDecoder()
    let pending = ""
    for await (const chunk of child.stdout) {
      if (closed) break
      pending += decoder.decode(chunk, { stream: true })
      for (let end = pending.indexOf("\n"); end !== -1; end = pending.indexOf("\n")) {
        const message = event.parse(JSON.parse(pending.slice(0, end)))
        pending = pending.slice(end + 1)
        receive(message)
      }
      if (pending.length > 16_000_000) throw new ControlError("console_failed")
    }
    if (!closed) fail()
  })().catch(fail)
  void child.exited.then(() => { if (!closed) fail() })
  return {
    input(data) {
      for (let offset = 0; offset < data.length; offset += 4096) send({ type: "input", data: [...data.subarray(offset, offset + 4096)] })
    },
    resize(cols, rows) { send({ type: "resize", cols: Math.max(24, Math.min(512, cols)), rows: Math.max(5, Math.min(297, rows)) }) },
    close() { if (closed) return; closed = true; child.stdin.end(); child.kill() },
  }
}

export function ChatViewport(props: {
  connection: ChatConnection; focused: boolean; activate: () => void;
  attach: (receive: ((frame: ChatFrame) => void) | undefined) => void;
}) {
  const [terminal, setTerminal] = createSignal<EmbeddedTerminalRenderable>()
  let size = { cols: 0, rows: 0 }
  let restored = false
  createEffect(() => { if (props.focused) terminal()?.focus(); else terminal()?.blur() })
  props.attach((frame) => {
    if (frame.cols !== size.cols || frame.rows !== size.rows) return
    if (frame.full) restored = true
    // Apply every delta in stream order, not through a coalescing Solid signal.
    if (restored) terminal()?.write(frame.data)
  })
  onCleanup(() => { props.attach(undefined); terminal()?.blur() })
  return <box flexGrow={1} minHeight={5} minWidth={24} overflow="hidden">
    <oblivionChat ref={(value) => {
      // Trusted defaults for cells where the guest did not specify a color.
      value.write("\x1b]10;#e4e4ec\x07\x1b]11;#101014\x07")
      value.on("focused", props.activate)
      setTerminal(value)
    }} width="100%" height="100%" maxScrollback={0} selectable={true}
      onTerminalResize={(cols, rows) => { restored = false; size = { cols, rows }; props.connection.resize(cols, rows) }}
      onData={(data, source) => { if (source === "input" && props.focused) props.connection.input(data) }} />
  </box>
}
