import path from "node:path"
import { z } from "zod"
import { maximumPathBytes, maximumPaths } from "./local-path"

const reply = z.object({ paths: z.array(z.string()).max(maximumPaths) }).strict()
// JSON can encode one input byte as a six-byte escape.
const maximumReply = maximumPathBytes * 6 + maximumPaths * 3 + 32

export function createNativeFilePicker(launcher: string) {
  const helper = path.join(path.dirname(launcher), process.platform === "win32" ? "oblivion-vm.exe" : "oblivion-vm")
  let active: { stop: () => Promise<void> } | undefined
  return {
    async choose(signal: AbortSignal) {
      if (signal.aborted) return []
      if (active || !path.isAbsolute(launcher)) throw new Error("Desktop picker unavailable")
      const child = Bun.spawn([helper, "pick-files"], {
        stdin: "pipe", stdout: "pipe", stderr: "ignore", timeout: 30 * 60_000,
      })
      let exited = false
      let stopping: Promise<void> | undefined
      const owner = { stop }
      active = owner
      void child.exited.then(() => { exited = true; if (active === owner) active = undefined })

      async function within(milliseconds: number) {
        let timer: ReturnType<typeof setTimeout> | undefined
        try {
          return await Promise.race([child.exited.then(() => true), new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), milliseconds) })])
        } finally { clearTimeout(timer) }
      }

      function stop() {
        return stopping ??= (async () => {
          if (exited) return
          try { await child.stdin.end() } catch { /* The window may have closed. */ }
          if (await within(2000)) return
          child.kill("SIGKILL")
          if (!await within(2000)) throw new Error("Desktop picker did not stop")
        })()
      }

      const abort = () => { void stop().catch(() => {}) }
      signal.addEventListener("abort", abort, { once: true })
      if (signal.aborted) abort()
      try {
        const [paths, code] = await Promise.all([readSelection(child.stdout), child.exited])
        if (signal.aborted) return []
        if (code !== 0) throw new Error("Desktop picker unavailable")
        return paths
      } catch {
        await stop()
        if (signal.aborted) return []
        throw new Error("Desktop picker unavailable")
      } finally {
        signal.removeEventListener("abort", abort)
      }
    },
    async close() { await active?.stop() },
  }
}

async function readSelection(stream: ReadableStream<Uint8Array>) {
  const reader = stream.getReader()
  const buffer = new Uint8Array(maximumReply)
  let bytes = 0
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      if (chunk.value.length > buffer.length - bytes) throw new Error("Desktop picker reply is too large")
      buffer.set(chunk.value, bytes)
      bytes += chunk.value.length
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytes))
    return reply.parse(JSON.parse(text)).paths
  } finally { reader.releaseLock() }
}
