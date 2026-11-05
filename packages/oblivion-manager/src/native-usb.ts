import { z } from "zod"

export const liveMedia = z.object({
  version: z.literal(1),
  devices: z.array(z.object({
    id: z.string().regex(/^[0-9a-f]{64}$/),
    name: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
    bytes: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    read_only: z.boolean(),
  })).max(64),
})

export type LiveDevice = z.infer<typeof liveMedia>["devices"][number]
export type UsbBrowser = {
  page: (path: string, after?: string) => Promise<unknown>
  close: () => Promise<void>
}

export type NativeUsbClient = {
  open: (safe: string, device: string, opening: string) => UsbBrowser
  operate: (args: string[], signal: AbortSignal) => Promise<unknown>
  close: () => Promise<void>
}

export function createNativeUsbClient(launcher: string): NativeUsbClient {
  let active: UsbBrowser | undefined
  let operation: { cancel: () => void; exited: Promise<number> } | undefined
  return {
    open(safe: string, device: string, opening: string): UsbBrowser {
      if (active || operation) throw new Error("A USB attachment is already open.")
      const child = Bun.spawn([launcher, "files", "usb-browse", "--safe", safe, "--usb", device, "--opening", opening], {
        stdin: "pipe", stdout: "pipe", stderr: "ignore",
      })
      const reader = child.stdout.getReader()
      let busy = false
      let stopping: Promise<void> | undefined
      async function wait(milliseconds: number) {
        let clear = () => {}
        try {
          return await Promise.race([child.exited, new Promise<undefined>((resolve) => { const timer = setTimeout(resolve, milliseconds); clear = () => clearTimeout(timer) })])
        } finally { clear() }
      }
      const browser: UsbBrowser = {
        async page(path, after) {
          if (stopping || busy) throw new Error("The USB browser is unavailable.")
          busy = true
          try {
            child.stdin.write(JSON.stringify({ path, after: after ?? null, limit: 100 }) + "\n")
            await child.stdin.flush()
            const line = new Uint8Array(512 * 1024)
            let length = 0
            while (true) {
              const chunk = await reader.read()
              if (chunk.done || length + chunk.value.length > line.length) throw new Error("The USB directory reply is unavailable.")
              const newline = chunk.value.indexOf(10)
              if (newline >= 0 && newline !== chunk.value.length - 1) throw new Error("Invalid USB directory reply.")
              line.set(chunk.value, length)
              length += chunk.value.length
              if (newline >= 0) return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line.subarray(0, length - 1))) as unknown
            }
          } finally { busy = false }
        },
        close() {
          return stopping ??= (async () => {
            try { await child.stdin.end() } catch { /* The child may have exited after revocation. */ }
            const code = await wait(100_000)
            if (code === 0) return
            if (code === undefined) {
              child.kill("SIGTERM")
              if (await wait(2000) === undefined) { child.kill("SIGKILL"); await wait(2000) }
            }
            throw new Error("USB removal was not confirmed. Check the runtime before continuing.")
          })()
        },
      }
      active = browser
      void child.exited.then(async () => {
        if (active === browser) active = undefined
        await reader.cancel().catch(() => {})
      })
      return browser
    },
    async operate(args, signal) {
      if (active || operation || signal.aborted) throw new Error("A USB attachment is unavailable.")
      const child = Bun.spawn([launcher, "files", ...args, "--json"], { stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout: 40 * 60_000 })
      const cancel = () => { if (child.exitCode === null) child.kill("SIGTERM") }
      const running = { cancel, exited: child.exited }
      operation = running
      signal.addEventListener("abort", cancel, { once: true })
      if (signal.aborted) cancel()
      try {
        const [text, code] = await Promise.all([new Response(child.stdout).text(), child.exited])
        if (signal.aborted || code !== 0 || Buffer.byteLength(text) > 8192) throw new Error("The USB operation was not confirmed.")
        return JSON.parse(text) as unknown
      } finally {
        signal.removeEventListener("abort", cancel)
        if (operation === running) operation = undefined
      }
    },
    async close() {
      const running = operation
      running?.cancel()
      await Promise.all([active?.close(), running?.exited])
    },
  }
}
