import { fileEvent, type FileEvent, type FileFinished, type FileMappingEntry, type FileReview, type NativeFileClient, type RunningFileCopy } from "./native-file-events"

// The protocol cap includes its newline. Keep at most one partial line in RAM.
const lineLimit = 4096
type Schedule = (milliseconds: number, callback: () => void) => () => void

export function createNativeFileClient(launcher: string, schedule: Schedule = (milliseconds, callback) => {
  const timer = setTimeout(callback, milliseconds)
  return () => clearTimeout(timer)
}): NativeFileClient {
  const active = new Set<RunningFileCopy>()
  let closed = false
  return {
    start(request, event) {
      if (closed) throw new Error("File copy client is closing.")
      const child = Bun.spawn([launcher, ...request.args, "--events"], { stdin: "pipe", stdout: "pipe", stderr: "ignore" })
      let exited = false
      let settled = false
      void child.exited.then(() => { exited = true; if (settled) active.delete(handle) })
      let reviewed: FileReview | undefined
      const mappings: FileMappingEntry[] = []
      let mappingDigest: string | undefined
      let mappingSelected: string | undefined
      let completed: FileFinished | undefined
      let approved = false
      let cancelling = false
      let finalizing = false
      let transferred = 0
      let stopping: Promise<void> | undefined

      async function within(milliseconds: number) {
        let clear = () => {}
        try {
          return await Promise.race([child.exited.then(() => true), new Promise<boolean>((resolve) => { clear = schedule(milliseconds, () => resolve(false)) })])
        } finally { clear() }
      }

      async function stop() {
        if (stopping) return stopping
        cancelling = true
        stopping = (async () => {
          if (exited) return
          try { child.stdin.write(JSON.stringify({ action: "cancel", operation_id: request.identity.operation_id }) + "\n"); await child.stdin.end() } catch { /* EOF is also a cancellation boundary. */ }
          if (await within(request.args.includes("--usb") ? 85_000 : 10_000)) return
          child.kill("SIGTERM")
          if (await within(2_000)) return
          child.kill("SIGKILL")
          if (!await within(2_000)) throw new Error("File copy process did not stop. Inspect its recorded outcome.")
        })()
        return stopping
      }

      function accept(value: FileEvent) {
        if (completed || value.identity.operation_id !== request.identity.operation_id || value.identity.safe_id !== request.identity.safe_id || value.identity.opening !== request.identity.opening) throw new Error("File copy identity changed.")
        if (value.event === "mapping") {
          if (reviewed || approved || value.start !== mappings.length || value.total !== request.sources.length || mappingSelected && value.selected !== mappingSelected || mappingDigest && value.mapping_sha256 !== mappingDigest) throw new Error("File copy mapping changed.")
          mappingDigest = value.mapping_sha256
          mappingSelected = value.selected
          mappings.push(...value.entries)
        }
        if (value.event === "review") {
          if (reviewed || approved || value.direction !== request.direction || value.name !== request.name || mappings.length !== request.sources.length || !mappingDigest || value.summary.mapping_sha256 !== mappingDigest) throw new Error("File copy review changed.")
          if (mappingSelected !== (mappings.length === 1 ? mappings[0]?.alias : "selection") || value.summary.entries - value.summary.files - value.summary.directories !== (mappings.length === 1 ? 0 : 1)) throw new Error("File copy selection changed.")
          if (mappings.some((entry) => entry.covered_by !== null && (entry.covered_by >= mappings.length || mappings[entry.covered_by]?.alias === null))) throw new Error("File copy mapping is incomplete.")
          if (new Set(mappings.filter((entry) => entry.alias !== null).map((entry) => entry.alias)).size !== mappings.filter((entry) => entry.alias !== null).length) throw new Error("File copy mapping has duplicate destinations.")
          if (new Bun.CryptoHasher("sha256").update(JSON.stringify([mappingSelected, mappings.map((entry) => [entry.input_index, entry.alias, entry.covered_by])])).digest("hex") !== mappingDigest) throw new Error("File copy mapping digest changed.")
          reviewed = value
        }
        if (value.event === "progress") {
          if (!reviewed || !approved || value.total_bytes !== reviewed.summary.bytes || value.bytes < transferred || finalizing && value.phase !== "finalizing") throw new Error("File copy progress is invalid.")
          transferred = value.bytes
          finalizing = value.phase === "finalizing"
        }
        if (value.event === "finished") {
          if (value.outcome === "completed" && (!reviewed || !approved || value.receipt?.manifest_sha256 !== reviewed.summary.manifest_sha256 || value.receipt.entries !== reviewed.summary.entries || value.receipt.bytes !== reviewed.summary.bytes)) throw new Error("File copy receipt changed.")
          if (value.outcome === "cancelled-before-copy" && approved) throw new Error("File copy cancellation is uncertain.")
          completed = value
        }
        if (!cancelling || value.event === "finished") event(value)
      }

      async function drain() {
        const reader = child.stdout.getReader()
        let pending = new Uint8Array(0)
        try {
          while (true) {
            const chunk = await reader.read()
            if (chunk.done) break
            let start = 0
            while (start < chunk.value.length) {
              const newline = chunk.value.indexOf(10, start)
              const end = newline === -1 ? chunk.value.length : newline + 1
              const length = pending.length + end - start
              if (length > lineLimit) throw new Error("File copy response is too large.")
              const line = new Uint8Array(length)
              line.set(pending); line.set(chunk.value.subarray(start, end), pending.length)
              pending = line
              start = end
              if (newline === -1) continue
              accept(fileEvent.parse(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line))))
              pending = new Uint8Array(0)
            }
          }
          if (pending.length) throw new Error("File copy response ended early.")
        } finally { reader.releaseLock() }
      }

      const output = drain().catch(async () => { await stop(); throw new Error("File copy result is unavailable. Inspect its recorded outcome.") })
      const done = Promise.all([output, child.exited]).then(([, code]) => ({ code, finished: completed })).finally(() => { settled = true; if (exited) active.delete(handle) })
      // A component can disappear before it attaches its final-result handler.
      // Cleanup still owns and reaps the process without an unhandled rejection.
      void done.catch(() => {})
      const handle: RunningFileCopy = {
        async approve(digest) {
          if (!reviewed || approved || cancelling || completed || digest !== reviewed.summary.manifest_sha256) throw new Error("Review this exact copy before approving it.")
          approved = true
          try { child.stdin.write(JSON.stringify({ action: "approve", operation_id: request.identity.operation_id, manifest_sha256: digest }) + "\n"); await child.stdin.flush() }
          catch { await stop(); throw new Error("File copy approval was not delivered.") }
        },
        async cancel() { await stop(); await done.catch(() => {}) },
        done,
      }
      active.add(handle)
      return handle
    },
    async close() {
      closed = true
      const results = await Promise.allSettled([...active].map((copy) => copy.cancel()))
      if (results.some((result) => result.status === "rejected")) throw new Error("File copy cleanup is incomplete. Inspect recorded outcomes before exiting.")
    },
  }
}
