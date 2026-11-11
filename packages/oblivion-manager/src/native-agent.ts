import { closeSync, writeSync } from "node:fs"

export type AgentStartup = "opening" | "connecting" | "gateway-failed" | "gateway-timeout" | "ephemeral-storage-full"
export type AgentEvent = AgentStartup | "safe-closed-before-exit"

export async function launchNativeAgent(
  launcher: string,
  args: string[],
  terminal: { suspend: () => void | Promise<void>; resume: () => void | Promise<void> },
  report: (event: AgentEvent) => void,
) {
  const child = Bun.spawn([launcher, ...args], {
    env: { ...process.env, OBLIVION_MANAGER_HANDOFF: "1" },
    stdio: ["inherit", "inherit", "inherit", "pipe"],
  })
  const descriptor = child.stdio[3]
  let suspended = false
  let completion: "attached" | "failed" | "closed" | undefined
  try {
    try {
      if (descriptor == null) throw new Error("Agent startup channel unavailable")
      // This channel contains only single-byte events. The launcher
      // waits for our acknowledgement before touching the terminal.
      const reader = Bun.file(descriptor).stream().getReader()
      try {
        for (;;) {
          const chunk = await reader.read()
          if (chunk.done) break
          for (const byte of chunk.value) {
            const stage = String.fromCharCode(byte)
            if (completion && !(completion === "attached" && stage === "D")) throw new Error("Unexpected agent event")
            switch (stage) {
              case "P":
              case "R":
                if (suspended) throw new Error("Agent terminal already released")
                suspended = true
                await terminal.suspend()
                if (stage === "R") completion = "attached"
                break
              case "W":
                if (suspended) {
                  await terminal.resume()
                  suspended = false
                }
                report("opening")
                break
              case "G":
                if (suspended) throw new Error("Manager terminal unavailable")
                report("connecting")
                break
              case "F":
              case "T":
              case "S":
                if (suspended) throw new Error("Manager terminal unavailable")
                report(stage === "F" ? "gateway-failed" : stage === "T" ? "gateway-timeout" : "ephemeral-storage-full")
                completion = "failed"
                break
              case "D":
                if (completion !== "attached") throw new Error("Agent terminal was not attached")
                report("safe-closed-before-exit")
                completion = "closed"
                break
              default:
                throw new Error("Invalid agent startup stage")
            }
            if (writeSync(descriptor, "K") !== 1) throw new Error("Agent startup acknowledgement failed")
          }
        }
      } finally { await reader.cancel() }
    } catch (error) {
      // Closing the channel lets the launcher perform its own scoped cleanup.
      // Reap only this child if a broken protocol prevents it from exiting.
      const deadline = setTimeout(() => child.kill("SIGKILL"), 120_000)
      try {
        if (descriptor != null) closeSync(descriptor)
        await child.exited
      } finally { clearTimeout(deadline) }
      throw error
    }
    closeSync(descriptor)
    const code = await child.exited
    if (code === 0 && completion !== "attached") throw new Error("Agent startup completed without terminal handoff")
    return code
  } finally {
    if (suspended) await terminal.resume()
  }
}
