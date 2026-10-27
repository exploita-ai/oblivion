import { setTimeout } from "node:timers/promises"
import { ControlError } from "./control"

// The controller checks readiness before granting a capability. An aborted
// in-flight call must settle before the caller requests ordered cleanup.
export async function startWhenReady(start: () => Promise<void>, options: {
  signal: AbortSignal;
  waiting: (value: boolean) => void | Promise<void>;
  wait?: () => Promise<void>;
  now?: () => number;
}) {
  const now = options.now ?? performance.now.bind(performance)
  const deadline = now() + 120_000
  const remaining = () => {
    if (options.signal.aborted) throw new ControlError("chat_start_cancelled")
    if (now() >= deadline) throw new ControlError("gateway_connect_timeout")
  }
  try {
    for (let attempt = 0; attempt < 40; attempt++) {
      remaining()
      await options.waiting(true)
      remaining()
      try {
        await start()
        remaining()
        return
      } catch (error) {
        remaining()
        if (!(error instanceof ControlError) || error.code !== "gateway_not_ready") throw error
      }
      if (attempt === 39) throw new ControlError("gateway_connect_timeout")
      try {
        await (options.wait?.() ?? setTimeout(Math.min(3000, Math.max(0, deadline - now())), undefined, { signal: options.signal }))
      } catch (error) {
        remaining()
        throw error
      }
    }
  } finally { await options.waiting(false) }
}
