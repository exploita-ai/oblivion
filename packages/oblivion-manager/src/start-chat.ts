import { setTimeout } from "node:timers/promises"
import { ControlError } from "./control"

// The controller's start-chat operation checks readiness before stopping the
// offline VM or granting a capability. Only that pending state is retryable.
export async function startWhenReady(start: () => Promise<void>, options: {
  signal: AbortSignal;
  waiting: (value: boolean) => void;
  wait?: () => Promise<void>;
}) {
  for (let attempt = 0; attempt < 40; attempt++) {
    if (options.signal.aborted) throw new ControlError("chat_start_cancelled")
    try { await start(); return } catch (error) {
      if (!(error instanceof ControlError) || error.code !== "gateway_not_ready") throw error
    }
    if (attempt === 39) throw new ControlError("gateway_connect_timeout")
    options.waiting(true)
    try {
      await (options.wait?.() ?? setTimeout(3000, undefined, { signal: options.signal }))
    } catch (error) {
      if (options.signal.aborted) throw new ControlError("chat_start_cancelled")
      throw error
    } finally { options.waiting(false) }
  }
}
