import { Global } from "@opencode/util/global"
import { HeapSnapshot } from "@opencode/util/heap-snapshot"
import { Effect, Queue } from "effect"
import { Oblivion } from "@opencode/util/oblivion"

export const listen = Effect.gen(function* () {
  if (process.platform === "win32") return
  if (Oblivion.enabled) {
    const ignore = () => undefined
    return yield* Effect.acquireRelease(
      Effect.sync(() => process.on("SIGUSR1", ignore)),
      () => Effect.sync(() => process.off("SIGUSR1", ignore)),
    )
  }
  const global = yield* Global.Service
  const signals = yield* Queue.dropping<void>(1)
  yield* Effect.acquireRelease(
    Effect.sync(() => {
      const handler = () => Queue.offerUnsafe(signals, undefined)
      process.on("SIGUSR1", handler)
      return handler
    }),
    (handler) => Effect.sync(() => process.off("SIGUSR1", handler)),
  )
  yield* Queue.take(signals).pipe(
    Effect.andThen(
      HeapSnapshot.write(global.log).pipe(
        Effect.catchCause((cause) => Effect.logError("failed to write heap snapshot", { cause })),
      ),
    ),
    Effect.forever,
    Effect.forkScoped({ startImmediately: true }),
  )
})

export * as Heap from "./heap"
