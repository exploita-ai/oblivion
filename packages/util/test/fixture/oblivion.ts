import { Effect } from "effect"
import { HeapSnapshot } from "../../src/heap-snapshot.js"
import { Oblivion } from "../../src/oblivion.js"
import { Observability } from "../../src/observability.js"

await Effect.gen(function* () {
  yield* Effect.logInfo("OBLIVION_LOG_TEST_CANARY_2dc9")
  yield* Effect.void.pipe(Effect.withSpan("OBLIVION_TRACE_TEST_CANARY_9ab1"))
  if (Oblivion.enabled) {
    const error = yield* Effect.flip(HeapSnapshot.write(process.argv[2]))
    if (!(error.cause instanceof Error) || error.cause.message !== "Heap snapshots are disabled in Oblivion")
      throw new Error("Expected explicit snapshot refusal")
  }
}).pipe(Effect.provide(Observability.layer()), Effect.runPromise)
process.stdout.write(JSON.stringify({ oblivion: Oblivion.enabled }))
