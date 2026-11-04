import { useRenderer } from "@opentui/solid"
import { createSignal, onCleanup, onMount, Show } from "solid-js"
import { BootLogo } from "./boot-logo"
import { SafeManager } from "./safe-manager"
import type { NativeRuntime, NativeStatus } from "./native-control"

export type InitialStatus = { state: NativeStatus; received: number }

export function Startup(props: { runtime: NativeRuntime; initial: Promise<InitialStatus | undefined> }) {
  const clock = useRenderer().clock
  const [elapsed, setElapsed] = createSignal(0)
  const [boot, setBoot] = createSignal(true)
  const [initial, setInitial] = createSignal<InitialStatus>()
  const started = clock.now()
  let stopped = false
  const animation = clock.setInterval(() => setElapsed(clock.now() - started), 16)
  const finish = clock.setTimeout(() => { clock.clearInterval(animation); setBoot(false) }, 3000)
  onMount(() => { void props.initial.then((value) => { if (!stopped) setInitial(value) }) })
  onCleanup(() => { stopped = true; clock.clearInterval(animation); clock.clearTimeout(finish) })
  return <Show when={boot()} fallback={<SafeManager runtime={props.runtime} initial={initial()?.state} initialReceived={initial()?.received} />}>
    <BootLogo elapsed={elapsed()} />
  </Show>
}
