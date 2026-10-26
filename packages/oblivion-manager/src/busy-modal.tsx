import { BoxRenderable } from "@opentui/core"
import { createSignal, onCleanup, Show } from "solid-js"
import { Portal, useTerminalDimensions } from "@opentui/solid"
import { theme } from "./theme"

export function BusyModal(props: { text: string; cancellable?: boolean }) {
  const size = useTerminalDimensions()
  const [frame, setFrame] = createSignal(0)
  const frames = ["|", "/", "−", "\\"]
  const timer = setInterval(() => setFrame((value) => (value + 1) % frames.length), 100)
  onCleanup(() => clearInterval(timer))
  return <Portal ref={(container) => { if (!(container instanceof BoxRenderable)) return; container.position = "absolute"; container.left = 0; container.top = 0; container.width = "100%"; container.height = "100%" }}><box position="absolute" left={0} top={0} width={size().width} height={size().height} zIndex={3000} backgroundColor={theme.background.base}
    alignItems="center" justifyContent="center" onMouseDown={(event) => event.stopPropagation()} onMouseUp={(event) => event.stopPropagation()}>
    <box width={Math.min(56, size().width - 4)} flexDirection="column" gap={1} padding={2}
      backgroundColor={theme.background.panel} border borderColor={theme.border.base}>
      <box flexDirection="row" gap={2}>
        <text width={1} flexShrink={0} fg={theme.feedback.info}>{frames[frame()]}</text>
        <text fg={theme.text.base}>{props.text}</text>
      </box>
      <Show when={props.cancellable}><text fg={theme.text.muted}>Esc Cancel</text></Show>
    </box>
  </box></Portal>
}
