import { useTerminalDimensions } from "@opentui/solid"
import { theme } from "./theme"

export function PageHeader(props: { title: string; description: string }) {
  const dimensions = useTerminalDimensions()
  const spacious = () => dimensions().width >= 110 && dimensions().height >= 32
  return <box flexShrink={0} flexDirection="column" gap={spacious() ? 1 : 0} paddingBottom={spacious() ? 2 : 1}>
    <text fg={theme.text.base}><b>{props.title}</b></text>
    <text fg={theme.text.muted}>{props.description}</text>
  </box>
}
