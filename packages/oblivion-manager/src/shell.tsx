import { For, Show, type JSX } from "solid-js"
import { useTerminalDimensions } from "@opentui/solid"
import { NetworkIndicator, type NetworkLabel, type NetworkConnection } from "./network-indicator"
import { ActionBar } from "./action-bar"
import { BusyModal } from "./busy-modal"
import { theme } from "./theme"

export const sections = ["Sessions", "Network", "API keys", "Keyboard & time zone", "System"] as const
export const accessSections = ["Keyboard & time zone"] as const

export function Shell(props: {
  children: JSX.Element; mounted: boolean; welcome?: boolean;
  breadcrumb: string; page: number; navigation: boolean; editing: boolean;
  network: NetworkLabel; host: string; blocked: boolean; connection: NetworkConnection; transport: string;
  busy: string; cancellable?: boolean; onClose?: () => void; notice: string; feedback: "info" | "success" | "error";
  chat?: boolean; terminal?: boolean; documents?: boolean; activeSession?: string | null; onSection?: (index: number) => void;
  debugAvailable?: boolean; debugActive?: boolean;
  onChat?: () => void; onDocuments?: () => void; onTerminal?: () => void; accessSetting?: number;
}) {
  const dimensions = useTerminalDimensions()
  const wide = () => dimensions().width >= 110
  const spacious = () => wide() && dimensions().height >= 32
  const viewport = () => props.chat || props.terminal
  const hostSelected = (index: number) => props.page === index && !props.chat && !props.documents
  return <box width="100%" height="100%" flexDirection="column" backgroundColor={theme.background.base}>
    <box flexGrow={1} minHeight={0} flexDirection={wide() ? "row" : "column"}>
      <Show when={!props.activeSession}><box width={wide() ? 32 : "100%"} height={wide() ? "100%" : "auto"} flexShrink={0} flexDirection="column"
        paddingLeft={wide() ? 3 : 2} paddingRight={wide() ? 3 : 2} paddingTop={spacious() ? 2 : 1} gap={wide() ? 1 : 0}
        border={wide() ? ["right"] : []} borderColor={theme.border.base} backgroundColor={theme.background.panel}>
        <Show when={wide()}>
          <text fg={theme.text.brand}><b>OBLIVION</b></text>
        </Show>
        <Show when={props.mounted} fallback={<box flexDirection={wide() ? "column" : "row"} gap={1} paddingTop={spacious() ? 2 : 0} paddingBottom={1}>
          <For each={accessSections}>{(name, index) => <NavigationRow
            title={name === "Keyboard & time zone" && !wide() ? "Keyboard / Time" : name}
            active={props.accessSetting === index()} focused={props.navigation && props.page === index()}
            disabled={props.editing} onSelect={() => props.onSection?.(index())} />}</For>
        </box>}>
          <box flexDirection={wide() ? "column" : "row"} gap={1} paddingTop={spacious() ? 2 : 0} paddingBottom={1}>
            <For each={sections}>{(name, index) => <NavigationRow
              title={name === "Keyboard & time zone" && !wide() ? "Keyboard / Time" : name}
              active={hostSelected(index())} focused={props.navigation && props.page === index()}
              disabled={props.editing} onSelect={() => props.onSection?.(index())} />}</For>
          </box>
        </Show>
        <Show when={props.debugAvailable}>
          <box flexGrow={wide() ? 1 : 0} />
          <box paddingBottom={1}>
            <NavigationRow title="Debug" diagnostic active={!!props.debugActive}
              focused={props.navigation && props.page === (props.mounted ? sections.length : accessSections.length)}
              disabled={props.editing} onSelect={() => props.onSection?.(props.mounted ? sections.length : accessSections.length)} />
          </box>
        </Show>
      </box></Show>
      <box flexGrow={1} minWidth={0} minHeight={0} paddingLeft={viewport() ? 0 : wide() ? 4 : 2} paddingRight={viewport() ? 0 : wide() ? 4 : 2} paddingTop={viewport() ? 0 : spacious() ? 2 : 0} flexDirection="column">
        <Show when={!props.welcome && !viewport()}><text height={spacious() ? 3 : 1} flexShrink={0} fg={theme.text.muted}>{props.breadcrumb}</text></Show>
        {props.children}
      </box>
    </box>
    <Show when={!props.busy && props.notice && (!viewport() || props.feedback === "error")}>
      <box flexShrink={0} paddingLeft={2} paddingRight={2} border={["top"]} borderColor={theme.border.base}>
        <text fg={theme.feedback[props.feedback]}>{`${props.feedback === "error" ? "! " : props.feedback === "success" ? "+ " : "i "}${props.notice}`}</text>
      </box>
    </Show>
    <box flexShrink={0} flexDirection={wide() || !props.activeSession ? "row" : "column"} justifyContent="space-between" paddingLeft={wide() ? 3 : 1} paddingRight={wide() ? 3 : 1}
      paddingTop={spacious() ? 1 : 0} paddingBottom={spacious() ? 1 : 0} border={["top"]} borderColor={theme.border.base}>
      <NetworkIndicator label={props.network} host={props.host} blocked={props.blocked} connection={props.connection} transport={props.transport} />
      <Show when={props.mounted}><box alignSelf="flex-end"><ActionBar disabled={props.editing} actions={props.activeSession ? [
        { title: "Chat", key: "F6", run: () => props.onChat?.() },
        { title: "Documents", key: "F7", run: () => props.onDocuments?.() },
        { title: "Terminal", key: "F8", run: () => props.onTerminal?.() },
        { title: "Close", key: "Ctrl+Q", run: () => props.onClose?.() },
      ] : [{ title: "Lock Oblivion", key: "Ctrl+Q", run: () => props.onClose?.() }]} /></box></Show>
    </box>
    <Show when={props.busy}><BusyModal text={props.busy} cancellable={props.cancellable} /></Show>
  </box>
}

function NavigationRow(props: { title: string; active: boolean; diagnostic?: boolean; focused?: boolean; disabled: boolean; onSelect: () => void }) {
  const foreground = () => props.diagnostic ? theme.navigation.debug : props.focused ? theme.navigation.focused : props.active ? theme.navigation.active : theme.navigation.inactive
  return <box flexDirection="row" minWidth={0} height={1} flexShrink={0}
    backgroundColor={props.focused ? theme.background.selection : theme.background.panel}
    onMouseDown={() => { if (!props.disabled) props.onSelect() }}>
    <text width={2} flexShrink={0} fg={foreground()}>{props.focused ? "›" : props.active ? "•" : ""}</text>
    <text flexGrow={1} wrapMode="none" overflow="hidden" fg={foreground()}>{props.title}</text>
  </box>
}
