import { createSignal } from "solid-js"
import { Menu } from "./menu"
import { capacity, type NativeStatus } from "./native-control"

export function requestedAgentName(agent: NativeStatus["agent_safes"][number]["agent"]) {
  return agent === "codex" ? "Codex" : agent === "claude" ? "Claude Code" : "OpenCode 2"
}

export function SafeInspector(props: { state: NativeStatus; id: string; blocked?: string; task: () => void; launch: (agent: NativeStatus["agent_safes"][number]["agent"]) => void; choose: () => void; back: () => void }) {
  const [selected, setSelected] = createSignal(0)
  const record = () => props.state.agent_safes.find((entry) => entry.id === props.id)
  const opened = () => props.state.open_sessions.find((entry) => entry.id === props.id)
  const parent = () => props.state.safe_parents.find((entry) => entry.id === props.id)?.parent ?? record()?.parent
  const title = (id: string) => props.state.session_titles[id] ?? `Safe ${id.slice(0, 8)}`
  const known = () => props.state.sessions.includes(props.id) || !!record() || !!opened()
  const storage = () => !known() ? "Storage unavailable" : record()?.ephemeral || !props.state.sessions.includes(props.id) && !!opened() ? "RAM only" : "Persistent"
  const bytes = () => props.state.session_sizes?.[props.id] ?? (record() ? record()!.mib * 1024 ** 2 : undefined)
  const current = () => !known() ? "Not in current catalog" : props.state.recovery_required || opened()?.recovery_required ? "Recovery required" : opened() ? `Open · ${opened()!.mode === "documents" ? "Files VM" : "Native workspace VM"}`
    : record()?.state === "failed" ? "Creation failed" : record()?.state === "recovery-required" ? "Recovery required" : "Closed"
  const items = () => [
    ...(record() ? [{ name: "Review saved task", description: "Open this Safe offline and read the exact saved task before execution. Opening the review does not submit it.",
      disabled: props.blocked, action: "Open task review", run: () => { if (!props.blocked) props.task() } }] : []),
    ...(record() ? [{ name: "Open requested agent", description: props.blocked ? "This creation record cannot start an interactive client." : `Open ${requestedAgentName(record()!.agent)} interactively. The stored task is not submitted. Native login controls remain available if needed.`,
      disabled: props.blocked, action: "Open requested agent", run: () => { if (!props.blocked && record()) props.launch(record()!.agent) } }] : []),
    { name: record() ? "Choose another agent" : "Choose an agent", description: "Choose a different official client in this Safe.", disabled: props.blocked, action: "Choose agent", run: () => { if (!props.blocked) props.choose() } },
  ]
  return <Menu title={`Review Safe · ${title(props.id)} (${props.id.slice(0, 8)})`} description={[
    `Current · ${current()} · ${storage()}${bytes() ? ` · ${capacity(bytes()!)}${props.state.session_sizes?.[props.id] ? "" : " requested"}` : ""}`,
    `Parent · ${parent() ? `${title(parent()!)} (${parent()!.slice(0, 8)})` : "No parent recorded"}`,
    record() ? `Agent-created · Requested client: ${requestedAgentName(record()!.agent)}` : "Origin · No local agent-creation record",
    ...(record() ? [`Creation record · ${record()!.state} (not the current process state)`] : []),
  ].join("\n")} items={items()} selected={selected()} change={setSelected} focused choose={(index) => { const item = items()[index]; if (item && !item.disabled) item.run() }} back={props.back} />
}
