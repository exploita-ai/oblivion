import type { NativeStatus } from "./native-control"

export function conversationArgs(agent: NativeStatus["agent_safes"][number]["agent"], conversation: "latest" | { id: string }) {
  if (conversation === "latest") return agent === "codex" ? ["resume", "--last"] : ["--continue"]
  return agent === "codex" ? ["resume", conversation.id] : agent === "claude" ? ["--resume", conversation.id] : ["--session", conversation.id]
}
