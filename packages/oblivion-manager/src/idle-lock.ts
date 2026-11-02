export type IdleLockAction = "session" | "host"

export function idleLockAction(input: {
  elapsedMs: number
  generalMounted: boolean
  sessionOpen: boolean
  sessionMinutes: number
  hostMinutes: number
}): IdleLockAction | undefined {
  if (!input.generalMounted || input.elapsedMs < 0) return
  if (input.hostMinutes > 0 && input.elapsedMs >= input.hostMinutes * 60_000) return "host"
  if (input.sessionOpen && input.sessionMinutes > 0 && input.elapsedMs >= input.sessionMinutes * 60_000)
    return "session"
}
