import type { NativeStatus } from "./native-control"
import { FormView } from "./form"

function choices(current: number) {
  return Array.from(new Set([0, 5, 10, 15, 30, 60, 120, current])).sort((a, b) => a - b)
    .map((value) => ({ value: String(value), label: value === 0 ? "Disabled — no inactivity lock" : `${value} minutes` }))
}

export function NativeIdle(props: { state: NativeStatus; save: (safe: number, host: number) => void; back: () => void }) {
  return <FormView form={{
    title: "Automatic lock",
    description: `Only keyboard, mouse and paste activity reset these timers. Model output and network traffic do not. Locking stops agents and locks encrypted volumes.\n${props.state.idle_lock.writable ? "Changes are saved automatically in encrypted storage." : "Changes apply in RAM for this run."}\n${props.state.idle_lock.storage === "saved-encrypted" ? "Saved encrypted" : props.state.idle_lock.storage === "ram-only" ? "RAM only" : "Default policy"}`,
    fields: [
      { id: "safe", label: "Lock each Safe after inactivity", description: "Closes that Safe and its child branch, including active agents.", value: String(props.state.idle_lock.preferences.safe_minutes), choices: choices(props.state.idle_lock.preferences.safe_minutes) },
      { id: "host", label: "Lock Oblivion after inactivity", description: "Closes all Safes and locks encrypted storage.", value: String(props.state.idle_lock.preferences.host_minutes), choices: choices(props.state.idle_lock.preferences.host_minutes) },
    ],
    submit: "Apply automatic lock", run: async () => {},
  }} cancel={props.back} submit={(values) => props.save(Number(values.safe), Number(values.host))} />
}
