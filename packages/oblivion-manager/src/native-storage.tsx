import { FormView } from "./form"
import { capacity, type NativeStatus } from "./native-control"

export function storageUnavailable(state: NativeStatus | undefined) {
  if (!state) return "Refresh the runtime status before preparing encrypted storage."
  if (state.recovery_required) return "Complete runtime recovery before preparing encrypted storage."
}

export function NativeStorage(props: { bytes: number; reset: boolean; back: () => void; submit: () => void }) {
  return <FormView form={{
    title: props.reset ? "Reset incomplete storage setup" : "Create encrypted storage",
    description: props.reset
      ? "Remove only the unfinished app archive. Published encrypted storage cannot be reset through this action. This does not create or unlock a new archive."
      : `Managed encrypted archive · ${capacity(props.bytes)}\nCreate the archive inside the controller VM's data disk. Each persistent Safe gets a separate encrypted volume.\nYou will choose a password after confirming. Creation leaves Oblivion locked.`,
    fields: [], submit: props.reset ? "Reset unfinished app storage" : "Confirm storage and choose password", run: async () => {},
  }} cancel={props.back} submit={props.submit} />
}
