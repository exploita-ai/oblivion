import { FormView } from "./form"
import { capacity, type NativeStatus } from "./native-control"

export type StorageReview = { mode: "create"; bytes: number } | { mode: "reset" | "repair" }

export function storageUnavailable(state: NativeStatus | undefined) {
  if (!state) return "Refresh the runtime status before preparing encrypted storage."
  if (state.recovery_required) return "Complete runtime recovery before preparing encrypted storage."
  if (state.backing_recovery_required) return "Repair the storage backing before preparing encrypted storage."
}

export function NativeStorage(props: { review: StorageReview; back: () => void; submit: () => void }) {
  const content = () => {
    const review = props.review
    if (review.mode === "create") return {
      title: "Create encrypted storage",
      description: `Managed encrypted archive · ${capacity(review.bytes)}\nCreate the archive inside the controller VM's data disk. Each persistent Safe gets a separate encrypted volume.\nYou will choose a password after confirming. Creation leaves Oblivion locked.`,
      submit: "Confirm storage and choose password",
    }
    if (review.mode === "reset") return {
      title: "Reset incomplete storage setup",
      description: "Remove only the unfinished app archive. Published encrypted storage cannot be reset through this action. This does not create or unlock a new archive.",
      submit: "Reset unfinished app storage",
    }
    return {
      title: "Repair storage backing",
      description: "Repair the runtime storage filesystem. Repair can replay its journal and change filesystem metadata. Oblivion stays locked.",
      submit: "Confirm repair",
    }
  }
  return <FormView form={{ ...content(), fields: [], run: async () => {} }} cancel={props.back} submit={props.submit} />
}
