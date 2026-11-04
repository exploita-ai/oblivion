import { FormView } from "./form"
import { capacity, type NativeStatus, type StoragePlan } from "./native-control"

export function storageUnavailable(state: NativeStatus | undefined) {
  if (!state?.persistence || state.general_present) return undefined
  if (state.persistence.plan && !state.persistence.unavailable) return undefined
  if (state.persistence.unavailable === "usb_no_free_space") return "Not enough unused space after the live image. Use a larger writable boot medium."
  if (["usb_foreign_partitions", "usb_live_layout_unsupported", "usb_partition_table_unsupported"].includes(state.persistence.unavailable ?? "")) return "The boot medium has an unsupported partition layout. Oblivion will not modify it."
  return "Live persistence needs a writable boot USB or virtio disk containing the Oblivion image. A read-only ISO with an arbitrary second disk is not supported."
}

export function NativeStorage(props: { plan: StoragePlan | null; reset: boolean; back: () => void; submit: () => void }) {
  const device = () => props.plan
    ? `Boot medium: /dev/${props.plan.device} · ${capacity(props.plan.disk_bytes)} total\nData partition: ${props.plan.partition} · starts at ${capacity(props.plan.start * 512)} · ${capacity(props.plan.sectors * 512)} raw capacity\n`
    : "Managed app archive\n"
  return <FormView form={{
    title: props.reset ? "Reset incomplete storage setup" : "Create encrypted storage",
    description: `${device()}${props.reset
      ? "Remove only the unfinished app archive. Published encrypted storage cannot be reset through this action. This does not create or unlock a new archive."
      : "Create an encrypted app archive in unused space after the live image. Existing boot partitions stay in place. Usable capacity is slightly lower after encryption and filesystem metadata.\nYou will choose a password after confirming this device and space."}`,
    fields: [], submit: props.reset ? "Reset unfinished app storage" : "Confirm storage and choose password", run: async () => {},
  }} cancel={props.back} submit={props.submit} />
}
