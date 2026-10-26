import { createSignal, Show } from "solid-js"
import { z } from "zod"
import { theme } from "./theme"
import { BusyModal } from "./busy-modal"
import { FormView } from "./form"
import { Picker } from "./picker"
import type { Preferences } from "./state"

const choice = z.object({ value: z.string(), label: z.string() })
export const catalog = z.object({ keyboards: z.array(choice.extend({ variants: z.array(choice) })), timezones: z.array(z.string()) })
export type Catalog = z.infer<typeof catalog>

export function Setup(props: { catalog: Catalog; current: Preferences; writable: boolean; applyKeyboard: (keyboard: string, variant: string) => Promise<void>; save: (value: Preferences, persist: boolean) => Promise<void>; cancel: () => void; failed: (error: unknown) => void }) {
  const [step, setStep] = createSignal(0)
  const [keyboard, setKeyboard] = createSignal(props.current.keyboard)
  const [variant, setVariant] = createSignal(props.current.variant)
  const [area, setArea] = createSignal(props.current.timezone.split("/")[0])
  const [timezone, setTimezone] = createSignal(props.current.timezone)
  const [saving, setSaving] = createSignal(false)
  const areas = () => [...new Set(props.catalog.timezones.map((zone) => zone.split("/")[0]))].map((value) => ({ value, label: value }))
  const stage = () => step() === 0 || step() === 1 ? 0 : step() === 5 ? 1 : step() === 2 || step() === 3 ? 2 : 3
  return <box flexGrow={1} minHeight={0} flexDirection="column" gap={1}>
    <text flexShrink={0} fg={theme.text.muted}>{["Keyboard", "Test", "Time zone", "Review"].map((label, index) => index === stage() ? `[${label}]` : label).join("   /   ")}</text>
    <Show when={!saving()} fallback={<BusyModal text="Applying preferences" />}>
    <Show when={step() === 0}><Picker title="Keyboard / Layout" description="Choose your keyboard layout. Type to search." choices={props.catalog.keyboards} selected={keyboard()} choose={(value) => { setKeyboard(value); setVariant(value === props.current.keyboard ? props.current.variant : ""); setStep(1) }} back={props.cancel} /></Show>
    <Show when={step() === 1}><Picker title="Keyboard / Variant" description="Choose the standard layout or a regional variant." choices={props.catalog.keyboards.find((layout) => layout.value === keyboard())?.variants ?? []} selected={variant()} choose={(value) => {
      setVariant(value); setSaving(true)
      void props.applyKeyboard(keyboard(), value).then(() => { setStep(5); setSaving(false) }).catch((error) => { setSaving(false); props.failed(error) })
    }} back={() => setStep(0)} /></Show>
    <Show when={step() === 5}><FormView form={{ title: "Keyboard / Test", description: "The selected layout is applied temporarily. Check letters and symbols before using a password.", fields: [{ id: "sample", label: "Type a harmless sample (@ - / :)", description: "This sample is discarded. Do not type a password." }], submit: "Continue to time zone", run: async () => {} }} cancel={() => setStep(1)} submit={() => setStep(2)} /></Show>
    <Show when={step() === 2}><Picker title="Time zone / Region" description="Choose a region, or UTC." choices={areas()} selected={area()} choose={(value) => { setArea(value); if (value === "UTC") { setTimezone("UTC"); setStep(4); return }; setStep(3) }} back={() => setStep(5)} /></Show>
    <Show when={step() === 3}><Picker title={`Time zone / ${area()}`} description="Choose the nearest city in your time zone." choices={props.catalog.timezones.filter((zone) => zone.startsWith(area() + "/")).map((value) => ({ value, label: value.slice(area().length + 1).replaceAll("_", " ") }))} selected={timezone()} choose={(value) => { setTimezone(value); setStep(4) }} back={() => setStep(2)} /></Show>
    <Show when={step() === 4}><FormView form={{ title: "Review your setup", description: `${keyboard()}${variant() ? ` / ${variant()}` : ""} · ${timezone()} · Local time: ${new Intl.DateTimeFormat("en-GB", { timeZone: timezone(), dateStyle: "medium", timeStyle: "short" }).format(new Date())}`, fields: [], submit: props.writable ? "Apply preferences" : "Apply temporarily", run: async () => {} }} cancel={() => setStep(2)} submit={() => {
      setSaving(true)
      void props.save({ version: 1, completed: props.writable, keyboard: keyboard(), variant: variant(), timezone: timezone() }, props.writable).catch((error) => { setSaving(false); props.failed(error) })
    }} /></Show>
  </Show></box>
}
