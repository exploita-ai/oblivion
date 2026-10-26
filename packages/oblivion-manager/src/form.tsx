import { ScrollBoxRenderable } from "@opentui/core"
import { useKeyboard, usePaste, useTerminalDimensions } from "@opentui/solid"
import { createEffect, createSignal, For, onCleanup, Show } from "solid-js"
import { palette, theme } from "./theme"
import { ActionItem, SelectList } from "@opencode/tui-kit"
import { PageHeader } from "./page-header"

export type Field = {
  id: string
  label: string
  description?: string
  value?: string
  secret?: boolean
  choices?: { value: string; label: string }[]
  validate?: (value: string, values: Record<string, string>) => string | undefined
}

export type Form = {
  title: string
  description: string
  fields: Field[]
  submit: string
  run: (values: Record<string, string>) => Promise<void>
}

export function FormView(props: { form: Form; cancel: () => void; submit: (values: Record<string, string>) => void }) {
  const dimensions = useTerminalDimensions()
  const spacious = () => dimensions().width >= 110 && dimensions().height >= 32
  const [focused, setFocused] = createSignal(0)
  const [values, setValues] = createSignal(Object.fromEntries(props.form.fields.map((field) => [field.id, field.value ?? field.choices?.[0]?.value ?? ""])))
  const [error, setError] = createSignal("")
  let scroll: ScrollBoxRenderable | undefined

  createEffect(() => {
    const target = scroll?.getChildren()[focused()]
    if (!scroll || !target) return
    const y = target.y - scroll.viewport.y
    if (y < 0) scroll.scrollBy(y)
    if (y + target.height > scroll.viewport.height) scroll.scrollBy(y + target.height - scroll.viewport.height)
  })

  function insert(text: string) {
    const field = props.form.fields[focused()]
    if (!field || field.choices) return
    const value = values()[field.id] + text.replace(/[\x00-\x1f\x7f-\x9f]/g, "")
    if (Buffer.byteLength(value) > 1024) {
      setError("This field is too long (maximum 1024 bytes).")
      return
    }
    setValues((before) => ({ ...before, [field.id]: value }))
    setError("")
  }

  function submit() {
    const invalid = props.form.fields.find((field) => field.validate?.(values()[field.id], values()))
    if (invalid) { setError(invalid.validate!(values()[invalid.id], values())!); setFocused(props.form.fields.indexOf(invalid)); return }
    setError("")
    props.submit(values())
  }

  usePaste((event) => {
    if (!props.form.fields[focused()]?.secret) return
    event.preventDefault()
    insert(new TextDecoder().decode(event.bytes))
  })
  useKeyboard((key) => {
    if (key.name === "escape") { key.preventDefault(); props.cancel(); return }
    if (key.name === "tab") { key.preventDefault(); setFocused((before) => (before + (key.shift ? props.form.fields.length : 1)) % (props.form.fields.length + 1)); return }
    if (key.name === "return") {
      key.preventDefault()
      if (focused() < props.form.fields.length) {
        const field = props.form.fields[focused()]
        const invalid = field.validate?.(values()[field.id], values())
        if (invalid) { setError(invalid); return }
        setError(""); setFocused(focused() + 1); return
      }
      submit()
      return
    }
    const field = props.form.fields[focused()]
    if (!field?.secret) return
    key.preventDefault()
    if (key.ctrl && key.name === "u") return setValues((before) => ({ ...before, [field.id]: "" }))
    if (key.name === "backspace") return setValues((before) => ({ ...before, [field.id]: Array.from(before[field.id]).slice(0, -1).join("") }))
    if (!key.ctrl && !key.meta && !key.super && key.sequence && !key.sequence.startsWith("\x1b")) insert(key.sequence)
  })
  onCleanup(() => setValues({}))

  return <box flexGrow={1} minHeight={0}>
    <box width="100%" maxHeight="100%" minHeight={0} flexShrink={1} flexDirection="column" gap={1}>
      <PageHeader title={props.form.title} description={props.form.description} />
      <scrollbox ref={(value) => { scroll = value }} flexShrink={1} minHeight={0} contentOptions={{ minHeight: 0 }}>
        <For each={props.form.fields}>{(field, index) => (
          <box onMouseDown={() => setFocused(index())} flexDirection="column" gap={spacious() ? 1 : 0} paddingBottom={1} flexShrink={0}>
            <box flexDirection="row">
              <text width={2} flexShrink={0} fg={theme.formfield.marker}>{focused() === index() ? "›" : ""}</text>
              <text fg={focused() === index() ? theme.formfield.focused : theme.formfield.label}>{field.label}</text>
            </box>
            <box paddingLeft={1} paddingRight={1} border={true} borderColor={focused() === index() ? theme.border.focused : theme.border.base} backgroundColor={theme.background.field}>
              <Show when={field.choices} fallback={
                <Show when={field.secret} fallback={<input flexGrow={1} value={values()[field.id]} focused={focused() === index()} maxLength={1024} onInput={(value) => { setValues((before) => ({ ...before, [field.id]: value })); setError("") }} textColor={theme.text.base} backgroundColor={theme.background.field} focusedBackgroundColor={theme.background.field} />}>
                  <text fg={theme.formfield.focused}>{"*".repeat(Math.min(56, Array.from(values()[field.id] ?? "").length))}{focused() === index() ? "_" : ""}</text>
                </Show>
              }>{(choices) => <SelectList theme={palette} height={Math.min(3, choices().length)} focused={focused() === index()}
                items={choices().map((choice) => ({ title: choice.label }))}
                selected={Math.max(0, choices().findIndex((choice) => choice.value === values()[field.id]))}
                onFocus={() => setFocused(index())}
                onChange={(selected) => setValues((before) => ({ ...before, [field.id]: choices()[selected].value }))} />}</Show>
            </box>
            <Show when={field.description || field.secret}><text paddingLeft={2} fg={theme.text.muted}>{field.description ?? "Hidden · Ctrl+U to clear"}</text></Show>
          </box>
        )}</For>
      </scrollbox>
      <Show when={error()}><text flexShrink={0} fg={theme.feedback.error}>! {error()}</text></Show>
      <box flexShrink={0} flexDirection="row" gap={3} border={spacious() ? ["top"] : []} borderColor={theme.border.base} paddingTop={spacious() ? 1 : 0}>
        <ActionItem theme={palette} modern flush variant="primary" focused={focused() === props.form.fields.length}
          action={{ title: props.form.submit, key: "Enter", onTrigger: submit }} />
        <ActionItem theme={palette} modern flush variant="secondary" action={{ title: "Cancel", key: "Esc", onTrigger: props.cancel }} />
      </box>
      <Show when={props.form.fields.length}><text flexShrink={0} fg={theme.text.muted}>{focused() === props.form.fields.length ? "Enter confirms · Shift+Tab edit fields" : "Tab next · Shift+Tab previous · Enter continue"}</text></Show>
    </box>
  </box>
}
