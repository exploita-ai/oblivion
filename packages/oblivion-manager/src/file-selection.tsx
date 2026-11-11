import { createSignal } from "solid-js"
import { useKeyboard } from "@opentui/solid"
import { Menu } from "./menu"

export type FileSelection = { paths: string[]; change: (paths: string[]) => void; continue: () => void }

// Only exact selections are deduplicated here. The backend resolves aliases,
// overlapping folders and filesystem identity before the approval review.
export function selectionError(paths: string[]) {
  if (paths.length > 128) return "Choose at most 128 files or folders. Remove an item from Selected items to continue."
  if (paths.reduce((bytes, value) => bytes + Buffer.byteLength(value), 0) > 64 * 1024) return "Selected paths exceed 64 KiB. Remove an item from Selected items to continue."
}

export function SelectionBasket(props: { selection: FileSelection; back: () => void }) {
  const [selected, setSelected] = createSignal(0)
  useKeyboard((key) => {
    if (key.defaultPrevented || key.name !== "c" || !props.selection.paths.length) return
    key.preventDefault(); props.selection.continue()
  })
  return <Menu title="Selected items" description={`${props.selection.paths.length} selected · Items keep their selection order. Choose an item to remove it; continue to review destination names before copying.`}
    items={props.selection.paths.map((value) => ({ name: value, description: value, action: "Remove selection", run: () => {} }))}
    selected={Math.min(selected(), Math.max(0, props.selection.paths.length - 1))} change={setSelected} focused
    choose={(index) => props.selection.change(props.selection.paths.filter((_, position) => index !== position))}
    toolbar={[{ title: "Continue", key: "C", disabled: !props.selection.paths.length, run: props.selection.continue }, { title: "Browse", key: "Esc", run: props.back }]}
    empty="No items selected. Return to browsing and use Space to select files or folders." details={false} back={props.back} />
}
