import path from "node:path"
import type { Stats } from "node:fs"
import { lstat } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import parse from "shell-quote/parse"

export const unsafePathText = /[\p{Cc}\p{Bidi_Control}\p{Zl}\p{Zp}]/u

const maximumPaths = 128
export const maximumPathBytes = 64 * 1024
const fileURL = /^file:/i
const drivePath = /^[a-z]:[\\/]/i
const windowsDevice = /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])$/i

export async function inspectLocalPaths(input: string, current: string, batch: boolean): Promise<{ path: string; info: Stats }[]> {
  if (!input || unsafePathText.test(input) || Buffer.byteLength(input) > maximumPathBytes) throw new Error("Invalid path")
  // A real native filename wins over terminal escaping, including literal
  // backslashes, quotes, spaces and $. Only absence permits interpretation.
  const literal = resolveLocalPath(input, current)
  if (literal) {
    const info = await existingPath(literal)
    if (info) return [{ path: literal, info }]
  }
  const spelling = input.trimStart()
  if (fileURL.test(spelling)) {
    const filename = resolveInput(spelling, current, false)
    if (!batch) return [{ path: filename, info: await lstat(filename) }]
    const info = await existingPath(filename)
    if (info) return [{ path: filename, info }]
  }
  const words = terminalWords(spelling, batch ? maximumPaths : 1)
  const filenames = [...new Set(words.map((value) => resolveInput(value, current, words.length > 1)))]
  if (filenames.reduce((bytes, value) => bytes + Buffer.byteLength(value), 0) > maximumPathBytes) throw new Error("Invalid path")
  return Promise.all(filenames.map(async (filename) => ({ path: filename, info: await lstat(filename) })))
}

function existingPath(filename: string) {
  return lstat(filename).catch((error: unknown) => {
    if (error instanceof Error && "code" in error && (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "ENAMETOOLONG")) return
    throw error
  })
}

function resolveInput(input: string, current: string, absolute: boolean) {
  let value = input
  if (fileURL.test(value)) {
    const url = new URL(value)
    if (url.hostname && url.hostname !== "localhost" || url.search || url.hash) throw new Error("Local URL required")
    value = fileURLToPath(url)
  }
  if (!value || unsafePathText.test(value) || absolute && !(process.platform === "win32" ? drivePath.test(value) : path.isAbsolute(value))) {
    throw new Error("Invalid path")
  }
  const resolved = resolveLocalPath(value, current)
  if (!resolved) throw new Error("Invalid path")
  return resolved
}

function resolveLocalPath(value: string, current: string) {
  if (process.platform !== "win32") return path.resolve(current, value)
  const tail = drivePath.test(value) ? value.slice(2) : value
  if (/^[\\/]{2}/.test(value) || /[:*?"<>|]/.test(tail) ||
    tail.split(/[\\/]/).some((component) => windowsDevice.test(component.split(".")[0]?.trimEnd() ?? ""))) return
  const resolved = path.resolve(current, value)
  if (drivePath.test(resolved)) return resolved
}

function terminalWords(input: string, limit: number) {
  const windows = process.platform === "win32"
  // Windows Terminal wraps names with spaces in double quotes and joins them
  // with spaces by default. Backslashes are path separators, even before a quote.
  // The POSIX scanner requires complete words before calling shell-quote, which
  // otherwise tolerates incomplete quotes and can interpret shell syntax.
  const word = windows ? /"([^"]+)"|([^ "]+)/y : /(?:[^\s'"\\$\x60|&;()<>*?#{}~]|\\[^\n]|'[^']*'|"(?:[^"\\$\x60]|\\[^\n])*")+/y
  const values: string[] = []
  let offset = 0
  while (offset < input.length) {
    word.lastIndex = offset
    const match = word.exec(input)
    if (!match || values.length === limit || word.lastIndex < input.length && input[word.lastIndex] !== " ") throw new Error("Invalid path")
    const parsed = windows ? [match[1] ?? match[2]] : parse(match[0], () => { throw new Error("Shell expansion is not supported") })
    if (parsed.length !== 1 || typeof parsed[0] !== "string" || !parsed[0]) throw new Error("Invalid path")
    values.push(parsed[0])
    offset = word.lastIndex
    while (input[offset] === " ") offset++
  }
  if (!values.length) throw new Error("Invalid path")
  return values
}
