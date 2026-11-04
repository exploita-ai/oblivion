import { expect, test } from "bun:test"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { createNativeFileClient } from "../src/native-file-process"
import type { FileCopyRequest, FileEvent } from "../src/native-file-events"

const identity = { operation_id: "a".repeat(32), safe_id: "b".repeat(32), opening: "c".repeat(32) }
const digest = "f".repeat(64)

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "oblivion-copy-events-"))
  const script = path.join(root, "child.ts")
  await writeFile(script, `
const mode=process.argv[2];const identity=JSON.parse(process.argv[3]);const digest="f".repeat(64)
const total=mode==="empty"?0:12
const review={event:"review",identity,direction:"import",name:"città.txt",summary:{manifest_sha256:digest,entries:1,files:1,directories:0,bytes:total}}
async function emit(value){await Bun.stdout.write(JSON.stringify(value)+"\\n")}
if(mode==="ignore")process.on("SIGTERM",()=>{})
if(mode==="early"){await emit({event:"finished",identity,outcome:"interrupted",receipt:null});process.exit(0)}
if(mode==="oversize")await Bun.stdout.write("x".repeat(4096)+"\\n")
else if(mode==="wrong-identity")await emit({...review,identity:{...identity,safe_id:"d".repeat(32)}})
else if(mode==="truncated"){await Bun.stdout.write(JSON.stringify(review));process.exit(0)}
else{const bytes=new TextEncoder().encode(JSON.stringify(review)+"\\n");const split=bytes.indexOf(195)+1;await Bun.stdout.write(bytes.subarray(0,split));await Bun.stdout.write(bytes.subarray(split))}
if(mode==="ignore")setInterval(()=>{},1000)
const reader=Bun.stdin.stream().getReader();let pending=""
while(true){const chunk=await reader.read();if(chunk.done)break;pending+=new TextDecoder().decode(chunk.value);let end
while((end=pending.indexOf("\\n"))!==-1){const input=JSON.parse(pending.slice(0,end));pending=pending.slice(end+1)
if(input.operation_id!==identity.operation_id)process.exit(9)
if(input.action==="cancel"){await emit({event:"finished",identity,outcome:"cancelled-before-copy",receipt:null});if(mode!=="ignore")process.exit(0);continue}
if(input.action!=="approve"||input.manifest_sha256!==digest)process.exit(8)
if(mode==="backwards"){await emit({event:"progress",identity,phase:"copying",bytes:8,total_bytes:12});await emit({event:"progress",identity,phase:"copying",bytes:7,total_bytes:12});continue}
await emit({event:"progress",identity,phase:"copying",bytes:total?5:0,total_bytes:total})
await emit({event:"progress",identity,phase:"finalizing",bytes:total,total_bytes:total})
await emit({event:"finished",identity,outcome:"completed",receipt:{id:identity.operation_id,manifest_sha256:mode==="wrong-receipt"?"e".repeat(64):digest,entries:1,bytes:total}});process.exit(0)
}}
`)
  return { root, request(mode: string, selected = identity): FileCopyRequest { return { args: [script, mode, JSON.stringify(selected)], identity: selected, direction: "import", name: "città.txt" } } }
}

function observer() {
  const events: FileEvent[] = []
  const review = Promise.withResolvers<void>()
  return { events, review: review.promise, event(value: FileEvent) { events.push(value); if (value.event === "review") review.resolve() } }
}

test.each(["normal", "empty"])("a real child reviews before approval and drains byte progress and receipt (%s)", async (mode) => {
  const source = await fixture()
  const client = createNativeFileClient(process.execPath)
  const seen = observer()
  const copy = client.start(source.request(mode), seen.event)
  try {
    await seen.review
    expect(seen.events.map((event) => event.event)).toEqual(["review"])
    await expect(copy.approve("e".repeat(64))).rejects.toThrow("exact copy")
    expect(seen.events).toHaveLength(1)
    await copy.approve(digest)
    const result = await copy.done
    expect(result.code).toBe(0)
    expect(result.finished?.outcome).toBe("completed")
    expect(seen.events.map((event) => event.event)).toEqual(["review", "progress", "progress", "finished"])
    expect(result.finished?.receipt?.bytes).toBe(mode === "empty" ? 0 : 12)
  } finally { await client.close(); await rm(source.root, { recursive: true }) }
})

test("Cancel closes the owned child's input before any payload approval", async () => {
  const source = await fixture()
  const client = createNativeFileClient(process.execPath)
  const seen = observer()
  const copy = client.start(source.request("normal"), seen.event)
  try {
    await seen.review
    await copy.cancel()
    expect((await copy.done).finished?.outcome).toBe("cancelled-before-copy")
    expect(seen.events.some((event) => event.event === "progress")).toBe(false)
    await expect(copy.approve(digest)).rejects.toThrow()
  } finally { await client.close(); await rm(source.root, { recursive: true }) }
})

test.each(["oversize", "wrong-identity", "truncated", "backwards", "wrong-receipt"])("invalid %s events reap the child and leave the outcome uncertain", async (mode) => {
  const source = await fixture()
  const client = createNativeFileClient(process.execPath)
  const seen = observer()
  const copy = client.start(source.request(mode), seen.event)
  try {
    if (mode === "backwards" || mode === "wrong-receipt") { await seen.review; await copy.approve(digest) }
    await expect(copy.done).rejects.toThrow("recorded outcome")
  } finally { await client.close(); await rm(source.root, { recursive: true }) }
})

test("a negative terminal event before review is not a fabricated completion", async () => {
  const source = await fixture()
  const client = createNativeFileClient(process.execPath)
  const seen = observer()
  try {
    const result = await client.start(source.request("early"), seen.event).done
    expect(result.finished?.outcome).toBe("interrupted")
    expect(seen.events.map((event) => event.event)).toEqual(["finished"])
  } finally { await client.close(); await rm(source.root, { recursive: true }) }
})

test("bounded cancellation escalates only the exact owned child while another copy remains usable", async () => {
  const source = await fixture()
  const timers: { delay: number; fire: () => void }[] = []
  const waits = [Promise.withResolvers<void>(), Promise.withResolvers<void>()]
  const client = createNativeFileClient(process.execPath, (delay, fire) => { const index = timers.length; timers.push({ delay, fire }); waits[index]?.resolve(); return () => {} })
  const first = observer()
  const second = observer()
  const stuck = client.start(source.request("ignore"), first.event)
  const other = client.start(source.request("normal", { ...identity, operation_id: "d".repeat(32) }), second.event)
  try {
    await Promise.all([first.review, second.review])
    const stopping = stuck.cancel()
    await waits[0]!.promise
    expect(timers[0]?.delay).toBe(10_000)
    timers[0]!.fire()
    await waits[1]!.promise
    expect(timers[1]?.delay).toBe(2_000)
    timers[1]!.fire()
    await stopping
    expect(second.events).toHaveLength(1)
    await other.approve(digest)
    expect((await other.done).finished?.outcome).toBe("completed")
  } finally { await client.close(); await rm(source.root, { recursive: true }) }
})

test("manager exit closes and reaps every pending copy and cannot start another one", async () => {
  const source = await fixture()
  const client = createNativeFileClient(process.execPath)
  const first = observer()
  const second = observer()
  const one = client.start(source.request("normal"), first.event)
  const two = client.start(source.request("normal", { ...identity, operation_id: "d".repeat(32) }), second.event)
  try {
    await Promise.all([first.review, second.review])
    await client.close()
    expect((await one.done).finished?.outcome).toBe("cancelled-before-copy")
    expect((await two.done).finished?.outcome).toBe("cancelled-before-copy")
    expect(() => client.start(source.request("normal"), () => {})).toThrow("closing")
  } finally { await client.close(); await rm(source.root, { recursive: true }) }
})
