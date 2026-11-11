import { expect, test } from "bun:test"
import { launchNativeAgent } from "../src/native-agent"

// This handshake inherits a POSIX socket on descriptor 3. The Windows
// launcher uses its existing terminal adapter.
test.skipIf(process.platform === "win32")("native agent waits for each terminal handoff while startup stays in the manager", async () => {
  const stages: string[] = []
  const code = await launchNativeAgent("/bin/sh", ["-ec", `
    exchange() {
      printf %s "$1" >&3
      [ "$(dd bs=1 count=1 <&3 2>/dev/null)" = K ]
    }
    [ "$OBLIVION_MANAGER_HANDOFF" = 1 ]
    exchange P
    exchange W
    exchange G
    exchange R
  `], {
    suspend: () => { stages.push("suspend") },
    resume: () => { stages.push("resume") },
  }, (stage) => { stages.push(stage) })
  expect(code).toBe(0)
  expect(stages).toEqual(["suspend", "resume", "opening", "connecting", "suspend", "resume"])
})

test.skipIf(process.platform === "win32")("native agent keeps the manager active on gateway failure", async () => {
  const stages: string[] = []
  const code = await launchNativeAgent("/bin/sh", ["-ec", `
    printf G >&3
    [ "$(dd bs=1 count=1 <&3 2>/dev/null)" = K ]
    printf F >&3
    [ "$(dd bs=1 count=1 <&3 2>/dev/null)" = K ]
    exit 1
  `], {
    suspend: () => { stages.push("suspend") },
    resume: () => { stages.push("resume") },
  }, (stage) => { stages.push(stage) })
  expect(code).toBe(1)
  expect(stages).toEqual(["connecting", "gateway-failed"])
})

test.skipIf(process.platform === "win32").each([true, false])("native agent separates confirmed Safe closure from status 1 (%s)", async (closed) => {
  const stages: string[] = []
  const code = await launchNativeAgent("/bin/sh", ["-ec", `
    exchange() {
      printf %s "$1" >&3
      [ "$(dd bs=1 count=1 <&3 2>/dev/null)" = K ]
    }
    exchange R
    if [ "$1" = yes ]; then exchange D; fi
    exit 1
  `, "sh", closed ? "yes" : "no"], {
    suspend: () => { stages.push("suspend") },
    resume: () => { stages.push("resume") },
  }, (stage) => { stages.push(stage) })
  expect(code).toBe(1)
  expect(stages).toEqual(closed ? ["suspend", "safe-closed-before-exit", "resume"] : ["suspend", "resume"])
})
