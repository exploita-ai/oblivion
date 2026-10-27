# Project status

Oblivion is early beta. The architecture works end to end and public
pre-release images are available, but the project is not yet ready for
sensitive or irreplaceable data.

## Implemented

- amd64 and arm64 Debian live images
- encrypted general settings vault
- separate LUKS2 volume and password for each persistent session
- RAM-backed ephemeral mode
- one active session VM and volume at a time
- offline Documents mode without a network device or provider credential
- Tor and configurable SOCKS5 gateway modes with no intended direct fallback
- multiple provider keys, a global default and a per-opening override
- multiple chats sharing the documents of one encrypted session
- bounded removable-media import/export with manifests, hashes and recovery paths
- full-screen host manager and retained OpenCode coding-agent TUI

## Validated so far

- boot, encrypted persistence and a real provider response on physical amd64
  hardware
- lock and reopen flows on the physical boot-media candidate
- arm64 component builds and automated guest laboratories in CI
- automated storage, gateway, transfer and session lifecycle laboratories

Validation results belong to the commit that produced them. GitHub Actions
publishes the detailed logs and machine-readable evidence as expiring workflow
artifacts instead of storing historical snapshots in this repository.

## Hardening milestones

- complete the Debian package, service, binary and host-egress allowlist audit
- audit the release profile and keep all debug access removed
- repeat destructive persistence and recovery tests on a dedicated physical boot drive
- finish long-running Tor, proxy failure and network-revocation tests
- verify multi-chat persistence and migration across image upgrades
- make builds reproducible and publish signed checksums and provenance
- commission an independent security review

## Known limitations

- cloud inference exposes approved context and output to the provider
- running Oblivion inside another VM requires nested KVM; a booting manager
  does not establish full session support on that host/hypervisor combination
- generic ARM hypervisors that do not expose nested virtualization can boot the
  manager but cannot open sessions
- arm64 does not yet have the same physical and outer-VM validation coverage as
  amd64
- the image is larger and contains more Debian tooling than the final minimal
  profile should contain
- an unlocked system holds plaintext data and credentials in RAM
- debug and development builds are intentionally more observable than release
  images

## Remote-API beta scope

Keep the Debian host and the existing gateway/session/transfer VM boundaries.
Boot Debian directly on a qualified PC or run it as the outer host VM in a
qualified virtualizer. Native application ports, native Mac vault work and
removal of the outer VM are no longer active roadmap items. Local inference,
model downloads, GPU work and DGX Spark remain deferred.

The implemented/validated lists above are unchanged by this plan. There is no
new runtime capability, format migration or removal of an existing VM boundary.

| In scope | Delivery boundary |
| --- | --- |
| Agent and manager | Retain coding tools and OpenCode chat components; fix concrete usability/reliability defects. |
| Protected work | General LUKS2 vault and separate session volumes, titles, multiple chats, Documents, one active session, locking and recovery. |
| Remote providers | Abliteration first; qualify other integrated providers separately. No new catalog or arbitrary endpoints. |
| Keys and network | Encrypted keys, global default/per-opening override, Tor default, optional SOCKS5, revoked grants and no direct fallback. |
| Physical live image | Primary amd64 boot, guided encrypted persistence, minimal Debian and release hardening. |
| Virtualized image | Same Debian environment on qualified CPU/OS/hypervisor combinations, nested KVM, persistent virtual disk and tested import/setup profile. Start with the available UTM Mac; qualify Linux/QEMU and Windows/VirtualBox independently. |
| arm64 | Preserve builds/regressions; no generic ARM or all-Mac compatibility claim. |
| Ephemeral mode | Volatile Debian session state and unchanged archives; outer-host memory/swap/snapshot retention remains outside Debian's control. |
| Transfers and upgrades | Explicit import/export, preserved histories/files and verified recovery/upgrade paths without shell repair. |

Do not replace the gateway/transfer VMs with native host services or introduce
new platform abstractions solely for deferred native ports. Keep the current
Linux storage backend and formats. No native Mac encryption backend is needed
for this roadmap: Debian manages LUKS inside the VM's persistent virtual disk.

Also defer inference nodes, air-gap workflows, HuggingBay/torrents, OnionShare,
copies between sessions, simultaneous protected sessions and a disposable
browser. No GPU passthrough or inference VM work is scheduled.

## Near-term roadmap

1. **Focused source audit — complete; runtime qualification pending.**
   [Findings and targeted test results](#audit-results) cover controller/VM
   lifecycle, chat storage, credentials and transport. Complete image-wide
   write/egress tracing and destructive VM tests before release; native-vault
   research remains stopped.
2. **Persistence and recovery.** Prove multi-chat and document preservation
   across close/reopen, Debian reboot, outer-VM termination and upgrades.
   Exercise wrong passwords, full disks, interrupted transfers and failed lock.
3. **Remote reliability.** Complete key lifecycle, real API/agent tasks, Tor
   progress/cancellation, SOCKS5, failure recovery and direct-egress denial.
4. **Usable delivery.** Finish setup and existing TUI behavior, tested VM
   profiles, nested-acceleration/resource checks and explicit file transfers.
   Users install the supported virtualizer/import the image; Oblivion manages
   its internal services without Linux commands or configuration-file edits.
5. **Qualified beta.** Minimize Debian based on evidence, remove release debug
   access, publish verified artifacts/provenance, test upgrades/rollback and
   run independent user trials. Replace the physical candidate only after
   its successor passes regressions; publish actual supported combinations.

The audit below sets the order for persistence and remote-network corrections.
This plan does not change the
running VM, personal archives or host networking. Use disposable fixtures or
copies for destructive tests.

Require the full workflow on every declared profile: boot/import, prepare
storage, configure a key, perform an agent file task, use multiple chats and
Documents, lock, reboot and restore all work. At least five non-author testers
across qualified paths must complete it without developer repairs before the
managed-beta usability gate is complete. Unsupported nested virtualization
must be diagnosed early, not hidden behind a session startup timeout.

## Audit results

Reviewed on 2026-10-27 at runtime-source revision
`cf40a4c67eb101ad2cd488580da2a238e066d412`, with the existing documentation
changes in the working tree. Architecture retained: Debian live/outer host VM,
inner session/gateway/transfer VMs, LUKS2 and remote APIs. This audit changes
documentation only; it does not migrate chats, alter keys or restart a VM.

The findings below distinguish source-confirmed behavior from missing release
evidence. They do not establish the cause of any previously reported missing
conversation. No P0 bypass or plaintext credential disclosure was confirmed in
the reviewed paths; this is not an independent security certification.

### Existing protections

| Data or boundary | Evidence in the current implementation |
| --- | --- |
| Chat history | Stable `/vault/state/opencode/oblivion.db`, independent of client build channel. Legacy copy uses SQLite backup, including committed WAL frames; staging stays on the encrypted filesystem and originals are preserved. See [chat-database.py](../packages/oblivion-host/guest/chat-database.py), lines 25–27 and 86–156. |
| Agent files and temporary data | HOME/config/state/workspace are inside the session volume; cache and temporary data use `/tmp`. Guest `/var` and `/tmp` use tmpfs, journald persistence/forwarding is disabled, swap/sleep units are masked. See [conversation service](../packages/oblivion-host/guest/oblivion-conversation.service) and [guest setup](../script/oblivion/vm-common-setup.sh). |
| Runtime and logging | Controller rejects active swap, requires tmpfs runtime storage and disables core dumps. The Oblivion application profile disables its logger/tracer. See [storage.rs](../packages/oblivion-host/src/storage.rs), lines 1780–1855, and [observability.ts](../packages/util/src/observability.ts), lines 27–30. These checks do not control the outer hypervisor. |
| Real API keys | Stored under the encrypted general profile, using a mode-0600 pending file, file sync, atomic rename and directory sync. The session receives a revocable capability, not the provider key. See [storage.rs](../packages/oblivion-host/src/storage.rs), lines 1635–1681, and [network.sh](../packages/oblivion-host/guest/network.sh), lines 6–19. |
| Network | Session has no default route or DNS; the gateway applies transport/tool rules. Broker tests cover TLS rejection, unavailable proxy without direct fallback and stream revocation. See [network.sh](../packages/oblivion-host/guest/network.sh), [gateway firewall](../packages/oblivion-gateway/guest/firewall.nft) and [broker.rs](../packages/oblivion-gateway/src/broker.rs). |

These protections cover their configured paths. They do not prove that every
dependency, Debian service, outer-host swap file or saved VM state is clean.

### Prioritized work

**A1 — P1: chat startup can report success before chat storage/client startup.**
[network.sh](../packages/oblivion-host/guest/network.sh), line 29, sends `ready`
after interface/token setup. [vm.rs](../packages/oblivion-host/src/vm.rs),
lines 133–175, accepts that as startup completion. The database migration runs
later in [conversation.sh](../packages/oblivion-host/guest/conversation.sh),
line 6; a failure exits the service (`Restart=no`). Conflicting histories,
pending legacy work or failed database checks can therefore leave the
controller in chat mode without a working TUI. Add an application readiness
and typed failure handshake after database/client initialization, with an
explicit recovery/Documents path. Preserve originals; never repair this by
resetting a database. Acceptance: failed migration, corrupt storage, disk full
and client startup failure are visible and recoverable without a blank chat.
This failure path is source-confirmed, not reproduced on the user's archive.

**A2 — P1: recent committed chat data can be lost on a system/power failure.**
[database.ts](../packages/core/src/database/database.ts), lines 39–44, selects
WAL with `synchronous=NORMAL`. SQLite documents that this remains consistent
but may roll back recent commits after power/system failure; ordinary process
crashes are a different case. See [SQLite durability semantics](https://www.sqlite.org/pragma.html#pragma_synchronous).
Choose and measure a stronger durability policy for Oblivion, then verify the
entire guest filesystem/QEMU/outer-disk flush chain. The existing
[VM persistence test](../script/oblivion/vm-persistence-test.py), lines 187–212,
checks a document, credentials and network settings, not real chat history.
Acceptance must include multiple actual chats, messages and tool results
through normal close, reboot, forced VM termination and interrupted writes on
disposable storage. No power-loss test was performed in this audit.

**A3 — P1: a Tor checkpoint error short-circuits global lock/recovery.**
[gateway.rs](../packages/oblivion-host/src/gateway.rs), lines 95–102, destroys
the gateway but still returns `gateway_shutdown_unconfirmed` if its checkpoint
request failed. [storage.rs](../packages/oblivion-host/src/storage.rs),
lines 704–720, propagates that error before attempting the remaining transfer,
session VM and LUKS cleanup. Thus an error can leave volumes open even after
egress was stopped. It does not falsely report a successful lock, and a retry
may succeed. Make teardown attempt the remaining safe steps once revocation is
verified, aggregate failures and retain recovery status until closure is
verified. Acceptance: failed Tor checkpoint/control acknowledgement must not
skip unrelated safe cleanup. Source-confirmed; Linux fault injection pending.

**A4 — P1 for legacy upgrades: an inherited migration deletes chat history.**
[reset_v2_session_state](../packages/core/src/database/migration/20260622170816_reset_v2_session_state.ts),
lines 8–12, deletes messages, input/context and events. The
[migration runner](../packages/core/src/database/migration.ts), lines 107–115,
runs migrations absent from an existing database's journal. Fresh databases
bootstrap the current schema and already-migrated databases skip it. Determine
the supported older formats and reject unsupported upgrades explicitly or
provide preservation/recovery before allowing this migration. Test fixtures
from every supported version. This does not show that current October archives
or the user's previous chats were affected.

**A5 — release gate: whole-image and outer-host retention remains unverified.**
No plaintext disk leak was confirmed in the reviewed application paths. Run
synthetic markers through chat, tools, transfers, key operations and failures;
trace writes and inspect journals, temporary paths, dumps and persistent
devices after closure. Compare archives before/after ephemeral use. Repeat for
the actual release image and qualified outer-VM profile. Inner LUKS does not
encrypt saved guest RAM, hypervisor snapshots or outer-host swap; restrict and
test the VM profile and state that boundary explicitly. Do not use real secrets
in traces. This is missing evidence and an architectural trust boundary, not a
demonstrated internal LUKS bypass.

**A6 — P2: Tor progress, cancellation and unnecessary restarts.**
[tor.rs](../packages/oblivion-gateway/src/tor.rs), lines 55–62, reduces bootstrap
progress to a boolean. [start-chat.ts](../packages/oblivion-manager/src/start-chat.ts)
retries 40 times with three-second waits; that is not an overall deadline
because controller calls have their own timeout. Cancellation interrupts the
retry wait but is not propagated into the in-flight controller operation; see
[app.tsx](../packages/oblivion-manager/src/app.tsx), lines 296–309, and
[control.ts](../packages/oblivion-manager/src/control.ts), line 72.
[change_keys](../packages/oblivion-host/src/storage.rs), lines 922–1013, stops
the gateway even for a key rename or removing an unused key. Selecting the
already-selected key has a fast path and does not necessarily restart it.
Expose bootstrap stage/progress, use an overall startup deadline and controller
cancellation, and separate metadata changes from credential revocation. Test
slow bootstrap, cancellation and repeated openings while preserving no direct
fallback. These are source-confirmed lifecycle/UX issues, not proof Tor is the
cause of every observed delay.

**A7 — P2: invalid credentials become an unhelpful provider error.**
[broker.rs](../packages/oblivion-gateway/src/broker.rs), lines 211–223, preserves
429 separately but maps other unsuccessful responses, including 401/403, to
502 `provider_response_denied`. Keep the refusal to forward raw provider error
bodies, but return safe, predefined classifications that distinguish rejected
credentials, denied requests, rate limits and provider unavailability where
the status supports that distinction. Exercise replacement/default/override,
removal and revocation in a live chat lifecycle. Key storage and local broker
tests passed; a real-provider credential lifecycle was not exercised here.

**A8 — P2: complete the Debian host egress/service allowlist.**
The [gateway firewall](../packages/oblivion-gateway/guest/firewall.nft) governs
the gateway, not all Debian-host processes. The
[live setup](../script/oblivion/live-setup.sh) disables NetworkManager probes,
mDNS/LLMNR and managed DNS, but the reviewed setup does not install a general
default-deny host-output policy. Inventory actual processes, sockets, activation
and required DHCP/Wi-Fi/time/gateway traffic, then restrict unnecessary paths
and remove packages based on those measurements. This is defense in depth for
the trusted Debian host; it is not evidence that session tools can bypass the
gateway. Repeat packet capture on the final image, including startup/failure.

### Checks performed and limits

| Check | Result in this audit |
| --- | --- |
| Host Rust tests: `cargo test --locked --offline` in `packages/oblivion-host` | 46 passed on macOS. Linux-only storage/controller/VM paths were not executed. |
| Gateway Rust tests: same command in `packages/oblivion-gateway` | 35 passed, 2 ignored adapter tests requiring `OBLIVION_ADAPTER_BIN`. Local TLS/SOCKS fixtures, not a real Tor circuit/provider. |
| Private activation: `cargo test --locked --offline --features lab-emulation --test activation` in gateway | 10 passed on macOS. Lab mode does not establish production Linux isolation. |
| Manager: `bun test` in `packages/oblivion-manager` | 80 passed; fixtures do not validate a booted VM. |
| Core: `bun run script/test.ts test/database-migration.test.ts` in `packages/core` | 19 passed with the isolated test runner. Generic migration tests, not proof all historical archives survive. |
| Python: selected `test-chat-database.py` WAL/invalid-source cases and `test-console.py` in `script/oblivion` | 2 database + 3 console tests passed. The other database cases require the compiled Linux client and were not run. |
| Gitleaks 8.30.0, current tree, offline/redacted | No findings. Full Git history, personal volumes and runtime artifacts were not scanned. |

Total: 195 passing targeted tests on macOS, plus the secret scan. Installed
Bun was 1.3.5 rather than the repository's pinned 1.4.4; repeat with the pinned
toolchain for release. An additional Docker/Linux activation attempt had 5
passes and 5 startup failures: the container ran as UID 0 and exposed active
Docker-VM swap, both refused by `activation::harden`. Do not classify that run
as a production pass or weaken the checks; rerun in the existing swap-free,
unprivileged Linux laboratory. No host swap setting was changed.

Not executed: live provider requests, real Tor/bootstrap packet capture,
booted Linux controller fault injection, full image package/service execution
inventory, end-to-end chat power-loss/upgrade tests, outer-hypervisor retention
checks or a new ISO build. Existing earlier laboratory results are not a fresh
validation of this revision. No runtime code or tests were changed, so the
repository-wide lint/typecheck was not rerun for this documentation update.

## Security boundary

Remote APIs are not air-gapped; providers process submitted context and tool
output. The outer host OS and hypervisor remain trusted in virtualized use.
Debian cannot prevent those layers from recording input/display or persisting
unlocked memory through swap, dumps or saved VM state. Test and document a
restricted VM profile; do not imply the same physical-host retention guarantees
as bare-metal live boot. The project has not received an independent security
audit.

See the [remote-API beta plan](ARCHITECTURE.md#remote-api-beta-plan) for retained
boundaries, delivery profiles and release gates. Both the native-port and
local-inference-first roadmaps are superseded.
