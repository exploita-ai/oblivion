# Project status

Oblivion is early beta. The architecture works end to end and public
pre-release images are available, but the project is not yet ready for
sensitive or irreplaceable data.

`v0.1.0-beta.2` packages the operational features below for experimental use.
Its source commit `b959035` passed all 42 GitHub checks on both `main` and `dev`;
the release workflow rebuilt and verified both image architectures before
publication. This does not close the supported-candidate, public large-backup,
hardware, upgrade or independent-review gates documented here.

## Implemented

- **Host/guest text clipboard in beta 2 images.** UTM uses Debian's SPICE
  broker and a pinned open-source Wayland adapter restricted to UTF-8 text and
  256 KiB payloads. The host announces formats; bytes are requested only on
  paste. Guest terminal clipboard escapes remain filtered and manager copy
  requires a visible selection. With no selection Ctrl+C still interrupts
  agent/shell commands. State and helper output remain confined to the display
  RAM/runtime boundary. Bare-metal boot has no hypervisor clipboard channel.
  The amd64 build includes only the pinned upstream VirtualBox clipboard
  client, without guest-control, shared-folder or full Guest Additions services.
  Both mechanisms use the hypervisor's explicit sharing setting, independently
  of Debug/SSH. A fresh ARM64 ISO and separate networkless UTM VM passed both
  directions with a human tester using physical shortcuts; automated modifier
  delivery through the Apple view was unsuitable for these shortcut checks.
  Four protocol tests, six real headless Cage/data-control checks, 130 manager
  tests, official manager TypeScript checks and the 20-task repository check
  pass. Actual VirtualBox acceptance remains pending. Setup and clipboard
  instructions for UTM/VirtualBox are in `DEVELOPMENT.md`; previously released
  ISOs and the user's personal VM are unchanged.

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
| Operational workspace | Deliver the interactive terminal and process controls in the milestones below. |
| Protected work | General LUKS2 vault and separate session volumes, titles, multiple chats, Documents, one active session, locking and recovery. |
| Remote providers | Abliteration first; qualify other integrated providers separately. No new catalog or arbitrary endpoints. |
| Keys and network | Encrypted keys, global default/per-opening override, Tor default, optional SOCKS5, revoked grants and no direct fallback. |
| Physical live image | Primary amd64 boot, guided encrypted persistence, minimal Debian and release hardening. |
| Virtualized image | Same Debian environment on qualified CPU/OS/hypervisor combinations, nested KVM, persistent virtual disk and tested import/setup profile. Start with the available UTM Mac; qualify Linux/QEMU and Windows/VirtualBox independently. |
| arm64 | Preserve builds/regressions; no generic ARM or all-Mac compatibility claim. |
| Ephemeral mode | Volatile Debian session state and unchanged archives; outer-host memory/swap/snapshot retention remains outside Debian's control. |
| Transfers and portability | USB and virtual-media import, OnionShare receive/share, conversation exports, encrypted session backup/restore and redacted diagnostics. |
| Upgrades | Preserved histories/files and verified recovery/upgrade paths without shell repair. |

Do not replace the gateway/transfer VMs with native host services or introduce
new platform abstractions solely for deferred native ports. Keep the current
Linux storage backend and formats. No native Mac encryption backend is needed
for this roadmap: Debian manages LUKS inside the VM's persistent virtual disk.

Also defer inference nodes, air-gap workflows, HuggingBay/torrents, live copies
between sessions and simultaneous protected sessions. The additional Files/Git
UI, browser/project previews and MCP integrations are deferred for
now, with no scheduled delivery milestone. OnionShare is implemented in the development tree and remains subject to
operational-candidate qualification. No GPU passthrough or inference VM work is scheduled.

## Near-term roadmap

The operational roadmap was updated on 2026-10-28 to focus on terminal,
transfers, exports, encrypted backup/restore and OnionShare. These are ordered
milestones with acceptance gates, not calendar estimates or released features.
Retain the existing English OpenTUI manager, red branding and OpenCode chat
components throughout.

### Baseline and reusable implementation

The ARM64 candidate with SHA-256
`93c6dc8b4eafc86f9124195d8f7d92b9d124f209c69fb4e1f0e80ac24f1a0636`
passed real UTM acceptance on 2026-10-28: Tor/provider responses, two chats with
titles, a shared document, close/reopen and clean full VM shutdown/start. A new
provider request after restart read the original document using the saved key.
This covers the tested M4 Pro / Apple Virtualization profile at 4 CPUs and 4 GiB
RAM. The host's NordVPN was disconnected for the passing network test;
Tailscale remained connected. The earlier DHCP failure and 8 GiB stalls need
separate diagnosis. This result does not replace physical power-loss,
full-image leak, upgrade or network-failure qualification. Detailed local
evidence remains in ignored artifacts; publish reproducible evidence with the
candidate that is actually released.

| Capability | Current implementation to reuse | Remaining product work |
| --- | --- | --- |
| Terminal and jobs | OpenCode shell/jobs and PTY services; the manager's embedded terminal and bounded console transport. | A user-facing guest terminal and process view, independent of chat and provider readiness. |
| Files in/out | Documents picker, isolated transfer endpoints, manifests, hashes, cancellation and recovery. | Qualify USB and virtual import media; add the new source/destination choices without shared folders. |
| Exports and backups | Stable chat DB, per-session LUKS2 containers and controller teardown. | Markdown/JSON export, closed-session encrypted backup/restore and allowlisted diagnostics. |
| OnionShare | Existing Tor gateway and verified copy engine. | Package and confine the upstream CLI, implement private receive/share lifecycles and explicit intake approval. |

### Ordered milestones

| Milestone | Deliverable | Dependency and exit evidence |
| --- | --- | --- |
| **M0 — protect the baseline** | Preserve the passing chat/storage behavior; surface unsupported nested virtualization, insufficient RAM/storage, DHCP, gateway and provider failures distinctly. Finish remaining high-priority audit corrections. | Existing source/lab results plus profile-specific fault tests. No lost history, false lock success, stale protection indicator or direct fallback. This gate stays active for every later milestone. |
| **M1 — Terminal and Processes** | A full-window interactive shell in the session VM; create/select/stop terminals, inspect build/test/server jobs, bounded output and exit status. It works offline without a provider key. Switching to Chat or Documents keeps processes running; locking stops and verifies all session processes. | Reuse PTY/jobs and the embedded renderer. Exercise input, resize, scroll, interrupts, process-tree shutdown, crash/reopen and offline-to-chat transitions. No host shell, root console, provider key or general-vault access. |
| **M2 — file intake and delivery** | `Documents / Import` accepts selected USB files/folders and explicitly attached virtual import media. `Export` writes selected readable files after a clear destination/confirmation step. Provide source, destination, totals, progress, cancellation and recovery. | Reuse the copy engine. Test actual USB and UTM media, large directories, unsupported files, path escapes, disconnects, full disks and interrupted copies. Verify receipt/flush before success. Never expose an entire outer-host folder or mount the session filesystem there. |
| **M3 — exports and session portability** | Three distinct actions: `Export chat` as Markdown/JSON, `Back up encrypted session` with `Restore session`, and `Export diagnostics`. Backups preserve all chats, IDs, workspace/imports and required session metadata; provider keys remain in the general vault. | Complete M2 and the backup format/lifecycle contract below. Restore on a disposable copy and on another qualified instance; preserve originals and reject unsupported versions without destructive migration. Test corruption/truncation, wrong passwords, cancellation and low space. |
| **M4 — OnionShare files** | `Receive over Tor` and `Share over Tor` in the existing transfer UI, using upstream OnionShare CLI. Temporary private addresses/access keys, size/time limits, progress and cancellation; inspect and approve received files before publishing them to the session. | Complete M2/M3. Qualify the dedicated transfer/Tor path under the existing gateway boundary, secret/log retention, owner death, timeout and revoke-on-lock. Test real sender/recipient round trips, including an encrypted session backup. |
| **M5 — qualify and release** | Minimal audited Debian packages/services for the delivered features, release/debug separation, signed manifests/checksums, verified update/rollback and tested live/VM profiles. | Every included milestone passes affected package checks, root `bun run check`, Linux integration and actual supported-profile acceptance. At least five non-author testers finish the workflow without developer repairs. Publish measured image/RAM costs and exact support boundaries. |

The next operational candidate contains M0–M4: terminal/processes, useful file
intake/export, chat exports, encrypted session backup/restore, redacted
diagnostics and OnionShare receive/share. M5 qualifies that candidate for
release; incomplete features stay visibly planned and are not advertised as
shipped.

### Implementation progress (2026-10-28)

- **M1 source implemented; deployment qualification in progress.** Terminal F8
  uses guest-only tmux through the existing sanitized 60 Hz viewport, alongside
  Chat F6 and Documents F7. Offline use needs no key/NIC; chat-mode shells use
  the same revocable tool-proxy capability as the agent. Manager lifecycle and
  layout tests pass at 80×24 and 160×50, and the real PTY/tmux regression passes
  for multiple windows, resizing and reattachment. The ARM64 Linux guest with
  the actual terminal service and Rust bridge passes offline nonroot execution,
  process view, interruption and a workspace file across clean guest reboot.
  The focused real controller/LUKS laboratory additionally passes terminal
  attachment, background-job retention across detach/reattach, normal close
  with the QEMU PID reaped and LUKS mapping gone, and reopening with the workspace
  preserved and old jobs absent. Its persistent-disk scan finds no synthetic
  plaintext canaries. This uses HVF plus a nested TCG fixture: coexistence with
  a real provider chat and supported outer-VM acceptance still need the rebuilt
  candidate. Evidence stays under ignored `artifacts/oblivion-operations`.
- **Session base tools integrated in source.** The shared production/laboratory
  image now bundles curl, jq/SQLite, file/tree/less/nano, archive tools, Python
  venv/pip, PDF utilities and a pinned upstream Node LTS/npm bundle alongside
  Git/ripgrep and the shell/process tools. The generated `oblivion-tools`
  inventory is loaded by the real compiled client's configuration and included
  in static image audits, including non-Debian npm dependencies and source
  hashes. Shared terminal/agent defaults disable histories and npm log files,
  keep caches in RAM, and enable Node's native proxy support. The upstream
  bundle replaces Debian npm after a real test exposed an authenticated-proxy
  dependency/API mismatch; it also avoids that package's broad dependency set.
  Four ARM64 container integration tests pass with no external network and a
  read-only root, including authenticated HTTPS for curl/Python/Node/Git/npm/pip,
  certificate and proxy refusals, package installation and real chat startup.
  The offline ARM64 VM passes tools, virtualenv and Node-file persistence across
  reboot together with terminal/export acceptance. Its compressed session root
  is 307,261,440 bytes versus 247,767,040 bytes for the prior laboratory image
  (about 57 MiB additional; not a measured final ISO size). The amd64 upstream
  archive hash, Node and npm executables were checked under emulation; complete
  amd64 tool integration and supported-candidate/physical-media acceptance
  remain qualification gates. No running personal VM was updated.
- **M2 source implemented; supported-profile qualification remains.** Eligible USB and explicitly tagged
  virtio import/export media now expose their kind and read-only status.
  Export rejects import-only/read-only sources. The disposable ARM64 host/
  nested-guest lifecycle passes real LUKS copies, cancellation, interrupted
  writers, source-VM death, forced closure, ENOSPC, FAT/exFAT name collisions,
  UTF-8 round trips and ephemeral operation with persistent storage byte-identical.
  Its persistent-disk scan finds none of the synthetic plaintext canaries.
  That is a software-media test under HVF/TCG, not physical USB or production
  KVM/UTM acceptance of the new candidate.
- **M3 source implementation and qualification in progress.** Documents can select
  a chat and confirm Markdown/OpenCode JSON creation, or review and create an
  allowlisted diagnostic JSON report. Files are created inside the encrypted
  session and selected for a subsequent explicit media export. Chat export
  snapshots SQLite including committed WAL frames, reads the snapshot through
  an unregistered, network-isolated OpenCode server and preserves pending work
  and incomplete source messages. It returns only chat metadata and generated
  paths to the manager. Real compiled-client tests cover transcript equality,
  tool/reasoning content, UTF-8, symlink refusal and private staging cleanup.
  The deployed ARM64 service passes offline JSON/Markdown and diagnostic
  creation, ten consecutive maintenance operations, reboot persistence and
  removal of unfinished staging while preserving completed exports. Service
  instances use the operation ID rather than a reusable kernel port number.
  Supported-candidate acceptance remains pending; transcript export is not a
  backup. Whole-session backup and restore are connected in source to the
  controller and manager.
  `Sessions / Back up` selects writable media, requests the session password
  and write authorization, then requires confirmation of the encrypted volume.
  An offline guest records versioned session metadata and checks SQLite without
  starting the agent. The controller stops that guest and closes its mapping
  before copying; other session openings remain blocked until cleanup. The
  copy subprocess runs without root, with only a read-only inherited descriptor
  for the selected ciphertext. No session filesystem is mounted on the host.
  The separate backup authority allows one volume up to 1 TiB and one hour;
  ordinary document limits remain 256 MiB / 1,024 entries / five minutes.
  Descriptor-source/destination tests pass for a real 512 MiB stream, pinned
  inodes, invalid headers, corruption, truncation and widened authority. Metadata
  tests cover SQLite WAL, future versions and hostile links. Manager tests pass
  at 80×24 and 160×50, including disposal during preparation; the six focused
  cases also pass ten consecutive executions. The complete manager suite passes
  116 tests, the official TypeScript check passes, the Linux ARM64 manager builds
  and root `bun run check` passes all 20 tasks.
  The first real-controller backup run exposed a missing host copy executable;
  packaging is corrected for both laboratory and Live images. The repeated
  ARM64 laboratory passes actual 512 MiB LUKS backup, cancellation, termination
  of the copy subprocess and reopening of the original workspace/metadata. It
  confirms descriptor confinement, no provider/gateway dependency and no synthetic plaintext markers
  on the persistent disks. It uses HVF plus nested TCG and disposable ext4
  media, not a supported-profile or physical-media qualification. All 35 ordinary
  import/export lifecycle checks also pass again with the updated controller,
  including FAT/exFAT, low space, interruption, recovery and byte-identical
  persistent storage after ephemeral use. `Sessions / Restore` reuses the
  existing paginated source browser, copies one encrypted file into a fresh
  private volume and requests its password only after the source VM is detached.
  An offline session VM verifies metadata, SQLite integrity and compatibility
  through a private OpenCode snapshot before the new archive entry is published.
  Passwords stay off argv/environment/state records; the receiver has only an
  inherited descriptor for the empty destination. The original archive and
  backup medium are preserved. Cancel deletes only the new pending copy; a
  wrong password retains a verified copy for retry. An unexpected interruption
  after copying can leave an incomplete entry for explicit cleanup.
  The real ARM64 controller/LUKS lab passes cancellation, wrong-password retry,
  publication under a new ID, title/workspace reopening and unchanged source
  archive/medium. This combined volume test uses a guest without a chat DB.
  Separately, seven compiled-client export/inspection tests pass in an isolated
  Linux container, including unchanged live SQLite/WAL and preserved pending
  chats. The restore UI passes narrow/wide tests for read-only sources, late
  preparation cleanup, low-space feedback and transfer ownership; all seven
  cases pass ten consecutive executions. All 35 ordinary transfer lifecycle
  checks also pass again with the restore-capable controller. A combined
  native-chat volume round trip now also passes in a separate ARM64 laboratory:
  two settled transcript fixtures and pending prompts are created through the
  compiled OpenCode API, copied as part of the actual 512 MiB LUKS volume and
  compared after restore/reopening, including IDs, titles, messages, pending
  inbox records and a shared document. The same run rejects future metadata,
  a corrupt SQLite database, an invalid LUKS header and a truncated volume
  without publication or changes to the original archive/source medium.
  Insufficient general-vault space is refused before source startup. These
  are synthetic conversations without provider calls, under HVF plus nested
  TCG; physical media and supported-candidate UI acceptance remain pending. Copy
  hashes detect corruption; they do not authenticate an untrusted LUKS2 payload.
- **M4 source implemented; final qualification is in progress.** Documents now
  offers receive/share using pinned OnionShare 2.7 components in a separate
  GPL-3.0-or-later worker. Ordinary documents retain their 256 MiB / 1,024-entry
  limit and explicit manifest/hash approval. Intake is frozen after revocation;
  outgoing selections are copied, verified and sealed before publication.
  The host receives metadata and streams approved bytes without mounting the
  session filesystem. Addresses/access keys remain in RAM; reveal is explicit.
  A distinct Tor-only gateway has no provider credential, SOCKS listener or
  forwarding path. Publication requires fresh bootstrap/isolation and an
  acknowledged worker; cancellation, expiry, owner/session death and locking
  reap every auxiliary process before storage closure. Transfer guards use
  `onion-tor-state`, independently of model Tor/SOCKS5 settings.
  The host display keeps UID 1104; transfer hypervisors use 1105/1106 with
  private PID/network namespaces. The network-only actor shares only the
  existing public-uplink identity. A disposable Live-host build verifies these
  users coexist and keeps diagnostic access absent. New image definitions
  include both transfer profiles; existing distributed/personal images are
  unchanged.
  Encrypted backup sharing is a separate authority: after offline metadata
  checkpointing and verified session closure, one read-only LUKS2 descriptor
  becomes a read-only block device in the file VM. Neither a general-vault
  directory nor the session password reaches that VM. The worker verifies
  its device/header/size and streams through upstream HTTP/Range machinery,
  without copying the entire container into RAM. Its limit is 1 TiB / one
  hour, independent of ordinary documents. Source opening/mutation is blocked
  during sharing. The manager separately asks for preparation and publication
  approval. Restore currently reads removable/virtual media; direct Tor intake
  of backups larger than the document limit is not implemented.
  Tests found and fixed a display/transfer UID collision, the missing PCI
  hotplug port for ciphertext, concurrent QMP monitor access during copy setup,
  backup publication's phase admission and upstream acceptance of ranges
  starting beyond EOF. Werkzeug validates/normalizes ranges before upstream
  streaming. Linux ARM64 host/transfer suites pass (86 + one ignored, and 61),
  as do 130 manager tests, the official TypeScript check and the 20-task
  repository check. Rust also checks all Linux ARM64/amd64 targets.
  A public ARM64 HVF/TCG laboratory has passed 13 receive/import/reopen/share/
  revoke/ephemeral checks with independent Tor clients: absent/wrong
  authorization refused, selected-only content verified, all actors reaped and
  the persistent archive byte-identical during ephemeral use. Its capture has
  zero packets before enable and no UDP/IPv6 afterward; a full synthetic-disk
  scan finds no plaintext canaries. Earlier fresh Tor bootstrap failure at
  180 seconds is retained; later passes do not establish network reliability.
  Full 512 MiB public backup qualification is not yet passed: one attempt
  hit the laboratory unit's 15-minute ceiling, a later full stream ended with
  a curl failure, and the next fresh service missed the public reachability
  deadline before upload. Failed runs are retained. Only this opt-in test has
  a longer laboratory budget, with production deadlines unchanged. A separate
  real file-VM test passes interruption, Range resume and the complete 512 MiB
  hash on a private wire; its sparse block fixture is not an encrypted archive
  and does not replace public qualification. Supported
  UTM/KVM/physical-media acceptance and measured full-candidate RAM/image costs
  remain M5 gates.
- **DNS and UDP verified separately for the current network path.** Fresh
  two-VM Tor and authenticated SOCKS5 laboratories pass 13 checks each. They
  cover remote destination resolution, direct DNS over TCP/UDP, DoT,
  application UDP/QUIC and IPv6 bypass probes, revocation and transport loss.
  SOCKS5 outside capture contains only TCP to the configured proxy; Tor's
  explicit HTTPS test exits through Tor. Neither path falls back directly.
  A Live-host policy test with actual listening peers additionally passes for
  every host role, including the new transfer identities: application egress
  and UDP are blocked, while Root's DHCP exchange remains available. These
  policies govern Oblivion, not a surrounding host OS.

### Implementation contracts

- **One workspace and one open session.** Chat, Documents and Terminal use
  the selected session's encrypted filesystem. Views share its process
  lifetime; they do not unlock other volumes. Keep Chat full-window with the
  network footer and explicit view shortcuts; put infrequent actions in a
  command menu. Loading/recovery uses the existing central modal. Check 80×24,
  160×50, resizing, keyboard-only navigation and focus for every new view.
- **Files arrive through one intake path.** A source endpoint reads only the
  selected media/files. An isolated receiver stages data, the manager receives
  metadata, and the user approves the verified manifest before publication to
  `imports`. OnionShare reuses this path. No automatic
  execution, preview or archive extraction on receipt; an agent may send file
  contents to the provider when using them as context. A future outer-host
  file picker must send only an explicit selection through a bounded endpoint;
  qualify that adapter before offering it, without requiring a new native app.
- **Large backups need a separate operation.** Document transfers currently
  allow 256 MiB / 1,024 entries; a default session container is already 512 MiB.
  Keep bounded document limits. Add an authorized, streaming ciphertext-backup
  path with its own storage budget and cancellation, rather than giving the
  document browser access to the general vault. Close/flush/lock the selected
  session before copying its LUKS2 container; include versioned, encrypted
  session metadata without introducing custom cryptography. Validate lengths
  and hashes for copy corruption, then check the restored filesystem/database
  inside an offline guest using the session password. A hash alone does not
  authenticate an untrusted backup. Restore creates a separate archive entry,
  preserves chat IDs and the source, and keeps the one-open-session invariant.
  Do not back up VM RAM or unlocked saved-state files.
- **Explicit export boundaries.** Markdown/JSON and ordinary file exports are
  readable copies. Backup payloads remain encrypted. Diagnostics are generated
  from a fixed allowlist of version/platform/state/error fields, previewed and
  exported only on request; exclude conversations, documents, keys, access
  URLs, filenames and memory dumps. Ephemeral sessions offer readable exports
  but cannot be described as an existing persistent LUKS backup; an encrypted
  save-to-archive action needs its own explicit user-created archive flow.
- **OnionShare is a separate transfer capability.** Run its HTTP/file handling
  in the transfer boundary, with bounded RAM or encrypted staging. Only the
  gateway boundary may make external connections. Design and test an isolated
  Tor-service/control adapter; never hand the session a raw Tor control socket
  or the API broker's credentials. OnionShare requires Tor even when inference
  uses SOCKS5: request and show transfer Tor readiness separately, preserving
  the selected model transport. Private, expiring transfers are the default;
  disable webhooks, filename/request logging and automatic public services.
  Received content remains untrusted. Closing/locking revokes the service and
  cleans or explicitly recovers unfinished staging before reporting success.
- **Shell and agent tools use the same Rules.** Local operations
  work offline; permitted remote operations go through the gateway and scoped
  credentials. New tool destinations do not expand the model-provider
  allowlist. A generic proxy or shell subprocess must not provide an alternate
  route around Rules. Keep outer-host LAN, gateway-management and host-control
  services outside the session's reach.
- **Reuse upstream code deliberately.** Start with OpenCode PTY/jobs,
  OpenTUI, the existing transfer library and OnionShare CLI. Audit dependencies'
  logs, updates, crash output and temporary files. Bundle required runtimes in
  the image or a verified supported component delivery flow; users should not
  need package-manager commands or manual service setup.

Begin implementation with M1 after recording M0's remaining qualification
items. Use the current controller/guest boundaries and extend their internal
protocols as required. If a public Protocol or Server HttpApi changes, regenerate
the client from `packages/client` and respect the repository dependency layers.
Use disposable fixtures/copies for failure tests. This roadmap update itself
changes no running VM, personal archive, host network setting or release image.

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

### Remediation progress

The audit above records the original findings. Implementation proceeds in
separate commits; a code fix does not close its remaining runtime release gate.

| Finding | Implemented and checked | Still required |
| --- | --- | --- |
| A1: application readiness | Chat startup now remains `starting` until the attached OpenCode client confirms a DB-backed read after connection/plugin initialization. Guest migration runs after viewer attachment and reports fixed failure codes; failed startup revokes the capability and returns the same unlocked volume to Documents, retaining the recovery latch if cleanup fails. Console/parser and manager regressions cover success, storage failure and client exit. | Compiled TUI/controller lifecycle and modern starting/recover/cancel transitions pass in Linux. Still qualify the user-facing full/corrupt-disk dialog and failed offline recovery on supported KVM hardware. |
| A2: committed chat durability | SQLite connections now use WAL/FULL. With pinned Bun 1.4.4, 27 database/migration/workerd tests pass, including on-disk commit/reopen and sync-policy coverage; core typecheck passes. | The compiled API now passes outer-VM SIGKILL/reboot on two LUKS layers (details below). Physical power-loss behavior and target-hardware latency remain release qualification. |
| A4: legacy resets | Pending destructive migrations now preflight their populated tables before executing the migration sequence. Unknown populated V2 projections and old pending inputs are refused, not reset. The tested completed July V2 lineage still preserves messages, pending work and events; fresh/current databases remain supported. Database/migration/workerd suites: 36 passing tests. | Five compiled-client migration fixtures pass. Confirm the recovery dialog on supported KVM targets. Unsupported pre-launch archives must be opened with their original client for export/recovery; no automatic data-erasing upgrade. |
| A5: disk retention | Rebuilt ARM64 ISO inventory and runtime inspection verify RAM-backed writable system paths, no swap and disabled journal storage/forwarding. Synthetic lifecycle and crash disk scans find no plaintext markers; ephemeral use leaves the encrypted general image byte-identical. | The outer OS/hypervisor remains trusted. Guest controls cannot prevent host swap, snapshots, dumps or screen capture; qualify and document each supported host profile. No universal zero-retention claim. |
| A7: provider errors | The broker now returns fixed classifications and actionable messages for 401, 403, 429 and 5xx without forwarding provider bodies/headers. Ten local TLS/SOCKS broker tests pass, covering nine upstream status cases, credential stripping, disconnects and revocation. | Both compiled adapter tests and the Linux credential lifecycle pass. Provider acceptance remains separate; no real key was used. |
| A6: bootstrap lifecycle | Tor exposes only a validated 0–100 progress value. Modern startup schedules the gateway without blocking on systemd bootstrap, shows progress, counts controller work in the 120-second deadline and routes cancellation through controller cleanup. An in-flight operation settles before ordered cancellation/revocation; cleanup may exceed the connection deadline and is shown explicitly. Existing synchronous legacy entry remains available. Parser and manager tests cover malformed progress, elapsed controller time and cancellation after a controller accepts startup. | Live Tor bootstrap/guard persistence, packet capture, stalled-owner cleanup and controller cancellation pass in Linux. Qualify the deadline/progress UI on supported KVM hardware and degraded real links. |
| A6: key metadata | The controller now distinguishes effective credential changes from labels and unrelated keys. Renaming, replacing with the same secret, removing an unused key and changing a default hidden by an opening override preserve the gateway; effective replacement/removal/selection revokes it. Nine Linux key tests pass. | Real gateway PID checks now pass for rename, unused-key add/remove, replacement and removal. Target-hardware UI acceptance remains. |
| A3: global shutdown | Gateway shutdown distinguishes verified termination from checkpoint persistence. Lock/recover attempts gateway, transfer and session shutdown before checking results; a failed stop retains the recovery latch and prevents mapping closure. After successful closure, a lost Tor checkpoint produces a specific locked-state notice. Linux host builds and 55 Rust tests pass; 25 manager tests and typecheck pass, including the notice at 80×24/160×50. | The stopped-owner injection now passes with real LUKS and the gateway VM. Supported KVM hardware acceptance remains. |
| A8: host egress | The live host installs an atomic nftables default-deny policy before NetworkManager or the controller starts. Only the gateway hypervisor UID may open external TCP; IPv6, host/session/transfer TCP and external DNS are blocked. IPv4 DHCP and explicit diagnostic SSH subnets are the narrow exceptions; release images have no SSH service. Stopping the policy service does not flush its rules. | The rebuilt ARM64 ISO passes static inventory, runtime policy and boot-order checks. Qualify amd64 and actual Wi-Fi/Ethernet hardware. |

The rebuilt ARM64 ISO boots with the host policy active **before** NetworkManager
and the controller. Both services require the policy unit. Real namespace
packets exercise gateway TCP, blocked host/session/transfer traffic and DNS,
DHCP and diagnostic SSH opt-in/revocation. Stopping the firewall service retains
its rules; an invalid replacement fails without removing the previous policy.
The direct-kernel probe uses a RAM-only diagnostic overlay, no external NIC and
no writable disk. Its Python/nft executable/library paths come from the ISO's
immutable guest images; the production service confinement is retained.
Evidence: `artifacts/oblivion-audit-boot-order/summary.json` (ignored).

### Disposable Linux qualification (2026-10-27)

The ARM64 Linux client was rebuilt with Bun 1.4.4. A swap-free Debian guest
with no external NIC passed **68 checks** using the current gateway bundle:
35 component tests, 10 activation tests, production UID/capability/channel
checks, both compiled-adapter streaming/revocation tests and all five compiled
chat-storage migration tests. The storage cases cover channel histories,
conflicting transcripts, invalid sources, pending input and committed WAL
frames. The adapter packet capture recorded 766 TCP/IPv4 packets, zero
non-loopback/UDP/IPv6 packets and zero dropped/truncated packets. No synthetic
marker was found on the scanned writable disk. This is scoped loopback/lab
qualification, not a claim that the release ISO or outer hypervisor cannot
retain data. Evidence: ignored local `artifacts/oblivion-audit-storage-vm/summary.json`.

The corrected systemd/LUKS lifecycle run passed **40 checks**, including the
compiled TUI with actual shell-tool execution, full storage, hidden key/proxy
credentials, interrupted formatting, ephemeral isolation, manager/controller
SIGKILL, stalled-VM recovery and explicit force-stop. Read-only/ephemeral use
left the complete general encrypted image byte-identical. The writable-disk
scan found no synthetic secret/document markers. Evidence:
`artifacts/oblivion-audit-services-current/summary.json`.

A real gateway-owner lifecycle run passed **15 checks**, including retained
PIDs for harmless key edits, credential revocation, failed startup, owner death,
an unresponsive VM and a failed checkpoint followed by verified gateway,
session and storage closure. Modern startup remains `starting` until explicit
client acknowledgement; recovery returns the same unlocked volume to an offline
Documents VM, and cancellation stops the gateway without losing that VM.
This run used the actual units and encrypted profile with the compiled host
bundle. Evidence: `artifacts/oblivion-audit-gateway-lifecycle-final/summary.json`.

Selective Tor-state qualification passed **8 checks**, including live bootstrap
and retaining sampled guards across two gateway lifetimes. The outer capture
contained zero packets before explicit networking enablement, then 7,348
TCP/IPv4 packets and zero UDP/IPv6 packets. No provider request or real credential
was used. No synthetic secret marker was found on the writable disk.
Evidence: `artifacts/oblivion-audit-tor-state/summary.json`.

The rebuilt ISO also passed an outer-VM crash/reboot test: two committed chat
histories, their titles, durable pending input and a document survived SIGKILL
immediately after the compiled chat API acknowledged admission. Storage used
two nested LUKS2 layers. The raw disk contained no plaintext canary or test
password. This destroys the guest RAM; it does **not** simulate loss of the
physical Mac's power or storage cache. This focused probe runs the real chat
API on encrypted storage, not a complete interactive session-VM workflow.
Evidence: `artifacts/oblivion-audit-final-powerloss/summary.json`.

Static inventory of that exact ISO matched all five package manifests: host
282, session 154, gateway 132, import/export 110 each. No diagnostic image marker
was present. Runtime observation found no swap, a tmpfs root overlay, tmpfs
`/tmp`, `/var` and `/run`, read-only live media, no INET listener and disabled
journal storage/forwarding. The host services observed were Oblivion's
controller/manager/console/seat, NetworkManager/dispatcher/wpa_supplicant and
Debian's D-Bus/hostnamed/journald/logind/udev. An unnecessary dpkg database
backup timer/service was removed from activation by masking both units.
Idle services and no-NIC observations are not a claim about every connected
workload. Evidence: `artifacts/oblivion-audit-final-inventory/inventory.json`
and `artifacts/oblivion-audit-boot-order/summary.json`.

Nested lifecycle labs use TCG explicitly in the lab build. They test behavior,
not production KVM isolation or performance. Direct live-ISO probes use HVF with
a diagnostic initramfs, so they do not replace unmodified UEFI/USB acceptance.
User archives, running personal sessions and the existing USB candidate were
not modified. Generated evidence stays ignored; the separate audit ISO is not
published as a release.

The new compiled migration tests are part of the gateway laboratory bundle,
so future qualification runs execute them rather than relying on source-only
unit tests. Repository-wide `bun run check` passes; the manager suite currently
has 88 passing tests.

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
