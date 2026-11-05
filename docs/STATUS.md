# Oblivion 1.0 status

Updated 5 November 2026. The current source is a development refactor. Published
0.x images are the earlier Live-only product; they are not releases of the native
privacy framework. Use the [roadmap](oblivion1.0-roadmap.md) as the authoritative
feature and acceptance ledger.

Implemented source includes the native CLI, Mac and Linux x86_64/ARM64 helpers,
controller separation, official clients, private terminal/file relays, per-Safe
network control, RAM-only mode, family credentials, child-Safe creation, managed
chat jobs, same-agent native Share transfers and the OpenTUI manager. Shell/tmux uses
the same private relay and official agent wrappers. Share includes Safe/branch/all
export, guest review, encrypted streams, fresh-volume import, atomic collection
publication and explicit import recovery. These source statements do not imply
that all end-to-end paths have passed in an installed candidate.

The local chooser accepts an explicitly pasted path or local file URL,
reviews its type and resolved location, and leaves the existing copy review
in place. Existing literal paths take precedence; a pinned MIT parser also
accepts a single terminal-escaped path without executing a shell, expanding
variables or globs. Nothing is imported by pasting. Actual terminal drop gestures
and OS-native drag-and-drop APIs remain unqualified or unimplemented respectively.

Native copies now have stable operation IDs and receiver-side outcome records.
CLI and manager distinguish unknown, incomplete, ready, published and discarded
states rather than treating a failed command as proof that no output exists.
Explicit recovery verifies private staged content and finishes publication
without recopying; discard preserves published output and later user edits.
Records bind the Safe and destination identity, and file attachment checks the
current opening and lock fences under the controller lock. The manager's latest
32 references stay in RAM; durable context is only in encrypted Safe staging or
the selected export destination. Receiver inventory now restores access to those
operation references after a manager restart. Import inventory stays inside the
Safe; export inventory requires choosing its destination directory again. It
returns bounded metadata, then requires fresh status before recovery or discard.
It stores no new desktop history of source or destination paths.

Persistent receiver identity now uses a filesystem UUID and inode instead of a
mount's device number. A real isolated Linux fixture remounts the same ext4 data
on another loop device, recovers its pending publication and preserves later
edits after another remount. Current-device checks and pinned descriptors remain
in use during a live publication. Linux uses the descriptor-based UUID operation
available since kernel 6.9; macOS uses its volume UUID. Unsupported filesystems
fail before new receiver records are created. This does not replace the remaining
whole-VM, USB and native-chat restart acceptance gates.

Native copies now prepare one actual manifest before confirmation, retaining
the selected source or offered guest data and pinned destination through review.
The manager remains rendered while a private subprocess reports recursive
counts, total bytes, payload progress and finalizing. Its bounded event channel
requires an approval for that digest; a Cancel or owner EOF revokes copy I/O.
Only confirmed pre-approval cancellation claims that no file contents were
copied. Later interruption is reconciled from receiver records. The process
client retains ownership until actual child exit and uses bounded cleanup of
that child alone. CLI terminal copies review and confirm too; unattended copies
require `--yes`, which cannot bypass the manager's event approval.

Files now supports a selection basket across local directories and guest
workspace/imports pages. A single item keeps its layout; multiple inputs use one
named collection and one atomic publication. The backend resolves overlapping
folders and colliding leaf names, and the manager verifies every ordered mapping
page and its digest before enabling review. Absolute local source paths remain
in the calling process; only logical aliases enter the source offer. The CLI uses
repeated `--source` or `--path` selectors, with an explicit collection name for
multiple inputs. Native GUI drop APIs and installed-platform acceptance remain
incomplete.

Cross-agent conversation sharing, synchronization, conversion and handoff are
outside the 1.0 scope. Each agent owns its native chats and resume inside the
Safe. The canonical catalog, sync/projection workers, cross-agent deletion
protocol, history leases and Claude admission hook have been removed. Official
clients launch directly with their encrypted native profiles. Share preserves
the originating agent and native conversation formats; it never populates the
other clients. Retained experimental evidence is in [HISTORY](HISTORY.md).

Live now packages a launcher OS separately from the headless controller image.
Both Live and desktop use that controller VM. Live persistent data is a reviewed,
dedicated partition on the boot USB; RAM-only mode never attaches it. The old
controller USB discovery/partitioning code and protocol have been removed.
Archive setup reviews only the managed encrypted file and remains locked after
creation. Debian NetworkManager, keyboard and time-zone dialogs are reachable
on fixed virtual consoles; OS preferences remain in the volatile Live overlay.
No automatic NTP service was enabled. See [Live controls](LIVE.md).

The ARM64 outer Live now selects QEMU from Debian backports, records its package
version and executable hash, and verifies that evidence before ISO packing.
The native Linux helper requires QEMU 10.1 or newer on ARM64 before it can claim
support or allocate runtime data. This closes a source mismatch: the selected
EL2-capable kernel alone was insufficient with Debian stable QEMU 10.0. The inner
EL1-only QEMU and amd64 selection remain stable. Process and policy fixtures
cover the refusal and inventory; no new Live boot is qualified by this change.

Live controller initialization now overlaps the three-second, once-per-boot
wordmark. Initial status requests share one operation and the startup budget;
a cold-start failure stays visible until explicit retry. A shared runtime
supervisor now tracks exact client process births and backend ownership, releases
an abandoned startup, preserves a runtime adopted by another client and requests
guarded idle shutdown only when no owners remain. Busy or uncertain shutdown
does not become a successful stop; refused shutdown preserves live Share and
family authority. Backend helpers terminate their owned VM when their inherited
supervisor channel is lost. Real-process fixtures cover these source boundaries;
installed bootstrap interruption, USB reboot and nested virtualization remain
acceptance gates. No unimplemented Cancel action is presented.

The agent chooser now separates Enter for a new conversation from C to
continue that agent's latest conversation in its current workspace. A saved
task with an observed native chat ID offers a reviewed native resume after
rechecking the exact task, job cleanup and Safe opening. It sends no task
again. Native pickers and arguments retain their own behavior. Task resume uses the
same agent; backend shutdown and native persistence still require qualification.

Agent-created Safes have an explicit review screen. Closed RAM children resolve
to their existing volume and require their live parent's family authority; they
are not silently replaced with another Safe. Queued child tasks are sealed to
family/context before their creation journal is written. They are omitted from
public status and portable Share data. The CLI and manager now provide explicit
offline task review, start/reconciliation, confirmed retry and cancellation,
plus current managed-job identifiers and outcomes. Plaintext is fetched only for
review, escaped for display and cleared on Back, error, lock or opening change.
Native-client access sends no saved task. Creation-triggered startup now has a
credential-only delegation path for the supported native credential forms,
offline installation and a bounded gateway startup before task admission.
Ordinary OAuth caches are not cloned; unsupported or missing login leaves a
needs-auth observation. Installed-VM and real-provider qualification remain open.

The immutable SafeAdmin checkpoint now stores child provenance, the sealed task
and attempts inside the encrypted volume. Raw restore authenticates the volume
password/token and task context without requiring the mother, preserves original
identity/family/key and publishes through the current transaction with Offline
policy. The native personal-backup CLI provides full-volume export/import,
explicit finish after a wrong password, metadata-only status and discard.
The manager provides the corresponding path chooser, contents review and
transaction recovery screens, with passwords handled only by the private CLI.
Lock revokes copy workers before releasing the archive. An actual VM
backup/restore round trip remains an acceptance gate.

Family password changes now preview the complete local family, bind the review
to the current host opening and header digest, and preflight actual keyslots
before updating wrappers. An encrypted journal fences affected members after
interruption; explicit completion or rollback checks the whole set first.
Real LUKS2 header fixtures cover recovery and standalone child credentials.
Data keys are unchanged, so old copied headers and backups are not revoked.
See [family passwords](PASSWORDS.md).

The footer now shows a fresh Safe-scoped policy beside Network. Policy and
Tor/SOCKS5 observations bind to the host opening and the exact Safe ID, slot and
opening nonce, and expire after ten seconds. A locked, closing or reopened Safe
cannot inherit a previous positive route mark. Physical host-link status can
still appear on the welcome screen. Renderer fixtures cover these boundaries
at narrow and wide sizes; real gateway fault-injection acceptance remains open.

Development desktop bundles pair the CLI, manager and helper with a verified,
source-matching controller image and boot files. Stopped-runtime updates preserve
the private disk identity and reject mismatched assets. Stopped-only collection
and uninstall now remove verified managed software while preserving encrypted
data and runtime identity; fixture tests cover ownership and reinstall. Actual
installation, update, uninstall and signed-distribution qualification remain open; unsigned
checksums are not release provenance. See [desktop bundles](DESKTOP.md).

The development Debian package reuses the Live immutable role assets. Real dpkg
install/remove/purge/reinstall fixtures preserve configuration and data, and
validate payload ownership and inventory schemas. Actual role builds and the
service lifecycle on a real systemd/KVM host remain open. See [Debian](DEBIAN.md).

The Linux desktop package is separate from the private controller package.
It declares host dependencies and exposes `/usr/bin/oblivion`. First launch
checks host readiness and publishes a private per-user release. The package
entry point defers an APT update while the runtime is in use, then applies it
at the next launch after shutdown with the same disk and runtime identity.
The Polkit helper can enroll the authenticated local caller in Debian's
`kvm` group after explicit consent. The VM runs under the user's account.
Debian ARM64 packaging fixtures, Linux socket-credential tests, private
release fixtures on Linux and macOS, and the canonical root check passed.
Full artifact builds and APT, Polkit and nested-VM tests on target hosts
remain open. See [Debian desktop setup](DESKTOP.md#debian-desktop-package).

Local fixtures have checked terminal and control framing, stale ownership,
canary-protected RAM mode, idle locks, actual native history readers/importers,
SafeAdmin, managed jobs, file hashes and Share authentication. Gateway socket
checks include remote destination names, proxy authentication, revocation,
public TCP/passive FTP and collector blocks. They do not replace packet-level
acceptance with two actual Safe gateways.

On the test Mac M4 Pro, cached full-synchronization disk I/O fixed the reproduced
outer Debian memory-corruption failures in subsequent host cycles. The inner
Safe KVM guest still fails before Oblivion services. Software emulation reaches
userspace and has verified a synthetic encrypted file round trip across restart;
this diagnostic result does not qualify Mac hardware acceleration. There is no
production emulation fallback. Linux hardware acceptance and the Windows backend
remain open.

Portable CLI run/proxy parsing, private wire framing and Files validation now
compile for Windows MSVC; the Windows CI job includes their portable tests. The shared
amd64 controller build also verifies Hyper-V driver coverage in its kernel and
initramfs. Remaining Windows command orchestration, installed backend integration and
installer remain incomplete or unqualified; see [Windows requirements](WINDOWS.md).

The manager's target descriptor now drives both its builder and native launcher
discovery, including Windows x64 `.exe` names and the pinned OpenTUI DLL. Local
and guest file pickers supply their own parent paths instead of applying POSIX
path rules to Windows drives. Target and production-picker fixtures pass on the
development Mac. CI definitions compile and exercise that frontend on Windows;
no Windows PE execution, installed bundle or Hyper-V qualification is claimed.

`status --json`, `safes` and `close NAME` now run through the shared frontend
parser/executor in `oblivion-cli`, with the same State/Safe lookup used by the
other existing launcher commands. Agent `run`, storage lifecycle and tmux `shell` now use
shared orchestration too: Safe creation/reopening, storage-mode checks, protected
startup and idle cleanup are consumed by the actual Unix launcher. OS adapters
retain private prompts, human confirmation, monotonic clocks and terminal leases.
The shared `init` creates but leaves the archive locked; incomplete-setup reset
does not recreate it, and first-run `run` uses those same Init/Unlock operations.
Storage, run, Workspace, network and proxy syntax are checked before runtime startup.
Network changes after
opening, including Egress, carry both the slot and expected Safe ID; malformed
creation IDs fail before naming or attachment. Actual Unix-socket fixtures cover
these paths, including opaque argv, RAM-child reuse and failed cleanup. This does
not qualify the installed VM or complete the Windows launcher. The authenticated
Unix adapter remains the production transport. Both local and desktop control
paths use one portable request/response codec while preserving their framing and
lifetime boundaries.
Malformed peer data produces static protocol/state errors instead of repeating
payload fields. A Windows backend and the remaining portable command
orchestration are still open.

Network status/set and saved proxy list/add/remove now use the common frontend
and the same controller DTOs. A network command selects one open Safe and one
change before any effects; the final status read retains its expected identity.
Proxy lists admit only bounded public metadata, not credential-bearing fields
or raw parser diagnostics. Hidden URL/password entry shares one completion path.
Actual Unix-socket fixtures cover temporary read-only routing, private credential
entry, unchanged active transports and malformed-listing rejection. They do not
qualify public Tor/SOCKS5 paths or replace the real-gateway acceptance gates.

Safe open/rename/grow and automatic-lock settings now use the portable frontend
as well. Offline open pins the exact Safe without starting an agent; growth uses
a free maintenance slot after checking mode and closed state. Persistent rename
does not need an idle slot. The controller explicitly allows that catalog-only
operation while a Share maintenance VM occupies the default slot, retaining the
other maintenance restrictions. Temporary rename stays bound to its opening.
Idle preferences and complete status now share one wire model with the producer;
partial updates preserve the other timer and zero remains an explicit disable.
The controller's human-activity tracker is unchanged. Real Unix-socket fixtures,
portable DTO/command tests and the Linux maintenance-admission predicate cover
these source boundaries. Actual disk growth and cold-restart acceptance remain open.

Files inspection and recovery now use the portable frontend for list, transfers,
status, recover and discard. The Unix adapter supplies private file channels and
the local receiver filesystem; copy syntax, approval and payload streaming are shared; platform adapters own
filesystem and transport handles. Both paths reuse the same Safe lookup and fresh
opening check. Invalid inspection syntax fails before runtime startup. Portable
tests, a real Unix controller-socket fixture and the existing copy checks pass;
Windows filesystem endpoints are now connected in source; installed transfer
acceptance remains open.

Windows now has an experimental HCS helper core with direct kernel/initrd
boot, owned VM handles, private VirtioSerial token provisioning, local named-pipe
control and authenticated AF_HYPERV. Linux and Windows consume one runtime-auth
implementation. File leases check ACLs, object identity and VHDX metadata; the
guest selects the configured VMBus SCSI controller and LUN before disk writes.
Supervisor loss is observed during HCS waits. Successful shutdown requires an
actual Stopped observation; uncertain cleanup retains the leases until exit.
Portable models and MSVC compilation pass locally. Native Windows ACL, pipe,
cancellation and lifetime fixtures are defined in CI but have not been executed
on this Mac. Network startup now prepares an owned isolated HCN ICS switch and
static endpoint. The HCS builder binds its metadata to the runtime; Debian writes
the MAC-matched IPv4 profile only in RAM before NetworkManager starts, with no
automatic Hyper-V DHCP fallback. HCN responses must confirm the requested
identity and addresses. Creation precedes the VM, and cleanup requires its
confirmed stop and observed network-resource absence. HCN calls are synchronous;
service hangs, exact flags, coexistence and recovery still require Windows tests.
The Windows installed entrypoint, initial setup and local Files payload endpoints are now connected in source; the normal-user SCM broker and stopped-only software maintenance are connected in source, with receipt-bound grant/network recovery now connected and installed qualification still open.
Pipe peer/ACL behavior
with the actual HCS worker, boot, inner KVM and the installed lifecycle remain
Windows acceptance gates. See the [Windows backend](WINDOWS.md).

Safe tasks, family password changes and personal-backup recovery now also use the
portable frontend. Their DTOs have one Wire owner, with controller-specific slot
aliases where required. Real Unix fixtures cover offline task review/start,
family preview, backup reconciliation after a lost reply and explicit discard.
Malformed grammar fails before runtime startup. Copy streaming now uses one portable payload exchange with native filesystem
endpoints; Windows fixture execution and installed transfer acceptance remain open.

The Windows same-user named-pipe client now implements the shared controller
adapter and native Runtime hooks. It authenticates the server SID, supports
bounded requests and cancellable duplex attachments, and uses the shared guest
launch, frame decoder and terminal filter. Console passwords leave redirected
stdin intact; pipes retain native bytes. Explicit release finishes before the
attachment lease closes. Human activity uses the same classifier and
opening-bound report as Unix, through a bounded worker. Real Windows fixtures
cover these boundaries, including an isolated console subprocess; they have
only been cross-compiled on this Mac. There is still no qualified installed Windows
entrypoint or installer qualification.

Remaining release gates include real login and scoped child-credential delegation,
chat persistence after cold restart,
native resume for each agent,
close during active jobs,
family password rotation and independent restore, concurrent Tor/SOCKS5 failures,
Share between two installed candidates, physical media, resource measurements,
desktop installation/uninstall qualification, installed bootstrap terminal-loss
cleanup and signed release provenance. Local inference is deferred until after
1.0. No independent security audit has been completed.

CI builds current-source images as drafts. A successful check, build or checksum
alone must not publish them as qualified releases.

The Windows source now has a private runtime supervisor with per-client leases,
exact helper-process identity and an owned lifetime pipe. Multiple terminals
reuse that runtime. The final owner requests guarded idle shutdown; an uncertain
stop persists Recovery and never becomes a successful stop because a pipe or PID
disappeared. A cancelled or rejected client is isolated at admission, without
stopping other owners. Installed discovery, privilege setup and reconciliation
of HCS/network/grants after a crash remain unfinished.

Fresh Windows disk initialization now creates a private VHDX through the SDK,
binds its identifier and capacity, and retains a nonserializable creation
capability. Only the distinct initial-install path can send NewDisk authority
through the current private bootstrap. The guest stores it in root-only RAM,
matches runtime identity and capacity, requires a blank first block and consumes
the authority before writing its marker. Normal startup cannot authorize a blank
disk. Formatting/checking uses the pinned descriptor; a read-only handoff keeps
that object pinned through mounting. Real Linux procfd tests cover formatting,
checking, refusal and the handoff; the mount case was skipped without the required
capability/loop support. Rust/Python bootstrap tests pass. Windows disk and
supervisor fixtures have been cross-compiled, not executed on this Mac.

Desktop bundles now share one portable manifest validator and canonical identity,
already consumed by the Unix installer. The existing builder accepts a Windows
target with native `.exe` roles and the OpenTUI DLL, while rejecting Windows path
aliases. The native Windows command binary and initial per-user setup now consume this bundle model, but are not a completed or qualified installer to distribute.
The compiler context now includes the common bundle, wire, CLI and Windows
dependency sources; this source change was not qualified by building another ISO.

The top-level command grammar and HELP now have one portable owner, including
runtime commands and typed entry to Unix Files/Share adapters. The actual Unix
executable rejects unknown and malformed commands before runtime startup. The
Windows executable connects the same control/storage/agent/network/task workflows
to per-user installed discovery and supervisor leases; it launches the real
manager with pinned installed assets. Status polling and human-activity reports
read bounded private metadata and use the existing pipe without hashing the ISO
or implicitly starting a stopped runtime. Windows Files reads guest pages and
receiver outcomes through opening-bound attachments, releasing before pipe close.
Local Files payload copies are now connected to the shared protocol and consent
flow. Software update/removal is now connected through the observed-Stopped maintenance path.

Windows setup now records Pending before bundle publication, configuration or
VHDX creation. Bundle validation checks real inventory, hashes, file identities
and ACLs; publication creates only a new private directory. Boot copies are
separate from the immutable release. Setup commits Ready only after authenticated
controller startup, verified shutdown and VHDX UUID/capacity/file-identity checks.
Pending setup now retries bootstrap only for its recorded original disk identity. Current preflight requires
an elevated token and nested HCS capabilities for setup and the privileged worker;
ordinary launch now delegates to the SCM broker described below. Portable installation tests and MSVC compilation pass.
Windows-only fixture execution, actual installation/boot, privilege setup and
HCS/network/ACL reconciliation remain acceptance gates. No ISO was built for this
increment.

The Windows development builder now compiles the actual CLI/helper and manager
assets on the matching host, binding the launcher to the shared source inventory.
With a real matching controller it uses the same prepare/assemble verification;
without one it emits build inputs, never an installable manifest or fake runtime.
Its new work/output tree has private current-user/System ACLs. Repository text
uses LF across platforms for exact source pairing. The Python inventory and
builder suite passes; PowerShell parsing is registered in Windows CI, while a
real Windows build has not been executed on the development Mac.

Live startup diagnostics now stay on the delegated PTY. Real-process tests verify
stderr, termios restoration, owned-child cleanup and explicit R after failed or
normal exits. The locked Live manager offers Change storage mode, stops file
workers and the runtime, then exits to that explicit retry screen. Failed switches
pause automatic status requests and preserve a usable file adapter after confirmed
worker shutdown. Codex selection explains native Device Code login without
rewriting agent arguments or forwarding a callback port.

New USB setup durably writes its identity to the reviewed free extent before
publishing the new partition entry. The existing partition geometry and sample
data survive the actual sfdisk sparse-file test, and the new identity remains
readable without completing kernel node setup. Unknown partitions are not
formatted as recovery. Physical USB, kernel discovery and full power-loss tests
remain open.

Interactive OpenCode2 process trees now enter a Safe-owned systemd scope. The
native elected server and native restarts can outlive their first TUI without
belonging to the attachment's cgroup. Private managed --standalone jobs retain
the original service cgroup and fixed native entrypoint. TERM/HUP cleanup was
exercised with actual process groups and a detached server-style process. The
pinned ARM64 2.0.1 binary passed two actual TUI clients, first-client closure and
session ID/title recovery through its API and SQLite after a server restart.
This covers native metadata, not provider/tool conversations, real scope/PID1
behavior, encrypted Safe reboot, SIGKILL/OOM or forced-cancel execution recovery.
No new image was built for this increment.

Windows Files now has local source and destination authorities and actual CLI
copy orchestration, including the manager's existing event/approval channel.
The common parser, human review, consent state machine, manifest, receipt and
receiver journal have one implementation. Sources stay pinned; the destination
uses same-volume private staging and exclusive handle-based publication. Native
Windows names are checked before review. Recovery uses the same inventory and
status/recover/discard commands, with a platform-tagged volume/file identity.
Inspection never creates the receive lock or receiver records.

The cancellable data pipe retains a separate zero-access kernel lease until
explicit controller release; cancelling I/O is not treated as cleanup success.
Import opens no guest receiver before approval. Offer, approval and payload
boundaries now flush before awaiting the peer, with actual buffered Unix
socket regressions. Windows filesystem, event-pipe and copy-orchestration fixtures
are compiled for MSVC and registered in Windows CI; they have not been executed
on this Mac. This does not qualify HCS boot, installed transfer persistence,
Windows durability, ordinary-user installation or unknown-resource recovery.

Focused Unix verification passed 25 transfer cases, six copy-parser cases and
ten real launcher/event cases. They include buffered import/export, interrupted
publication, receiver inventory and preservation of user edits during recovery.
The canonical root `bun run check` passed. MSVC checks include the actual
Windows entrypoint, native backend fixtures and Files command fixtures; those
cross-compiles are kept separate from Windows execution and VM acceptance.

Personal-backup copies now consume one portable workflow on Unix and Windows.
The shared core owns writable-state and closed-Safe preflight, slot selection,
private password entry, preparation/receipt validation, Copied reconciliation
and restore completion after a lost reply. Native endpoints pin the selected
LUKS2 source and private output; the payload protocol and volume checks are
shared with the existing media path. Export publishes exclusively only after
controller confirmation. Backup attachment EOF ends authority without the Files
AgentRelease protocol; EOF alone never proves copying or restoration. This
source increment does not qualify Windows execution or an installed-VM round trip.

Verification passed 15 shared CLI backup cases, nine focused Mac transfer cases,
three Linux native-backup cases (including tmpfs publication without a UUID),
and four actual Unix frontend/attachment cases. The canonical root check and
MSVC checks for the complete CLI/entrypoint/tests and Transfer library passed.
Windows named-pipe and synthetic 32 MiB ciphertext adapter fixtures were compiled,
not executed; CI definitions do not replace that missing runtime evidence.

Share now has one native export/import/status/discard workflow consumed by both
actual launchers. Grammar and review live in the CLI; import/export control DTOs
have one owner in Share and are used by the controller producer. Native filesystem
authority is shared with personal backups through local_file Input/Target/Output.
There are no retained Unix-only command copies, converted chat catalogs or
plaintext staging paths. Known provider stores stay excluded; content scanning
remains best effort and reviewed documents/messages can still contain secrets.

Export reopens the reviewed set and refuses a changed plan before publication.
Its source lease revokes pending I/O independently of the source channel and
owner drop revokes surviving watchers. Core sends the exact release/finish/end
operation before local lease close. Import publishes only with the Verified
proof returned after final age authentication, and reconciles a lost commit
without replay. Windows uses bounded native wait slices and fresh authenticated
cleanup, without detached I/O workers or an AgentRelease substitution.

Passed checks: shared grammar/review/import and control fixtures (13 cases),
actual export over UnixStream (one test, success and changed-plan scenarios),
local file authority and backup reuse (four cases), Unix lease owner-drop,
four private control fixtures and two compiled frontend cases. The Linux
controller oblivion-storage compiles, as do the full Windows CLI/entrypoint/tests
and Share library for MSVC. The canonical root check passed. Windows named-pipe
fixtures have been compiled rather than executed. Share between two installed
candidates, actual Windows execution and the hardware acceptance matrix remain open.

Windows source now connects update, verified software collection and software-only
uninstall to the installed CLI. Mutations retain the exclusive election and
journal writer only after observing Stopped and the previous writer's exit.
An update records the exact base/target, preserves configuration/runtime/data
identity, and can finish that transition after the supervisor rebind. Complete
bundles and boot files publish from unique private staging before entering their
fixed names. Registry and supervision records use flushed private atomic
replacement under the same ownership locks; there is no alternate-format reader.

Uninstall keeps data.vhdx, vm.json, installation metadata and the supervisor
journal. It reports unknown or in-use software rather than deleting it or claiming
complete removal; exit code 2 is the explicit incomplete outcome. Recovery only
retries a stop on a live authenticated stop/recovery supervisor and then proves
Stopped. Healthy active runtimes are refused, and absent/unknown HCS/HCN/ACL
state is still not adopted. This maintenance evidence does not qualify ordinary-user service startup; the
SCM broker and principal separation are described in the following increment.

Four portable installation-model cases and six common grammar cases pass on the
Mac, as does the canonical root check. Native Windows all-targets and the full
CLI/entrypoint/tests compile for MSVC without warnings. Windows filesystem,
mutex, journal replacement and pipe fixtures are compiled evidence only; their
execution, forced-interruption durability and real lifecycle remain open.

The Windows CLI now delegates ordinary launch, metadata discovery, resident start,
stop and recovery to a demand-start LocalSystem SCM service scoped to the actual
user SID. Terminal rendering and host Files endpoints stay in the user process.
The broker authenticates the token of the bounded pipe request before dispatch;
the client verifies the protected SCM LocalSystem configuration and pinned process
handle before sending, without querying a foreign SYSTEM token.
Requests cannot carry a user SID, executable, filesystem root or HCS JSON. Each
calling terminal owns one retained broker channel and supervisor lease; loss of
the channel cancels pending admission and releases only that owner.

ProgramData catalogs, boot copies and VHDX files are administrator/SYSTEM owned.
Only published software grants the user read/execute. Supervisor bindings now
include separate client/storage identities, and their global election mutex
serializes Session 0 with elevated setup. Maintenance holds its Stopped proof
while quiescing the broker and switching protected service software. These are
current 1.0 records, with no previous-format reader. Actual SCM installation,
ordinary-user pipe/ACL behavior, interruption and nested Hyper-V acceptance
remain Windows execution gates. No new ISO or platform support is claimed.

For this increment, all 18 portable native-backend library tests passed on the
Mac, and the canonical root lint/typecheck passed. Native Windows all-targets
and the Windows CLI library/entrypoint/tests compile for MSVC without warnings.
The added SID, protected descriptor, caller-token and principal-binding fixtures
are compiled evidence only; no SCM service was installed and no Windows VM was
run on the development Mac.

Windows owned-resource recovery is now connected in source. The helper persists
a private receipt before external effects, binding the exact generation, source/
configuration, principals, original file IDs/VHDX capacity and HCN plan. Its
exclusive lifetime file lock also covers cleanup. Recovery can replace a lost
supervisor only after acquiring its journal writer and that resource lock; it
stops only the receipt-owned HCS generation, verifies both HCN objects before
deleting either and revokes grants only on the original files. The clean receipt
precedes the supervisor's Stopped record. Foreign identities and unknown state
remain fenced. No-receipt recovery requires positive HCS and HCN absence plus
strict runtime-file admission and performs no external mutation.

Normal termination also accepts a confirmed ID-scoped HCS absence after an
ephemeral VM disappears. A generic failed Properties request never means stopped.
Portable model evidence is five HCS, nine configuration, eight network and two
receipt cases passing. Native Windows all-targets compiles without warnings,
including new receipt-lock/atomic-publication and file-evidence fixtures; these
Windows I/O/SDK cases have not been executed. Full lifecycle, interrupted initial
disk setup, forced interruption/power loss and SDK revoke behavior when a VM ACE
is already absent remain qualification or implementation gates. No image was
built or platform qualified by this source increment.

Windows setup now resumes the exact recorded Pending disk. The installer creates
a private staging VHDX, flushes it, commits FileID/UUID/capacity before publishing
data.vhdx and reconciles rename-before-registry interruption by the same FileID.
It preserves unknown/unrecorded partials and refuses replacement disks even with
the same UUID. Initial metadata and configuration publish atomically; a setup
lock serializes attempts. Ready revokes the Pending bootstrap ticket. The helper
no longer creates disks: its initialize operation receives the opaque capability
and reopens only the recorded object. A setup-only cancellation revokes the owned
Child lifetime, observes actual exit, drains the reply and releases the supervisor
writer before receipt recovery. Existing ordinary runtimes are refused.

The guest now validates and consumes a reissued NewDisk capability even when the
matching marker or ext4 filesystem already exists. The ext4 branch runs fsck and
never mkfs. Five portable installation-model tests and ten Mac guest/profile
cases pass. A real Linux sparse-FD/bootstrap/ext4 payload case passes with the
same SHA256 after repeated initialization; the Linux FD suite has four passing
cases and one mount case skipped for missing capabilities. Windows SDK creation,
publish/resume, setup-lock and owned-child cancellation fixtures are compiled
evidence only. Installed Windows setup, forced interruption and power-loss
durability remain unqualified. No new ISO was built for this increment.

Official-client distribution now distinguishes permissive licenses from Claude's
native commercial integration conditions. The image installer checks pinned
upstream LICENSE/NOTICE bytes before network access, preserves the complete
original package and installs the required documentation in the Safe filesystem.
Its evidence records only the installed clients and architecture, executable and
notice hashes, distribution policy and retained upstream notices. Partial or
unlisted installations fail before new downloads or evidence publication.
The notices are inputs to compiler/runtime pairing and survive Safe SquashFS,
controller, Debian and Live packing. Seven actual temporary-root installation
fixtures pass; they use synthetic archives without network access. The canonical
root check passes. These controls identify delivered bytes and conditions; they
do not record legal acceptance or establish exhaustive upstream license compliance.

Windows development bundles now include `install.cmd`, consumed by the ordinary
CLI's native UAC setup. Only verified software enters a fresh pinned staging tree;
the owner and SYSTEM retain full access while administrators receive read/execute.
The parent pins the exact ShellExecute process before sending a bounded request.
The helper authenticates the actual pipe token before interpreting it and selects
the original user's root without trusting a message SID or target path. The
original parent verifies its own broker after helper exit; the elevated helper
never substitutes the administrator's broker during another-account UAC.

Setup checks the actual Windows build, edition, feature state and HCS capability.
Enabling Hyper-V requires explicit confirmation and runs only fixed System32 DISM
arguments. Pending feature changes return a restart-required outcome before any
Oblivion service, VM or data disk, without rebooting automatically. Requirements,
servicing and installation share caller-EOF cancellation and scoped owned workers.
Interrupted Windows servicing remains unconfirmed and is re-queried on retry.
Human-readable diagnostics preserve the distinction between unavailable hardware
observations and a proved firmware setting. PowerShell 7, Python and the SDK are
builder dependencies only. User command registration and software maintenance now
use the original parent and the authenticated UAC helper respectively, as detailed
below.

Verification passed all 33 portable native-backend library cases. Full bundle
fixtures passed 16 cases with one case-alias test skipped on the Mac's
case-insensitive filesystem. Native Windows all-targets and the full Windows CLI
library/entrypoint/tests compile for MSVC without warnings, including the new
staging ACL and authenticated setup pipe fixtures. Those Windows kernel-object
cases have not been executed here. Actual same-account/other-account UAC, servicing
cancellation, clean Windows PE startup with Hyper-V disabled, reboot continuation
and nested-Safe boot remain acceptance gates. SDK import declarations do not prove
that ComputeCore/ComputeNetwork can load on that clean baseline. No ISO, VM or
Windows OS settings were changed for this increment.

Windows update, GC and uninstall now use that same UAC operation. The bounded
request/response binds the exact reviewed operation; update authenticates the
incoming current-format bundle's source instead of the old CLI's source. GC and
uninstall verify the actual running launcher role and FileID before staging.
Metadata-only handles admit published-software ancestors without granting access
to the private catalog or data; root/leaf ACLs, inventory and hashes remain checked.
The parent retains its source pins through helper exit, preventing partial
deletion of the invoking release. In-use uninstall stays explicitly incomplete;
a verified external bundle can finish it. Install now restores an Uninstalled
runtime through the existing stopped-only update path, preserving the original
disk identity without a Pending initialization capability.

Only the original parent writes its own HKCU command registration after an
authenticated outcome. The native release's bin directory goes directly into
user PATH, without a shell wrapper. Other entries, raw UTF-16 and registry type
are preserved. A bounded pending ownership record precedes writes, detects a
changed snapshot and reconciles known before/after states. Uninstall removes
only its owned entry; uncertain registration returns an explicit incomplete code.
An environment-change notification does not update the old terminal, so the CLI
asks the user to open a new one.

All 39 portable native-backend library cases pass, including operation confusion
and the five new PATH planner/recovery cases. The canonical root check passes.
The complete native backend and CLI library/entrypoint/tests compile for MSVC
without warnings. New real Windows fixtures cover restricted-token software
admission, source pins, private catalog/data refusal and isolated HKCU keys; the
software lifecycle fixture now includes reinstall. They are compiled evidence
only on the Mac. Actual UAC, registry mutation, uninstall/reinstall, cleanup
durability and nested Hyper-V qualification remain open. No ISO or VM was built.
