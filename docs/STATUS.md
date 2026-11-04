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
the local receiver filesystem; copy source selection, approval and payload
streaming remain in that adapter. Both paths reuse the same Safe lookup and fresh
opening check. Invalid inspection syntax fails before runtime startup. Portable
tests, a real Unix controller-socket fixture and the existing copy checks pass;
this does not provide Windows filesystem endpoints or installed transfer acceptance.

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
The Windows installed entrypoint and initial setup are now connected in source; local payload endpoints, a normal-user privilege broker, software lifecycle and grant/network-recovery integration remain unfinished.
Pipe peer/ACL behavior
with the actual HCS worker, boot, inner KVM and the installed lifecycle remain
Windows acceptance gates. See the [Windows backend](WINDOWS.md).

Safe tasks, family password changes and personal-backup recovery now also use the
portable frontend. Their DTOs have one Wire owner, with controller-specific slot
aliases where required. Real Unix fixtures cover offline task review/start,
family preview, backup reconciliation after a lost reply and explicit discard.
Malformed grammar fails before runtime startup. Copy streaming remains in the
Unix adapter; these commands do not provide Windows filesystem endpoints.

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
Local payload copies, Share, backup file streams and software update/removal are
still explicitly unavailable there and fail before installation discovery/boot.

Windows setup now records Pending before bundle publication, configuration or
VHDX creation. Bundle validation checks real inventory, hashes, file identities
and ACLs; publication creates only a new private directory. Boot copies are
separate from the immutable release. Setup commits Ready only after authenticated
controller startup, verified shutdown and VHDX UUID/capacity/file-identity checks.
Interrupted setup never retries as disk initialization. Current preflight requires
an elevated token and nested HCS capabilities; no implicit elevation or normal-user
broker is implemented. Portable installation tests and MSVC compilation pass.
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
