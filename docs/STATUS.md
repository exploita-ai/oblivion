# Oblivion 1.0 status

Updated 4 November 2026. The current source is a development refactor. Published
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
compile for Windows MSVC and are exercised in the Windows CI job. The shared
amd64 controller build also verifies Hyper-V driver coverage in its kernel and
initramfs. The Windows frontend, backend, bootstrap authentication, EFI boot and
installer remain unimplemented or unqualified; see [Windows requirements](WINDOWS.md).

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
