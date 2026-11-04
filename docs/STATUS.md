# Oblivion 1.0 status

Updated 4 November 2026. The current source is a development refactor. Published
0.x images are the earlier Live-only product; they are not releases of the native
privacy framework. Use the [roadmap](oblivion1.0-roadmap.md) as the authoritative
feature and acceptance ledger.

Implemented source includes the native CLI, Mac and Linux x86_64 helpers,
controller separation, official clients, private terminal/file relays, per-Safe
network control, RAM-only mode, family credentials, child-Safe creation, managed
chat jobs, canonical history adapters and the OpenTUI manager. Shell/tmux uses
the same private relay and official agent wrappers. Share includes Safe/branch/all
export, guest review, encrypted streams, fresh-volume import, atomic collection
publication and explicit import recovery. These source statements do not imply
that all end-to-end paths have passed in an installed candidate.

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
Lock revokes copy workers before releasing the archive. An actual VM
backup/restore round trip remains an acceptance gate.

The footer now shows a fresh Safe-scoped policy beside Network. Policy and
Tor/SOCKS5 observations bind to the host opening and the exact Safe ID, slot and
opening nonce, and expire after ten seconds. A locked, closing or reopened Safe
cannot inherit a previous positive route mark. Physical host-link status can
still appear on the welcome screen. Renderer fixtures cover these boundaries
at narrow and wide sizes; real gateway fault-injection acceptance remains open.

Development desktop bundles pair the CLI, manager and helper with a verified,
source-matching controller image and boot files. Stopped-runtime updates preserve
the private disk identity and reject mismatched assets. Actual installation,
update, uninstall and signed-distribution qualification remain open; unsigned
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

Remaining release gates include real login and scoped child-credential delegation,
chat persistence after cold restart,
interactive cross-agent resume and author admission, close during active jobs,
family password rotation and independent restore, concurrent Tor/SOCKS5 failures,
Share between two installed candidates, physical media, resource measurements,
desktop installation/uninstall qualification and signed release provenance. Local inference is deferred until after
1.0. No independent security audit has been completed.

CI builds current-source images as drafts. A successful check, build or checksum
alone must not publish them as qualified releases.
