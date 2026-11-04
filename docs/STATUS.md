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
public status and portable Share data. Automatic delivery and independent raw
backup of that creation journal remain unfinished.

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

Remaining release gates include real login, chat persistence after cold restart,
interactive cross-agent resume and author admission, close during active jobs,
family password rotation and independent restore, concurrent Tor/SOCKS5 failures,
Share between two installed candidates, physical media, resource measurements, desktop
packaging and signed release provenance. Local inference is deferred until after
1.0. No independent security audit has been completed.

CI builds current-source images as drafts. A successful check, build or checksum
alone must not publish them as qualified releases.
