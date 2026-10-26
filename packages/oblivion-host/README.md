# Oblivion host controller

Linux-only Rust component for the trusted live system. This is an implementation
prototype with systemd units, not an installed or finished live distribution. It delegates
cryptography to cryptsetup/LUKS2; it does not implement a cryptographic format.
It has no dependency on the OpenCode server, model or tool execution environment.

## Implemented boundary

- A general LUKS2 file contains an administrative profile and independent session
  LUKS2 files. Creation allocates space up front, uses Argon2id and never overwrites
  an existing file. Physical-device initialization is deliberately absent.
- Both levels stage creation in `.pending` files. Only fully formatted and closed
  containers are published, with an atomic no-replace rename and file/directory
  synchronization. Interrupted attempts remain separate from usable sessions.
- The general filesystem is mounted only by the privileged controller, with
  `nodev,nosuid,noexec` and private permissions. The controller formats session
  filesystems but **never mounts them**.
- One fixed session device-mapper name and an exclusive operation lock serialize
  all opens. The lock survives controller death while a trusted child is running.
  Status is reconstructed from kernel mappings and mount state, not saved JSON.
- Close uses ordinary cryptsetup removal and ordinary unmount. Busy handles cause
  failure; there is no deferred removal, lazy unmount or false “locked” state.
- Systemd supervises the non-root manager and root controller. Failed recovery
  latches a root-owned flag in RAM, which blocks creation and opening even across
  service restarts. Only verified closure of both volumes clears it.
- Ephemeral-profile unlock opens both device and filesystem read-only and disables
  ext4 journal replay. Existing session opens and creation are rejected in this
  mode. A RAM-backed ephemeral guest is still to be implemented.
- Password bytes travel through private stdin/socket channels, never argv, env or
  temporary key files. Owned buffers are zeroized; core dumps are disabled. This
  is not a claim that every kernel or library memory copy is erased immediately.
- The storage process requires root, disabled swap and a tmpfs runtime directory.
  The manager is a separate non-root UID, without access to the general filesystem.

`oblivion-storage --config /etc/oblivion/controller.json <operation>` is the
privileged internal interface. Configuration must be a root-owned regular file,
mode `0600`, without hard links; see [example](controller.example.json). Image
parents must be root-owned and not writable by other users. The configured paths
and their ancestors belong to the trusted system, never to an imported document.

| Operation          | Result                                                                                                                                          |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `init-general`     | Creates a new regular general-image file and returns with it locked                                                                             |
| `unlock`           | Opens/mounts the general and prepares profile/session directories                                                                               |
| `unlock-ephemeral` | Opens the existing general read-only, without journal replay                                                                                    |
| `create`           | Creates a session, prints its random opaque ID, leaves it locked                                                                                |
| `open <id>`        | Internal root-only storage primitive; opens only the block device                                                                               |
| `close`            | Internal root-only primitive; closes the mapping or fails if busy                                                                               |
| `enter <id>`       | Requires KVM, opens the vault and starts its confined QEMU service                                                                              |
| `leave`            | Requests guest shutdown, waits for QEMU termination, then closes the mapping                                                                    |
| `force-leave`      | Explicit forced QEMU stop, then closes the mapping; unsaved data may be lost                                                                    |
| `lock`             | Shuts down the guest, closes its mapping, unmounts and closes the general                                                                       |
| `recover`          | Root service operation; latches recovery before the operation lock, attempts ordinary shutdown and clears the latch only after verified closure |
| `status`           | Returns kernel-derived state and opaque IDs, no conversation titles                                                                             |
| `serve`            | Serves the restricted Unix control socket for the configured manager UID                                                                        |

Two additional operations, also available through the restricted manager IPC,
discard only unpublished attempts: `discard-general-pending` requires an absent
general archive and closed mappings; `discard-session-pending <id>` requires a
writable general, no open session and a valid pending ID. Both reject unresolved
recovery, symlinks and hard links. They never select a published archive.

Secrets are binary stdin (1–1024 bytes; creation requires at least 16). A newline
is part of a secret. Do not type real passphrases into shell command lines.
`oblivion-manager` now supplies a hidden password prompt outside the guest.
Its native Mac `--preview` mode never connects to storage or asks for a password.
The included lab uses only fixed, public synthetic passphrases.
The general image belongs on persistent storage (`/persist` in the example),
not the live system's RAM-backed `/var`.
If it is absent, the trusted TUI now supports its initial creation and password
confirmation. Incomplete attempts have a separate view and an explicit second
confirmation before deletion. The storage boundary is summarized in the
[architecture guide](../../docs/ARCHITECTURE.md).

## Local IPC

`/run/oblivion-control.sock` is mode `0600`, owned by `manager_uid` (nonzero).
The daemon additionally checks Linux `SO_PEERCRED` before reading any request.
Only the enumerated storage operations are accepted; paths, executable names,
mount options and shell commands cannot be supplied by a client.

Each connection carries exactly one request: a 4-byte big-endian header length
(1–1024), a JSON header with `operation`, optional `session` and `secret_len`, then
exactly that many secret bytes (maximum 1024). Unknown fields are rejected. The
JSON response contains `ok`, `output` and an optional static error code. Requests
and responses are not written to a log. The socket must never be exposed to a
session VM or forwarded over a network.

`oblivion-control` is a non-root command client for this protocol. It is a building
block for the manager, not a shell privilege escalation facility. The daemon
inherits its own root-owned config path and executes only its own storage binary.
Each storage command reacquires the independent operation lock.

The manager protocol's `open` invokes `enter`; `close` invokes `leave` and
`force-close` invokes `force-leave`. The manager cannot request the mapping-only
root primitives. Configuration without a VM remains usable for isolated storage
tests but rejects a manager session open.

The new `console` IPC operation accepts no secret or session argument and delegates
one connected serial socket using `SCM_RIGHTS`, followed by the ordinary JSON
success response. It never delegates QMP or arbitrary paths. The manager checks
that the controller's peer UID is root. The automated laboratories are described
in the [development guide](../../docs/DEVELOPMENT.md).
`recover` is deliberately absent from the manager IPC vocabulary; it is invoked
by trusted root services. The manager can retry `lock` or explicitly force-close
the session before locking the general. `status` includes `recovery_required`,
general existence/incomplete flags, pending session IDs and available/planned
session bytes. Pending IDs and available space are exposed only with a writable
general; the read-only profile cannot discard attempts.

Service ordering, dedicated accounts, console behavior and Mac reproduction are
part of the host trust boundary described in the
[architecture guide](../../docs/ARCHITECTURE.md). Units must be
integrated into the live image; do not install their fixed UIDs on a normal
multiuser workstation. The privileged controller retains host-visible mounts.

## VM boundary

`vm` configuration selects root-owned public images, memory and CPUs, not an
arbitrary executable or command line. Normal builds require a usable `/dev/kvm`
before unlocking a session. There is no software-emulation fallback. The explicit
`lab-emulation` Cargo feature is for synthetic tests only and is reported in
`status`; never ship that binary as a privacy product.

QEMU runs as UID/GID 1100 in a transient systemd unit, without capabilities and
with a private device tree, filesystem root and network namespace. Its root holds
only executables and libraries. Only the public boot images and active session
block device are bound into it. No host or session directory is shared with the
guest; the guest receives a readonly system disk and its own writable vault disk.
This first prototype has **no network device**. QMP and console use private Unix
sockets in RAM; the first trusted console bridge renders guest cells below a
reserved host header and filters terminal control sequences. The initial
interactive TUI cycle is tested; extended paste and resize remain open gates.

The guest mounts its vault at `/vault`; the conversation runs as UID/GID 1000.
Home, workspace, state and configuration belong to that vault. `/tmp` and `/var`
are tmpfs; the system root is SquashFS. Journald storage, swap, hibernation and
core dumps are disabled. Closing waits for the guest to power off; a timeout
returns an error and leaves the volume interlocked, never reporting a false lock.
Forced close is a separate explicit request. No memory snapshots are made.

## Document import

The optional `import` image configuration enables USB import in the trusted
manager. `Ctrl+^` opens its document menu while keeping the same chat console
and VM; `Ctrl+]` continues to close the session. Neither action is recognized
inside bracketed paste. The chat's existing components are unchanged.

The root controller lists unmounted USB leaf block devices, excluding the
filesystem holding the general image. It creates a readonly device-mapper
mapping for the selected source and starts `oblivion-import-vm` (UID/GID 1102)
without a network interface or shared filesystem. Only that VM mounts and
parses the external filesystem. Initial readers support ext4 without journal
replay, FAT and exFAT. The lab-only binary also accepts a synthetic virtio disk
with the fixed serial `oblivion-import`; production does not accept that fixture.

The user supplies one relative file or directory path, reviews its manifest
and explicitly approves import into the chat. A root-owned worker binds a
fresh operation ID, a maximum of 256 MiB/1024 entries and a five-minute budget
to private virtio ports and both QEMU process lifetimes. The manager receives
metadata and a receipt, never document payloads. Each copy uses a new guest
port, with no reusable receiver connection across operations.

The recipient runs as UID 1001, GID 1000, separately from the chat. It receives
into `/vault/.oblivion-inbox` (0700), verifies all bytes, then publishes one
fresh directory under `/vault/imports/<id>/files`. The chat group can edit the
published files but cannot access the inbox or replace top-level import IDs.
Both directories are on the same session filesystem; a cross-device rename
fails without a fallback. The same paths are RAM-backed in ephemeral sessions.

`oblivion-transfer-host.service` owns the relay and cleanup. Cancel, close,
lock and recovery stop it, reap the import VM, remove the temporary guest port
and remove the readonly mapping before closing the session. Cleanup failure
is an error, not a locked state. A lost final receipt can leave a complete copy
already published; interrupted publication can leave a private reserved ID.
There is no automatic retry, overwrite or claim of transactional rollback.

`U` in the document menu lists the active session's copies. A fresh maintenance
port reaches the dedicated receiver without an import VM, USB device or host
mount. Private receipts and publication markers remain inside the encrypted
session inbox, inaccessible to chat. The receipt describes the original import;
later chat edits are not rehashed or labelled corrupt. Published and uncertain
exposed copies cannot be deleted through recovery. Only private unpublished
attempts offer `D`, followed by a second explicit `D` confirmation. The receiver
rechecks state under the same inbox lock as import before deleting. `B` locks
both vault levels; cancellation never triggers an automatic retry.

Inventory pages contain at most 64 entries, with an inspection ceiling of 4096
IDs per root. Malformed records or an exceeded ceiling fail without deleting
anything. Hard process interruption is tested separately from power loss and
physical-device faults; those release gates remain open.

Export, physical USB removal/I/O fault tests, orphan reconciliation, A→B and
OnionShare remain separate roadmap work.

## Verification and remaining work

See the [development guide](../../docs/DEVELOPMENT.md). Cargo dependencies
are locked; build with `cargo build --locked --release`. Integration tests execute
the compiled Linux binaries with real cryptsetup and real device-mapper mappings
inside a disposable Debian VM, not mocks of encryption or process execution.

Still required: full live-image integration, KVM/hardware validation,
guest TUI refinement, complete boot/shutdown lifecycle, guest filesystem exhaustion,
I/O and power-loss recovery, profile settings/API broker,
full ephemeral guests, USB provisioning, integrity/backup decisions and release
hardening. Failed creation retains its `.pending` file until explicit confirmed
discard; published archives are never silently reused or overwritten.

### Explicit USB export

Configure `export` with a separate `export.squashfs` VM image (see the example
configuration). `E` authorizes the selected USB for writing before it is mounted;
the user then approves the document manifest separately. The writer supports
ext4, FAT and exFAT. The portable filesystems use mount permissions and UTF-8
names; the receiver does not attempt POSIX chmod on them. Names that require
rewriting are rejected and filesystem name collisions fail without overwriting.

A dedicated networkless UID/GID 1103 VM receives only the writable external
mapping. The chat guest supplies selected `workspace` or `imports` files via a
fresh virtio port and never sees that block device. Each ordinary readable copy
uses a new `Oblivion-<id>/files` directory, preserving existing files. These
external copies are outside the session's encryption.

The relay withholds success until the receiver confirms unmount and block-device
flush. The manager additionally waits for writer VM, port and mapping cleanup
before displaying safe removal. Cancellation or loss of the final response may
leave a complete or partial external copy and does not confirm safe removal.
On a writer error, the disposable guest attempts an unmount and powers off so
the relay observes its process exit even if virtio does not signal guest-port
closure. Physical-device removal, I/O and power-loss tests remain release gates.
