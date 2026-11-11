# Oblivion file copy engine

Bounded offers and streaming copies of explicitly selected regular files and
directories. Receives into a new private transaction, verifies SHA-256, syncs
before publication, and never overwrites an existing transaction. No network,
USB mounting, shell execution, logging or archive extraction in this library.

Manifest validation, payload hashes, paginated directory metadata, copy control
messages and Share content rules are platform independent. Unix and Windows
filesystem endpoints are separate from that shared protocol; they retain pinned
descriptor or handle identities and explicit publication. Windows sources and
receivers use native name, ACL and reparse-point checks. VM startup and runtime
authorization belong to the native backend, not this copy engine. Compiling for
Windows MSVC does not qualify an installed Windows transfer.

The `oblivion-copy` endpoint uses an inherited private descriptor, a monotonic
transport deadline, approval bound to the offered manifest and a verified
receipt. Separate send/receive processes have been exercised through VM
virtio-serial ports with a readonly source and LUKS destination.

`documents` exposes only selected paths under the session's `workspace` or
`imports`. `export` writes a fresh readable directory on POSIX media;
`export-portable` uses the isolated launcher's FAT/exFAT mount permissions.
The relay waits for the writer's separate unmount/flush acknowledgement before
returning export success. No endpoint can grant access to an external device.

The Linux `oblivion-copy-relay` forwards one approved offer through inherited
source/destination ports (FD3/4) and a trusted control connection (FD5). It pins
both peer processes with `SO_PEERPIDFD`, uses one absolute deadline, and stops
on owner death or controller cancellation. It verifies content and receipts;
only metadata reaches the controller. It has no listener or retry loop.

The controller owns authorization, isolated media endpoints, storage placement,
close/lock integration and cleanup. The native CLI also copies explicitly
selected desktop files over private streams without shared folders. Current
1.0 integration and whole-image acceptance have separate gates in the roadmap.
The relay binary requires Linux; Mac tests exercise its library with explicit
lifetime channels, while Linux tests and the VM laboratory exercise real pidfds.

## Native copy outcomes

Native uploads retain one prepared source selection through review. Downloads
retain the source offer and pinned destination descriptor, without authorizing
payload or creating receiver staging before approval. Recursive counts and total
bytes come from that manifest; approval binds its digest. File contents that no
longer match the reviewed manifest abort the copy.

Sources may have unrelated local parents; guest selections can span `workspace`
and `imports`. One input keeps its single-item layout. Multiple inputs use one
named collection, manifest, payload stream and atomic publication. Exact
duplicates and descendants covered by a selected directory are recorded as
covered inputs. Logical leaf aliases use NFC and full Unicode case folding for
collision detection, with deterministic numeric suffixes. Physical source paths
are never Unicode-normalized. Invalid nested names fail preparation instead of
silently changing project contents. Parent descriptors are deduplicated by their
actual filesystem identity, with admission checked before review.

The source offer exposes kinds and logical mappings rather than physical source
paths. The downloader derives the expected plan from its requested guest paths
and refuses changed plans or unselected manifest roots. The manager receives the
complete ordered map in pages of at most four entries; each event remains within
4096 bytes including its newline. A canonical mapping digest binds all pages to
the review. The selection limit is 128 inputs and 64 KiB of UTF-8 source paths;
the encoded request also remains subject to the 64 KiB message cap.

The manager communicates through a bounded, metadata-only NDJSON channel while
remaining active. A single owned copy process handles review, approval, payload
progress and finalizing. Progress counts actual document bytes, excluding wire
framing. The output total is not a completion receipt. Cancel, malformed input
or owner EOF revoke the private data channel, including blocked I/O. A verified
pre-approval cancellation has copied no file contents; interruption after
approval still needs receiver reconciliation because publication may have won
the race. The terminal CLI uses the same prepared engine with review and a
confirmation prompt; `--yes` is its explicit unattended-copy option.

The desktop CLI creates an operation ID before mutating a receiver. Native
import operations keep bounded context and receipts in the Safe's encrypted
staging; exports keep them in `.oblivion-transfers` inside the explicitly chosen
destination. No absolute host source path is saved in that durable context. The manager keeps
only its latest 32 operation references in RAM, clearing them when Oblivion locks.

`files transfers` enumerates the receiver's operation references after the
manager restarts. It scans only the selected Safe inbox or explicitly chosen
export directory, with ordered pages of at most eight references. Foreign or
invalid records are omitted; an unsafe or busy root is an error. The list grants
no recovery capability, and selecting a record still requires fresh status.

`files status`, `files recover` and `files discard` select that exact operation
and Safe. Export inspection additionally requires the original destination.
Current Safe opening and destination directory identity are rechecked. A lost
acknowledgment or cleanup error cannot prove that publication failed, so callers
query the receiver instead of starting a second copy automatically.

Durable target/publication identity consists of a filesystem UUID and inode.
It survives reassignment of a Linux loop or device-mapper number; the live
publication still checks current device identities through pinned descriptors.
Linux uses `FS_IOC_GETFSUUID` (kernel 6.9 or newer); macOS uses the volume UUID
from `fgetattrlist`. A filesystem without this facility is rejected before new
receiver records, with no fallback to a transient device number. UUID identity
is not cryptographic authentication against a cloned volume. Safe authorization,
private staging, pinned handles and manifest verification remain required.
See the [Linux UAPI](https://github.com/torvalds/linux/blob/v6.9/include/uapi/linux/fs.h)
and [Apple attribute interface](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2).

Recovery revalidates the complete private tree against the approved manifest,
including unexpected files, before publishing through pinned directory handles.
It finishes publication only; it does not resume a partially transmitted payload.
A published receipt records the original transfer, while later working-file
edits remain intact. Discard removes only identifiable unpublished private data,
never published output. Missing or untrusted context remains an unknown result.

## Personal Safe backups

Closed-Safe backup and restore reuse the streaming, approval and receipt
protocol. `session.oblivion` is the existing LUKS2 volume, including its chats,
documents and embedded metadata. There is no new encryption format; restoring
it requires the original Safe password. General application settings are excluded.
Native agent profiles and provider
credentials saved inside the Safe ARE part of a personal disk backup; use
Share to exclude known provider credential stores when transferring portable
work to another user. Review selected content for secrets as well.

`send-open-file` and `receive-open-file` operate on parent-selected descriptors.
They cannot choose a path on the host, browse a parent directory or read a
decrypted mapping. The parent fixes the byte ceiling and transport deadline.
The media picker can also select a single pinned backup for restore. Copying
verifies content before the controller authenticates and publishes the restored
Safe with its original identity. Originals are preserved on failure; portable
Share imports allocate new identities instead.

## OnionShare integration

This package also supplies the Linux `oblivion-onion-file` supervisor. It
coordinates fixed systemd units inside the dedicated file VM, seals approved
outgoing snapshots, freezes received intake and starts the same verified copy
endpoints. The separate [OnionShare adapter](../oblivion-onion/README.md) owns
HTTP handling; its Tor gateway publishes only a fixed private backend.

For encrypted backup sharing, the file VM receives exactly one read-only
ciphertext block device. Upstream streaming and Range support serve it without
mounting or decrypting it. Ordinary documents and large ciphertext backups
have separate limits and authority. Large-backup receipt directly over Tor is
not implemented; restore uses removable or prepared virtual media.

## Verification

See [the architecture guide](../../docs/ARCHITECTURE.md) for the integration
boundary.

From this directory:

```sh
cargo test --locked --release
cargo clippy --all-targets -- -D warnings

# Cross-check the shared library and Windows endpoints; this does not run them
cargo check --locked --lib --target x86_64-pc-windows-msvc
cargo test --locked --lib
```

The optional laboratory builder `script/oblivion/Dockerfile.transfer` runs the
package tests in release mode on Debian without network access during execution,
then exports the copy binaries, logs and source checksums. It includes the local
manifest dependencies that Cargo resolves even when their Windows code is not
compiled. The [source-check workflow](../../.github/workflows/oblivion-check.yml)
runs Cargo directly on its platform runners; it does not invoke this Dockerfile.
All test files and names are synthetic.

The 512 MiB descriptor-copy test checks the complete stream, receipt and
replacement-path isolation with a bounded deadline. Run `backup_sender` in
release mode, as the Unix CI jobs do, so debug hashing overhead does not consume
the transfer deadline.
File-VM laboratories additionally exercise HTTP interruption/resume, read-only
device checks, malformed inputs, approval, cancellation and teardown. A sparse
fixture with a LUKS marker is not a valid encrypted archive; real LUKS and
native-chat preservation require separate whole-product acceptance. Public large-file
Tor transfer and current-image/physical-media qualification remain open in
[STATUS.md](../../docs/STATUS.md).

## Share endpoints

`share-send` consumes a locally approved planner manifest on FD4 and the private
channel on FD3. Source aliases are limited to the portable roots and that
request's generated native-history export index. `share-receive` stages the same hash-checked
protocol in a private new Safe inbox. Known credential-store paths are rejected
by one shared positive-root validator.

The guest wrapper controls review and sends its final acknowledgement only
after cleaning the generated catalog stage. The copy library does not start
clients, publish imported Safes or decrypt the outer Share package. Those
responsibilities belong to the guest adapter, controller and
[Share container](../oblivion-share/README.md).
