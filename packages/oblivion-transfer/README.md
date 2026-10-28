# Oblivion file copy engine

Bounded offers and streaming copies of explicitly selected regular files and
directories. Receives into a new private transaction, verifies SHA-256, syncs
before publication, and never overwrites an existing transaction. No network,
USB mounting, shell execution, logging or archive extraction in this library.

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

The host manager integrates USB import, recovery and export. The controller owns
authorization, isolated source/destination environments, storage placement,
close/lock integration, filesystem-stall recovery and release to the chat.
The relay binary requires Linux; Mac tests exercise its library with explicit
lifetime channels, while Linux tests and the VM laboratory exercise real pidfds.

## Encrypted session portability

Closed-session backup and restore reuse the streaming, approval and receipt
protocol. `session.oblivion` is the existing LUKS2 volume, including its chats,
documents and embedded metadata. There is no new encryption format; restoring
it requires the original session password. Host settings and provider keys
remain in the general vault and are not part of this backup.

`send-open-file` and `receive-open-file` operate on parent-selected descriptors.
They cannot choose a path on the host, browse a parent directory or read a
decrypted mapping. The parent fixes the byte ceiling and transport deadline.
The media picker can also select a single pinned backup for restore. Copying
verifies content before the destination is admitted as a new independent
session; originals are preserved on failure.

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
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

The repository's `script/oblivion/Dockerfile.transfer` runs the same tests in
Debian without network access during test execution. Its CI jobs target ARM64
and x86-64. All test files and names are synthetic.

The 512 MiB descriptor-copy test checks the complete stream, receipt and
replacement-path isolation with a bounded budget for unoptimized CI binaries.
File-VM laboratories additionally exercise HTTP interruption/resume, read-only
device checks, malformed inputs, approval, cancellation and teardown. A sparse
fixture with a LUKS marker is not a valid encrypted archive; real LUKS and
compiled-chat preservation have separate host laboratories. Public large-file
Tor transfer and supported-image/physical-media qualification remain open in
[STATUS.md](../../docs/STATUS.md).
