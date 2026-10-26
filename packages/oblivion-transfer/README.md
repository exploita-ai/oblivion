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
