# Linux native runtime helper

This package implements `oblivion-vm` with QEMU/KVM for **x86_64 Linux**. It starts the Debian runtime headlessly and bridges the desktop's private controller socket to guest vsock port 4050. The surrounding Oblivion launcher owns installation, passwords and Safe lifecycle. ARM64 Linux, including DGX Spark, is explicitly unsupported by this first backend.

The code compiles for Linux and its Unix protocol fixtures run on the development Mac. A real Linux KVM boot, nested Safe, Tor, storage reopen and shutdown still need qualification. The host launcher now selects this backend on x86_64 Linux desktop installations. Real Linux qualification remains a release gate; compiling and protocol fixtures do not establish full platform support.

Build on x86_64 Linux with Rust and the distribution's QEMU packages installed:

```sh
cargo build --release --manifest-path packages/oblivion-native-linux/Cargo.toml
packages/oblivion-native-linux/target/release/oblivion-vm capabilities
# Pair the helper with the current CLI, manager and verified runtime evidence
# using the development desktop bundle builder below.
```

The [development desktop bundle](../../docs/DESKTOP.md) pairs this helper with
the CLI, manager and matching current-source ISO evidence. Its installer runs
`oblivion runtime install-bundle BUNDLE`; arbitrary ISO installation is refused.
Kernel/initrd extraction uses `bsdtar` at source-build time, so end-user
installation does not require it. Hardware and tool preflight precede persistent
runtime data allocation. Private state lives in `$XDG_DATA_HOME/oblivion` or
`$HOME/.local/share/oblivion`, and an owned `0700` socket directory below
`$XDG_RUNTIME_DIR` or `/tmp`. The data file is a dedicated, identity-marked sparse
16 GiB file; its size is capacity rather than memory consumption. A stopped-only
`runtime update BUNDLE` preserves it, the runtime identity and guest CID.
`runtime stop` never starts a stopped VM. After a crash, `runtime recover`
removes only owned disconnected control/QMP/auth sockets while holding startup
and lifetime locks; it refuses live listeners and arbitrary files.

Debian/Live installations select the local controller using root-owned `/etc/oblivion/installation.json` (`0644`) with exactly `{ "version": 1, "mode": "direct-controller" }`. A missing marker selects the desktop backend; an invalid marker errors. Runtime failures never fall back to a local controller. The launcher sets `OBLIVION_RUNTIME_MODE=desktop|direct` before starting the manager, so its exit action is explicit. Existing prototype configurations are not migrated.

The executable uses `/usr/bin/qemu-system-x86_64`, requiring a root-owned executable that is not writable by other users. Normal desktop execution should use the user's existing KVM and vhost-vsock access. Running as root also works with root-owned assets, sockets and RAW files. The helper does not install packages, load kernel modules, alter sysctls or change host networking.

`capabilities` reports `version`, `backend`, `architecture`, `virtualization`, `nested`, `vsock`, `supported` and a static failure `reason`. Preflight opens `/dev/kvm`, checks API 12, creates and closes a VM descriptor, checks KVM's supported VMX/SVM CPUID flags and the enabled nested module parameter. It also requires access to `/dev/vhost-vsock` and an AF_VSOCK socket. It never substitutes TCG when KVM or nesting is unavailable. These probes establish access and advertised features; they do not replace a real nested guest acceptance test. [KVM API](https://docs.kernel.org/virt/kvm/api.html), [nested KVM](https://docs.kernel.org/virt/kvm/x86/running-nested-guests.html).

The backend receives a private `vm.json` projection with v1 fields, an explicit
backend and Linux `guestCID`. The launcher's separate `runtime.json` additionally
requires its strict current bundle/hash binding; the backend never chooses or
upgrades that binding:

```json
{
  "version": 1,
  "backend": "qemu-kvm",
  "runtimeId": "00112233445566778899aabbccddeeff",
  "kernel": "/private/oblivion/kernel",
  "initrd": "/private/oblivion/initrd",
  "commandLine": "boot=live components console=hvc0 quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend=qemu-kvm oblivion.runtime-id=00112233445566778899aabbccddeeff",
  "disks": [
    { "path": "/private/oblivion/oblivion-amd64.iso", "readOnly": true },
    { "path": "/private/oblivion/storage.raw", "readOnly": false }
  ],
  "cpuCount": 4,
  "memoryMiB": 6144,
  "controlSocket": "/run/user/1000/oblivion/runtime.sock",
  "controlPort": 4050,
  "guestCID": 45032,
  "network": true,
  "serialStdio": false
}
```

The installer must allocate an unused random CID from the permitted guest range, rather than copy the example CID between runtimes. QEMU's vhost-vsock registration rejects a collision; the helper does not reconnect to a different VM as a fallback. `network` enables only QEMU's user-mode outer NAT; there is no TAP setup, port forwarding, host filesystem export, desktop or clipboard device. The existing per-Safe gateway remains responsible for Tor/SOCKS5 and direct access policy.

Linux AF_VSOCK host CID 2 identifies the physical host, not a Unix user. A different host user could otherwise bypass the private Unix endpoint and connect directly to the guest CID. Every boot therefore generates a random 32-byte control token in helper RAM. A private virtio-serial provisioning port waits for the guest's READY message before sending it; bytes written before guest-open could otherwise be discarded. The guest writes the token only to its protected `/run` directory and acknowledges completion. The helper then prefixes each vsock connection with the token and requires an authentication ACK before forwarding any v1 control bytes. The relay compares the token in constant time before parsing a request and rejects unauthenticated clients without forwarding anything. No token enters a command line, disk configuration or public network. Missing provisioning or an unknown backend never falls back to plain CID trust. The Apple VZ backend uses its separate private VM connection-object capability, rather than Linux's globally reachable host CID.

The matching Debian image must include `runtime-auth.py`, `oblivion-runtime-auth.service` and the authenticated control relay. `runtime_started` is emitted only after provisioning succeeds; controller readiness still needs its normal status probe. A real negative test from another Linux UID over AF_VSOCK remains required on test hardware; current fixtures exercise the actual provisioning and authentication implementations over Unix streams.

Both disks are regular RAW files, attached as virtio block devices in the configured order: readonly hybrid ISO `vda`, dedicated data file `vdb`. Block devices and extra writable disks are rejected. The private data file must be owned by the current UID, have no group/other permission, one link, and a size between 4 GiB and 1 TiB. It is held under an exclusive file lease. A bounded header read accepts only the installer's fresh `OBLIVION-RUNTIME-1` marker with the matching runtime ID and zero padding, or the current runtime ext4 label and UUID. The helper does not format a disk. Debian's runtime preparation verifies the identity again before mounting it.

The outer RAW filesystem is a container for controller-managed LUKS volumes; its ext4 metadata and runtime identity are not encrypted by this helper. Writable block I/O uses direct access, honored flushes and a disabled guest write cache, equivalent to QEMU's `directsync` mode. Discard, write-zeroes and cache reconfiguration are disabled. I/O errors stop the guest and are treated as runtime failure. No cached-I/O fallback is selected if direct I/O is unsupported. Readonly boot assets may use the host cache. Linux's cache choice is independent of the Virtualization.framework issue on macOS. [QEMU cache modes and block devices](https://www.qemu.org/docs/master/system/invocation.html).

The control socket's parent must already be current-UID-owned mode `0700`; the endpoint is mode `0600` and checks every incoming peer UID. Configuration files are likewise private regular files. A process lock prevents a second helper; stale socket files require explicit recovery under that lock. QEMU also holds its block-driver lock. The helper uses opaque argument arrays and JSON blockdev values, not a shell, and clears host environment variables before starting QEMU.

At most 64 connections run concurrently. Each duplex connection has two fixed 64 KiB buffers and applies backpressure. Guest EOF drains its remaining response before closing; a local transport disconnect closes both directions and releases the controller attachment lease. Native stdin EOF remains an agent-channel frame. Streams and frame contents are never logged.

QEMU starts paused until a private UID-checked QMP handshake succeeds. Core dumps and guest core inclusion are disabled, memory merging is off, user QEMU configuration is disabled and QEMU's seccomp sandbox is enabled. There are no memory snapshots or suspend images. Serial output is monitored for kernel panic and memory-corruption markers using a bounded, zeroized tail, then discarded by default. `serialStdio` explicitly enables the development console. Stderr events contain static identifiers only.

The launcher must lock Safes before asking the helper to stop. SIGINT, SIGTERM and SIGHUP stop admission and request QMP powerdown. After 45 seconds the helper kills QEMU and returns failure. Parent death kills QEMU through `PR_SET_PDEATHSIG`; ordinary errors also kill and reap the child. A kernel panic, Oops, paused I/O failure or lost control channel does not leave the runtime accepting new Safe requests.

Standalone development checks:

```sh
cd packages/oblivion-native-linux
cargo test
cargo check --target x86_64-unknown-linux-gnu
```

Fixtures require Python 3 and use real Unix sockets, locks, sparse identity-marked files, binary duplex traffic and QMP messages. They also exercise the actual Python guest provisioning/authentication functions without a VM or user profile. The desktop launcher integration and explicit Live installation profile are implemented. Acceptance on real Linux hardware must still verify boot, nested Safe isolation, Tor, storage reopening, cross-UID vsock rejection and shutdown before Linux support is released.
