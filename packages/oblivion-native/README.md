# Oblivion native runtime helper

`oblivion-vm` runs the Debian runtime headlessly through Apple's Virtualization.framework on Apple Silicon with macOS 15 or newer. Nested virtualization support is required because Safes and their gateways run inside Debian. The helper checks this before attaching disks. The Oblivion launcher owns configuration, controller authentication and the Safe lifecycle.

Build the signed helper with Xcode installed.

```sh
packages/oblivion-native/build.sh
packages/oblivion-native/.build/release/oblivion-vm capabilities
```

`capabilities` prints a JSON object with `version`, `backend`, `virtualization`, `nested` and `supported`. The build script applies the virtualization entitlement with an ad hoc development signature. Release distribution needs the project's signed and notarized artifacts.

Run the helper with a configuration produced by the launcher.

```sh
oblivion-vm run --config /absolute/path/to/runtime.json
```

```json
{
  "version": 1,
  "backend": "apple-vz",
  "runtimeId": "00112233445566778899aabbccddeeff",
  "kernel": "/absolute/path/to/vmlinuz",
  "initrd": "/absolute/path/to/initrd.img",
  "commandLine": "boot=live components console=hvc0 quiet oblivion.runtime=1 oblivion.runtime-backend=apple-vz oblivion.runtime-id=00112233445566778899aabbccddeeff",
  "disks": [
    { "path": "/absolute/path/to/oblivion-arm64.iso", "readOnly": true },
    { "path": "/absolute/path/to/persistence.raw", "readOnly": false }
  ],
  "cpuCount": 4,
  "memoryMiB": 4096,
  "controlSocket": "/tmp/oblivion-501/runtime.sock",
  "controlPort": 4050,
  "network": true,
  "serialStdio": false
}
```

The launcher creates the control socket's parent directory with mode `0700`, owned by the current user. Its absolute socket path must fit within 103 UTF-8 bytes. The helper binds mode `0600`, checks each connecting process's UID, holds an exclusive lock and forwards connections through a Virtio socket device to the configured guest port. The Debian runtime installs [`control-relay.py`](../oblivion-host/host/control-relay.py) and enables [`oblivion-control-relay.service`](../oblivion-host/host/oblivion-control-relay.service) for this port. The relay accepts only the physical VZ host CID 2 and runs with the controller-authorized UID 1000. It requires the `vmw_vsock_virtio_transport` guest driver. A reported `runtime_started` event means the virtual machine started, while controller readiness must be checked by the caller.

The disk array defines guest device order. Only RAW images, including the hybrid ISO, are accepted by Virtualization.framework. Disk attachments use explicit cached I/O with full synchronization. Uncached/automatic VZ disk access has caused Linux memory corruption; Apple ships the cached workaround in [container PR 1041](https://github.com/apple/container/pull/1041). The Debian controller encrypts persistent Safe contents with LUKS before they reach that backing image. Host caching does not replace encryption or remove the trust placed in the desktop OS. Optional NAT gives the Debian runtime an uplink, and each Safe's gateway continues to enforce its own transport policy. Disable NAT for offline runtime tests.

Serial output is discarded by default after scanning for fatal kernel panic/Oops and memory-corruption markers. A detected failure closes admission and stops the runtime; an Oops is not treated as a healthy kernel. Set `serialStdio` for explicit development console access, which binds the boot console to inherited stdin/stdout. Stderr contains identifier-only JSON events. The helper never includes guest output, paths or request contents in these events. Core dumps are disabled.

Before stopping the runtime, the launcher closes clients and asks the controller to lock every Safe. SIGINT, SIGTERM and SIGHUP request a guest shutdown. A 45-second shutdown timeout forces a stop with a nonzero exit status. Guest shutdown removes the socket and releases the process lock. A stale socket after process death requires explicit launcher recovery under the lock. Memory snapshots and suspend/resume are not provided. There is no desktop window, shared filesystem, shared clipboard or host-directory mount configured by this helper.

The native VM, nested virtualization flag and private stream bridge are implemented here. [`remote_control.rs`](../oblivion-host/src/remote_control.rs) provides the launcher client for the relay. Each request sends a u32 big-endian JSON header length, a local controller header with `version` set to `1`, and exactly `secret_len` secret bytes. Each response sends a u32 big-endian length and the controller JSON response. A successful `agent-attach` response switches to the raw agent-channel protocol. The relay holds the local controller connection as the attachment lease until disconnect. stdin EOF is an explicit agent-channel frame, while closing the transport releases the lease. Other descriptor operations (`console` and `terminal`) are rejected by this relay.

Packaging the native Debian image, relaying PTYs, importing files and managing the public `oblivion` command belong to the surrounding stack.
