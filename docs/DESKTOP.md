# Native desktop development bundles

These are development-only bundles for Apple Silicon macOS (`darwin-arm64`,
Apple Virtualization.framework) and x86_64 Linux (`linux-x86_64`, QEMU/KVM).
They package the native launcher, VM helper, terminal manager, and a separately
built matching Oblivion controller ISO. They are not release artifacts and do
not establish support on real hardware.

## Build

Build on the matching host platform. Install the Bun version pinned in root
`package.json`, Rust and its cached locked dependencies, and the native compiler
tools. macOS also needs the Swift toolchain and `codesign`; Linux needs
`bsdtar` from libarchive for build-time ISO extraction. The native build uses
offline Cargo and never builds an ISO or downloads a runtime.

First obtain a development ISO and all its evidence from the current source
tree using the [image build workflow](DEVELOPMENT.md#build-a-development-image).
The ISO architecture must be `arm64` for macOS or `amd64` for Linux. An older
ISO is refused even when its checksums are internally consistent.

```sh
OBLIVION_DESKTOP_VERSION=1.0.0~dev20261104 \
OBLIVION_DESKTOP_RUNTIME=artifacts/oblivion-stack-arm64 \
sh script/oblivion/build-native.sh
```

On Linux use `artifacts/oblivion-stack-amd64`. The version must start with a
digit, contain `~dev`, and be at most 64 characters using ASCII letters,
digits, `.`, `+`, `:`, `~` or `-`. Output defaults to
`artifacts/oblivion-desktop-PLATFORM/VERSION`; `OBLIVION_DESKTOP_OUTPUT` can
select a new directory. Existing output is never overwritten. The build calls
the existing Swift helper build on macOS, the Rust helper build on Linux, the
Rust `oblivion` target, and the manager's native Bun target.

Before compiling the launcher, the builder requires exactly the expected ISO
and fixed evidence filenames in `SHA256SUMS`, verifies every entry, and compares
the exact `host-sources.sha256` bytes against a freshly generated source inventory. It
extracts the kernel and initrd directly from that verified ISO's
`live/vmlinuz` and `live/initrd.img`. End-user installation does not extract an
ISO and does not require Python or bsdtar.

The inventory is shared with the Docker compiler through
`script/oblivion/native-bundle/host-sources.py`. It covers host Rust code, tests,
examples, host/guest services and scripts, the transfer/share/transport/Tor
libraries, gateway and OnionShare integration, clipboard sources, Python
history code, the generated tools server, manager/theme/TUI source, display
configuration, root Bun locks and notices, and the runtime image's installer,
lock, packaging and boot inputs. The helper's `PACKAGE_INPUTS` and
`SCRIPT_INPUTS` are the complete source list. Output paths are normalized to
the compiler layout, sorted, and hashed identically on macOS and Linux.
Caches and native host helper sources are excluded; compiled native helpers
are independently hashed in the bundle. Generate the current inventory with:

```sh
python3 -B script/oblivion/native-bundle/host-sources.py \
  packages/oblivion-host --scripts script/oblivion
```

## Install and update

Use a bundle produced from trusted source. A checksum identifies contents;
it is not a publisher signature.

```sh
sh /path/to/bundle/install.sh
```

The installer runs the bundled CLI's `runtime install-bundle` operation. It
verifies the manifest and complete file inventory, installs into a private
per-user release directory at
`~/.local/share/oblivion-desktop/releases/BUNDLE_ID` (or beneath
`XDG_DATA_HOME` when configured), and deploys the installed candidate before
activating `~/.local/bin/oblivion`. Updates require the existing runtime to be stopped.
The final launcher symlink is replaced atomically. An unrelated file or
symlink already named `~/.local/bin/oblivion` is refused.

The private desktop prefix also contains a strict `installation.json` record
binding it to one canonical runtime directory and runtime identity. Install,
collection and uninstall refuse another runtime using that prefix; setting
`OBLIVION_RUNTIME_DIRECTORY` never transfers ownership of an existing app
installation. `XDG_DATA_HOME` selects a separate prefix, but there is only one
managed `~/.local/bin/oblivion` command per account. A previous unshipped
prototype without the current ownership record is not automatically adopted.

Add `~/.local/bin` to your shell's `PATH` if needed, then run `oblivion` to
start the protected runtime and manager. The existing runtime storage and
Safe lifecycle remain under the native launcher's control. Installation does
not use sudo, install QEMU, change system permissions, change swap or sysctl
settings, or contact a provider.

## Remove old software or uninstall

First close your Safes and stop the protected runtime:

```sh
oblivion runtime stop
oblivion runtime gc
```

`gc` requires the startup and VM lifetime locks to be free. It removes old
release directories only after verifying their current-format manifest,
complete inventory, ownership and checksums. It keeps the active release,
the running command's release, and releases named in a staged update journal.
Private boot copies carry their own strict inventory; only verified obsolete
ISO, kernel and initrd files are removed. Unknown, changed or unlisted files
are retained for inspection. The scan is bounded to 256 entries in each
managed top-level directory.

Successful bundle installation also attempts this stopped-only cleanup. If
another process starts the runtime first, installation remains successful
and tells you to run `runtime gc` later. A durable launcher activation clears
its matching update journal; interrupted activation still requires rerunning
the matching bundle installer. Collection never deletes that journal.

To remove the desktop application:

```sh
oblivion runtime uninstall
```

Uninstall removes the verified managed `~/.local/bin/oblivion` symlink,
installed launcher/helper/manager/assets releases and verified boot files.
It refuses a running runtime, an unfinished update, an unrelated command
at that path, or a changed release referenced by the installed command.
An original downloaded or source-built bundle outside the managed release
directory is retained.

Encrypted Safe data is preserved. So are `runtime.json`, the runtime identity,
Linux guest CID, lock files, the original `storage.raw` directory and a private
`uninstalled.json` receipt. The receipt prevents startup until a development
bundle is installed again. Reinstalling recreates boot assets while reusing
the same storage path and identity; it does not initialize or copy that disk.
There is no data-purge option. Uninstall does not modify Debian's separately
installed direct-controller stack, delete your shell configuration, or change
host networking or system packages. If removal encounters an I/O error,
inspect the retained files before retrying from the original bundle's
`bin/oblivion runtime uninstall` command.

Linux hosts must already provide QEMU/KVM and the access required by the
native backend. Consult the [Linux helper requirements](../packages/oblivion-native-linux/README.md)
and [macOS helper requirements](../packages/oblivion-native/README.md).
macOS helper signing is ad hoc for development. Developer ID signing,
notarization, and Gatekeeper acceptance remain release gates; this build
does not bypass quarantine or Gatekeeper.

## Bundle evidence and acceptance gates

`bundle.json` is a strict version-1 `oblivion-desktop` manifest. It records
the explicit development product version, platform/backend, control protocol,
source identity, manager asset directory, boot assets, and a sorted SHA-256,
byte count and executable flag for every regular file except the manifest
itself. Its `bundle_id` hashes compact, recursively key-sorted JSON with the
`bundle_id` field omitted. Bundles contain at most 1024 files, use ASCII
relative paths of at most 512 characters without dot components, contain no
links or devices, and limit each file to 64 GiB.

Original runtime inventories and checksums live under `evidence/runtime`;
`evidence/runtime-image.json` associates the original ISO filename with
`runtime/controller.iso`. Root framework notices and manager/Termcn,
OpenTUI, Solid and Zod licenses are included. The ISO also carries its
component notices and Debian package documentation. These records support
review; they do not complete a license
audit or establish redistribution rights for third-party clients, firmware,
Python tools, or their dependencies. Review the [project notice](../NOTICE),
client terms, source obligations and complete image inventory before any
distribution. Nothing here grants a release signature or a licensing waiver.

Run the source-only bundler fixtures from the host package:

```sh
cd packages/oblivion-host
python3 -B ../../script/oblivion/native-bundle/test-bundle.py
```

Source fixture checks verify inventory matching, manifest construction and
rejection of invalid inputs. They do not prove that the shipped ISO boots.
Real-image boot, nested Safe isolation,
network/Tor behavior, agent/provider authentication, storage reopening,
cross-UID vsock rejection, shutdown and update recovery still need their
hardware acceptance matrix on both platforms. No fixture or successful local
build should be reported as passing those gates.
