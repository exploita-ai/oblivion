# Native desktop development bundles

These are development-only bundles for Apple Silicon macOS (`darwin-arm64`,
Apple Virtualization.framework), x86_64 Linux (`linux-x86_64`) and ARM64 Linux
(`linux-arm64`, QEMU/KVM).
They package the native launcher, VM helper, terminal manager, and a separately
built matching Oblivion controller ISO. They are not release artifacts and do
not establish support on real hardware.

The same manifest and assembly tool now also understand `windows-x86_64` with
three native `.exe` files and the pinned OpenTUI DLL. Validation is shared through
`oblivion-bundle`, including Windows path and case-alias checks. This is a build
contract. The Windows command entrypoint, initial managed setup and bundle
verification, Files, backup, Share and stopped-only software maintenance are
connected in source, including an ordinary-user SCM broker backed by protected
per-user installations, receipt-bound owned-resource recovery and exact-identity
Pending setup resume. Initial installation now uses a native UAC helper and
reviewed Hyper-V preparation. Installed/hardware qualification remains unfinished; see
[Windows status](WINDOWS.md). Do not substitute the Unix launcher in a Windows bundle.

Linux ARM64 additionally requires QEMU 10.1 or newer for its outer nested
controller. The helper checks the trusted executable before runtime allocation;
the ARM64 Live installs the appropriate Debian backports package automatically.
The controller's inner QEMU runs EL1 guests and keeps the stable package.

Native Files receiver recovery requires a filesystem UUID obtained from the
opened descriptor. Linux desktop export therefore needs kernel 6.9 or newer and
a filesystem supporting `FS_IOC_GETFSUUID`; macOS uses its volume UUID. An
unsupported destination is refused before copy approval, rather than recording
a device number that may change after restart. Local import sources do not use
this requirement; their receiver is inside the current Debian Safe image.

## Select files from the desktop

Open **Files → Import → Desktop picker** (D). Drag files or folders from the
desktop file manager into the Oblivion window, or use its file chooser. From an
agent terminal, open the trusted Files panel with **F7** first.

The picker returns the selected paths to the desktop manager. Review them,
add them to the selection, and approve the normal copy manifest before any
file contents move into the Safe. Oblivion stores no picker history. Native
desktop and file manager behavior is part of the host's trust boundary.

The window uses AppKit on macOS, Win32 on Windows and GTK 4 on Linux. The
Debian **desktop** package recommends `python3-gi` and `gir1.2-gtk-4.0`
(GTK 4.6 or newer). Linux bundles need those desktop dependencies for the
window. In a terminal without a desktop or on Oblivion Live, use the keyboard
file list or **Enter path** (P). These also work when the desktop window
cannot start.

## Build

Run the manual [native desktop workflow](../.github/workflows/oblivion-desktop.yml)
to produce the Apple Silicon tar and Windows x64 ZIP for one source revision.
The Linux jobs build the matching private controller and the generated MCP
bundle. The native jobs verify that source pairing before compiling the
launcher, helper and manager. Each archive has a SHA-256 sidecar. The
[Debian desktop workflow](../.github/workflows/oblivion-desktop-deb.yml)
builds the Linux packages. All three downloads are development artifacts.

Build on the matching host platform. Install the Bun version pinned in root
`package.json`, Rust and its cached locked dependencies, and the native compiler
tools. macOS also needs the Swift toolchain and `codesign`; Linux needs
`bsdtar` from libarchive for build-time ISO extraction. The native build uses
offline Cargo and never builds an ISO or downloads a runtime.

First build the **private controller ISO** and its evidence from the current
source tree. This is distinct from the outer bootable Live ISO:

```sh
OBLIVION_ARCH=arm64 sh script/oblivion/build-runtime.sh
```

Use `arm64` for Apple Silicon or ARM64 Linux and `amd64` for x86_64 Linux.
An older controller ISO or the outer Live ISO is refused as bundle input even
when its checksums are internally consistent. `build-stack.sh` builds the outer
Live launcher OS with this same controller image embedded.

```sh
OBLIVION_DESKTOP_VERSION=1.0.0~dev20261104 \
OBLIVION_DESKTOP_RUNTIME=artifacts/oblivion-runtime-arm64 \
sh script/oblivion/build-native.sh
```

On x86_64 Linux use `artifacts/oblivion-runtime-amd64`; ARM64 Linux uses
`artifacts/oblivion-runtime-arm64`. The version must start with a
digit, contain `~dev`, and be at most 64 characters using ASCII letters,
digits, `.`, `+`, `:`, `~` or `-`. Output defaults to
`artifacts/oblivion-desktop-PLATFORM/VERSION`; `OBLIVION_DESKTOP_OUTPUT` can
select a new directory. Existing output is never overwritten. The build calls
the existing Swift helper build on macOS, the Rust helper build on Linux, the
Rust `oblivion` target, and the manager's native Bun target.

Windows development builds use native x64 MSVC Developer PowerShell 7.4 or later,
the pinned Rust 1.88.0 toolchain, repository-pinned Bun, Python 3 and cached
dependencies. Run the builder without elevation so generated files belong to
the actual user. It creates its own private work/output tree; it does not change
ACLs on other files, install tools, boot a VM or build an ISO.

```powershell
# Actual PE executables and assets only; no runtime or installable bundle:
pwsh -File script/oblivion/build-native-windows.ps1 -Version '1.0.0~dev20261105'

# Assemble a bundle only with the matching real amd64 controller and evidence:
pwsh -File script/oblivion/build-native-windows.ps1 -Version '1.0.0~dev20261105' -Runtime artifacts/oblivion-runtime-amd64
```

Without `-Runtime`, output is explicitly marked build inputs and contains no
`bundle.json` or install flow. With it, the same Python prepare/assemble tools
verify the runtime checksums and exact current source inventory. Git attributes
keep source text in LF form on every platform; the build refuses source changes
during compilation. Outputs must be new paths and retain their private ACLs.
This is an unsigned development build, not proof of Windows installer support
or bit-identical binaries across different Windows SDK/linker versions.

For an existing CI controller, `-ToolsBundle PATH` with `-Runtime` reuses the
generated `server.mjs` from that controller build. The regular source inventory
still checks the exact bytes. The hosted workflow runs the Windows builder
with a restricted token for the same runner account, so the builder creates
its output under the caller's identity. The installed launcher reports the
bundle's product version through `oblivion --version`.

Before compiling the launcher, the builder requires exactly the expected ISO
and fixed evidence filenames in `SHA256SUMS`, verifies every entry, and compares
the exact `host-sources.sha256` bytes against a freshly generated source inventory. It
extracts the kernel and initrd directly from that verified ISO's
`live/vmlinuz` and `live/initrd.img`. End-user installation does not extract an
ISO or require build tools such as bsdtar.

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

## Install and update on macOS and Linux

Use a bundle produced from trusted source. A checksum identifies contents;
it is not a publisher signature.

For an Apple Silicon Actions artifact, verify the sidecar next to the tar file,
then extract the tar with its executable modes intact.

```sh
shasum -a 256 --check oblivion-VERSION-darwin-arm64.tar.sha256
tar -xf oblivion-VERSION-darwin-arm64.tar
sh oblivion-VERSION-darwin-arm64/install.sh
```

Replace `VERSION` with the version in the downloaded filename.

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

## Debian desktop package

On a compatible Debian host, install the development desktop package with APT,
then run the normal command as your own user.

```sh
sudo apt install ./oblivion-desktop_1.0.0~dev20261105_amd64.deb
oblivion
# Or go straight to an agent in a new Safe.
oblivion run codex
```

APT installs QEMU and the host dependencies and exposes `/usr/bin/oblivion`.
The first launch verifies the root-owned bundle and prepares a private copy for
the current user. When the KVM devices require membership in Debian's `kvm`
group, Oblivion asks for consent and opens a Polkit administrator prompt. After
enrollment, sign out and back in, or reconnect the SSH session, if the current
login still holds the old groups. The VM runs as the ordinary user. Firmware,
nested KVM, missing device nodes and device permissions are reported separately.

The ARM64 package needs a booted kernel with nested EL2 support and QEMU
10.1 or newer. On Debian trixie these require the appropriate backports
packages and host boot configuration. APT resolves dependencies before it
installs Oblivion, so configure that host baseline first.

An APT upgrade installs a new source bundle. A running runtime keeps its
private release until it stops. The next normal launch then activates the new
release using the same runtime identity and encrypted data disk. If an
activation was interrupted, the launcher finishes that exact verified release
before applying a newer package. Use APT for package upgrades. To remove the
private software as well as the package, close the Safes, stop the runtime,
run `oblivion runtime uninstall`, then run `sudo apt remove oblivion-desktop`.
Removing the package alone preserves the user's installed release and data.

From a checkout with the pinned Bun and Docker Buildx, build the development
package for either `amd64` or `arm64`.

```sh
bun install --frozen-lockfile
OBLIVION_ARCH=amd64 OBLIVION_DEB_VERSION=1.0.0~dev20261105 \
  sh script/oblivion/build-desktop-deb.sh
```

The package and checksum are written to `artifacts/oblivion-desktop-deb-<arch>/`.
The manual [Debian desktop workflow](../.github/workflows/oblivion-desktop-deb.yml)
builds both architectures as development artifacts. The package embeds the
verified controller image and build inventory. Installed APT, Polkit and
nested-VM acceptance on target hosts remains open.

## Windows development setup and maintenance

The Windows Actions artifact contains the bundle ZIP and its SHA-256 sidecar.
Extract the ZIP into a new private folder on a local NTFS volume. The ZIP
carries the files and manifest. Windows assigns permissions on extraction.
The following commands use the built-in Windows PowerShell as your regular
user. Set `$archive` to the downloaded ZIP beside its checksum file.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $archive = Get-Item -LiteralPath '.\oblivion-VERSION-windows-x86_64.zip'
    $expected = (Get-Content -LiteralPath "$($archive.FullName).sha256" -Raw).Trim()
    $hash = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -cne "$hash  $($archive.Name)") { throw 'Bundle checksum mismatch.' }

    $folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ("Oblivion-download-" + [Guid]::NewGuid().ToString('N'))
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($identity.User)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    New-Item -ItemType Directory -Path $folder | Out-Null
    Set-Acl -LiteralPath $folder -AclObject $acl
    Expand-Archive -LiteralPath $archive.FullName -DestinationPath $folder
    & (Join-Path $folder 'install.cmd')
}
```

From a produced Windows bundle, run `install.cmd` in a normal terminal. The
bundled CLI verifies and stages the software before requesting UAC for its
one-shot setup helper. That helper authenticates the original caller; entering
another administrator's credentials does not change the intended user. Only
the helper is elevated. No PowerShell 7, Python, Rust or SDK is needed to run it.

If Hyper-V must be enabled, the normal terminal asks for explicit confirmation.
The helper uses the fixed System32 DISM command and never restarts Windows.
When a restart is required, no Oblivion VM, service or data disk is created;
restart Windows and rerun the same installer. The parent reports the installed
launcher after confirming the helper's exit and the original user's broker.
That original parent registers the verified release's native `bin` directory in
its own user PATH. Open a new terminal, then run `oblivion`. No command wrapper
reconstructs agent arguments. Other PATH entries and their value type are
preserved; collision or uncertain ownership produces an explicit incomplete
registration result. Clean Windows startup, UAC with a different administrator,
actual registry execution and Hyper-V preparation remain acceptance gates.

The Windows entrypoint uses the same `runtime update BUNDLE`, `runtime gc` and
`runtime uninstall` grammar. Stop the protected runtime first; maintenance holds
an exclusive observed-Stopped capability and never boots or initializes storage.
The installed CLI accepts an explicitly selected current-format update bundle
and authenticates the new helper against that bundle's source.
Uninstall preserves runtime identity, configuration, the supervision journal and
the exact encrypted data VHDX. Its cleanup report distinguishes removed software,
unknown retained files and binaries still in use; exit code 2 means incomplete
removal, to retry from a verified external bundle. The invoking source remains
pinned through helper exit: uninstall from an installed command preserves its
complete in-use release. Maintenance uses the same native UAC handoff; the original
parent updates or removes only its owned user PATH entry. Reinstall restores
software around the preserved disk without initializing it again.
Ordinary launch uses the per-user SCM broker and leaves the CLI and
manager unelevated. Maintenance stops that broker while holding the same
observed-Stopped guard. Actual Windows lifecycle is still unqualified; see
[Windows maintenance](WINDOWS.md#stopped-only-software-maintenance).

## Remove old software or uninstall on macOS and Linux

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
There is no data-purge option. Uninstall does not delete your shell
configuration or change host networking or system packages. If removal encounters an I/O error,
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


## Debian Live

The Live OS runs the Linux launcher and headless QEMU/KVM helper. It never
starts a second controller directly on the physical OS. First launch selects
encrypted persistence on the boot USB or RAM-only mode **before** starting the
controller VM. An explicit `oblivion ephemeral` or `oblivion run --ephemeral
codex` selects the RAM backing directly; a flag after the agent name remains
an opaque native agent argument.

For persistence, review and confirm the boot USB, available data capacity and
any required GPT backup relocation. Preparation creates only a new dedicated
partition in unallocated trailing space. Existing partitions keep their starts
and sizes; no unrelated disk is offered. The root helper authorizes that one
partition, and the native helper checks its device identity and installation
marker. Only the controller VM mounts it. The outer OS does not mount ext4,
the general LUKS archive or a Safe filesystem.

RAM-only mode uses a sparse file beneath `/run` and does not authorize or
attach the persistent partition. To change the backing mode, close all work,
run `oblivion runtime stop`, wait for shutdown, then run
`oblivion runtime choose-storage`. The next invocation presents the choice
again. Selecting an incompatible mode while a runtime is configured fails
before starting or changing storage.

The Linux ARM64 host needs Linux 6.16 or newer with `KVM_CAP_ARM_EL2` and a
QEMU version that supports nested EL2. The ARM64 **outer Live OS** selects the
official Debian `trixie-backports` kernel and boots with `kvm-arm.mode=nested`
to present virtual EL2 to the controller VM. Linux documents that mode as
experimental and requires ARMv8.4 FEAT_NV2.

The private controller runs EL1 Safe and gateway guests using ordinary
VHE/nVHE. Its default ARM64 kernel is Debian stable (currently the 6.12 LTS
series), including signed `trixie-security` updates. Desktop and Live
continue to use the same controller ISO per architecture. Safe and gateway
guests and the AMD64 hypervisors also keep Debian stable.

`OBLIVION_HOST_KERNEL_VERSION` still accepts an exact backports meta-package
version for development. ARM64 overrides must meet the minimum for each
selected role: 6.12 for the controller and 6.16 for outer Live. Packing
rejects extra boot kernels, missing KVM configuration, and changed boot
images. The Live artifacts record the two roles separately and check that
the embedded controller's kernel and initramfs match both its ISO and the
launcher's detached boot files. The native probe still verifies host
capabilities before data setup. [ARM kernel parameters](https://docs.kernel.org/6.16/admin-guide/kernel-parameters.html),
[Linux 6.16 KVM API](https://docs.kernel.org/6.16/virt/kvm/api.html),
[Debian ARM64 backports kernel](https://packages.debian.org/trixie-backports/kernel/linux-image-arm64).
There is no software-emulation or direct-controller fallback. Live inside
another VM adds a nesting level and needs separate qualification.

The source includes these paths and sparse-file partition tests. The
three-second boot wordmark overlaps controller startup and appears once per
boot. A complete Live build, physical USB preparation and reboots, and the
RAM-mode unchanged-disk acceptance test remain required before distribution.
