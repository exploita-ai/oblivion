# Development

Oblivion is built from the same source for two 64-bit architectures. Physical
boot-media validation is currently performed on amd64 hardware; arm64 is built
for ARM hardware and compatible virtual machines.

## Image architectures

| Image | Also called | Intended hosts |
| --- | --- | --- |
| `amd64` | `x86_64` | 64-bit Intel and AMD PCs |
| `arm64` | `aarch64` | Apple Silicon and other 64-bit ARM systems |

`amd64` is the historical name of the 64-bit x86 instruction set. Intel and AMD
do not need separate images. 32-bit x86 is not supported.

## Prerequisites

- Bun 1.4.4
- Docker with Buildx
- Python 3
- QEMU for local VM tests
- sufficient free space for Debian root filesystems and VM disks

Install the JavaScript workspace and run the canonical checks:

```sh
bun install --frozen-lockfile --os '*' --cpu '*' --libc '*'
bun run check
bun run typecheck:tsc
```

Run tests from the package that owns them, never from the repository root. Read
the relevant instructions under `.opencode/skills` before changing tests.

## Build images

```sh
# Intel/AMD 64-bit image
bun run build:iso

# ARM 64-bit image
OBLIVION_ARCH=arm64 bun run build:iso

# development image with hardware-debug support
bun run build:hardware
```

The resulting images are:

```text
artifacts/oblivion-beta-iso/image/oblivion-development-amd64.iso
artifacts/oblivion-arm-iso/image/oblivion-development-arm64.iso
```

Generated images, VM disks, logs and evidence are written under `artifacts/`
and are ignored by Git. CI produces per-commit evidence as expiring workflow
artifacts; generated evidence must not be committed as permanent documentation.

Development images are not release images. They may contain diagnostics,
temporary access keys or services that must be absent from a public build.

### Session tools

`script/oblivion/session-packages.txt` declares the session's Debian tools:
shell/process utilities, Git/ripgrep, curl, jq/SQLite, file/tree/less/nano,
ZIP/XZ/bzip2 and Poppler PDF tools. Python includes `venv` and its pip bootstrap.
Node LTS and its bundled npm come from the upstream archives pinned by version
and architecture-specific SHA-256 in `script/oblivion/session-node.json`.
The build verifies the hash before extraction and keeps upstream licenses.
Updating that lock is an explicit source change, never a runtime auto-update.

Run `oblivion-tools` inside a session for its bundled capabilities, or add
`--json` for paths, Debian versions, Node provenance and npm dependency versions.
The same generated inventory supplies the agent's configured instructions and
the static image audit. Tool additions affect the session image, not the host,
gateway or transfer images. Compilers, language-specific toolchains, browsers
and office suites are outside this base set.

Both terminal and agent disable shell/REPL/pager/SQLite histories and automatic
npm audit/update checks; npm disk logs are disabled. Package caches use RAM;
project dependencies and the npm user prefix stay inside the session volume.
Python dependencies belong in a project virtualenv. HTTP(S) tools use the
opening-scoped proxy and gateway Rules; Node enables native environment-proxy
support. Other networking libraries still need their own proxy support.

The `session-tools-test` Docker target exercises actual commands and local TLS/
proxy fixtures with no external network, an unprivileged user and a read-only
root. `session-tools-chat-test` additionally checks the real compiled client's
launcher/configuration. CI runs this integration on ARM64 and amd64. For booted
offline acceptance, build `terminal-artifacts` with
`--build-arg TERMINAL_GUEST=opencode-guest`, then run
`script/oblivion/run-terminal-lab.py --tools --exports` with its image/output
arguments. These disposable laboratories do not modify a provisioned VM.

### OnionShare component

`packages/oblivion-onion` contains a separate GPL-3.0-or-later adapter for the
pinned upstream Web service. Build the `onionshare-test` Docker target and run
the read-only/nonroot/networkless command in its README. The runtime bundle
retains dependency versions, download hashes and licenses; no resolver or
installer runs when starting a transfer. The development-only
`onionshare-lock-artifacts` target regenerates the Python lock for review.
Supplemental license source hashes are maintained separately when upstream
wheels omit the license text. Never replace this with an unpinned pip install.

The `onion-tor-test` target adds actual Tor ownership/service tests with networking
disabled. Its root fixture needs only SETUID/SETGID/CHOWN/DAC_OVERRIDE/KILL to
start and reap the daemon as UID 1200; see the CI command. These are fixture
capabilities, not the HTTP worker's privileges. `onion-control-artifacts`
exports a separate gateway and diagnostic image for `run-onion-lab.py` with
Mac ARM64 HVF or explicit Linux TCG. The production unit remains silent; the
diagnostic image alone adds a root console fixture. It does not replace the
gateway's production controller or sandbox.

`Dockerfile.transfer` now also exports `oblivion-onion-file`. Build that bundle
into `artifacts/ci/transfer` before building `onion-file-artifacts` from
`Dockerfile.vm-lab`, then run `run-onion-file-lab.py --image <directory>
--output <new-directory>` with HVF on Mac ARM64 or explicit `--accelerator tcg`
on Linux. This uses the actual file-controller, systemd socket activation,
read-only share bind, Unix/TCP relay and verified copy endpoints on a private
two-VM wire. It checks ten share/receive/review and failure lifecycles, including raw
backup streaming and refusal of writable/invalid block fixtures.
Production and diagnostic peers are separate images; no writable user disk or
external network is attached. The ARM64 job is registered in CI.

Component tests alone do not establish public reachability. The disposable
ARM64 host has now additionally passed a real public receive/review/import/
reopen round trip and selected-file sharing with independent Tor clients.
Absent/wrong recipient authorization was refused, the approved download
matched, revocation stopped access and ephemeral use left the general archive
byte-identical. These are HVF/TCG laboratory results, not supported-candidate
or physical-media qualification. The deployed ISO remains unchanged; new
image builds include the transfer profiles. Measure candidate RAM/image costs
and qualify the normal KVM path before shipping.

The host's selective state store now takes an explicit `Model` or `Transfer`
purpose. The model keeps its legacy `profile/tor-state` filename; transfers
use `profile/onion-tor-state` with no fallback. Writes retain private modes,
atomic rename and directory sync, and the storage controller still enforces
the general-vault writable/ephemeral policy before saving. No transfer state
read or write changes `transport.json`, proxy credentials or provider keys.
The source transfer owner now loads/checkpoints this store every four seconds
and during revocation. The public laboratory also verifies separate transfer
guards and an unchanged archive during ephemeral use.

`onion_uplink::arguments` describes QEMU's existing user/stream/hub network
backend as a machine-less process, with no CPUs, kernel, writable disk or guest
filesystem. Its Linux launcher now uses the existing uplink identity with a
private PID namespace; Tor/file VMs use their own UIDs and private PID/network
namespaces. No new host firewall exception is required. The root owner launches
all three actors when optional `onion` configuration is present. This is source
integration, not a deployed or supported-profile-qualified candidate.
From `packages/oblivion-host`, run:

```sh
cargo +1.85.0 test --locked --test tor_profile --test onion_uplink --test onion_vm --test onion --test onion_task --test onion_copy -- --include-ignored
```

Install the architecture's QEMU executable on PATH for the actual network test.
It uses the production argument builder, verifies no CPU/block devices through
QMP and exchanges a fixed DHCP packet only with the emulated local router. It
does not contact a public destination or establish Tor isolation/readiness.
Compiler-only suites leave that explicit integration test ignored; a separate
ARM64/amd64 CI job installs QEMU and runs it. Native Mac results do not prove
the Linux service sandbox or end-to-end transfer ownership.

The private `onion` operation is not an OpenCode public API. It accepts
`prepare` (`ttl_seconds` 1–3,600), `status`, `receive` (`client_auth`, canonical
52-character base32 X25519 public key), `access`, `freeze`, `import`, `stage`, `share` and `cancel`.
`prepare-backup` separately authorizes a closed-session ciphertext share with
`id`, `password` and `ttl_seconds`; no filesystem path is accepted.
Prepare returns before Tor bootstrap completes and publishes no URL. After
verified readiness, receive acknowledges background file startup; polling
advances through `starting` and `receiving`. Explicit access returns only the
private URL; the recipient keeps the corresponding private authorization key.
The manager now generates that pair in RAM, hides the private key by default
and sends only the public key to the controller. Reveal is explicit; disposal
clears the owned raw byte buffer. This is not a promise that JavaScript strings
or terminal render copies have all been overwritten. The receive view then
hands off the sealed source to the existing Documents approval/copy UI. Freeze revokes Tor before file review and reaps both network actors;
`review` waits for the sealed intake acknowledgement. `import` starts the
existing source and session receiver on private ports, advances through
`preparing-import` to `copying`, and exposes a manager-owned 0600 socket at
`/run/oblivion-onion-host/copy.sock`. Its parent allows traversal (0711); the
root control socket remains root-owned 0600. Only metadata reaches the UI.
`imported` and its verified receipt follow approved publication and port removal.
Cancellation joins file/copy workers before final port teardown. Do not supply provider
keys or arbitrary targets/paths; all commands reject unknown fields. Job files
contain only operation/session IDs, the mode flag and deadline. New Live builds
include the optional `onion` VM configuration; previously built candidates are
not modified. Session-file sharing first requires the existing manifest and
copy approval; the owner retains the actual approved path order and the file
VM verifies/seals that snapshot before publication.

The `--onion-host` override in `run-vm-lab.py` loads the current fixture,
controller bundle and production host firewall into a disposable host's RAM.
It verifies the immutable gateway/file images, opens synthetic LUKS volumes
and sends transfer commands through the actual manager IPC as UID 1000.
The nine offline lifecycle checks include private namespaces, no publication
before verified readiness, cancellation, normal close, owner/session SIGKILL,
expiry and general lock. They check that every auxiliary PID exits before
confirmed storage closure, model credential/transport files stay unchanged
and synthetic password/key/proxy markers are absent from the persistent disk.
The immutable QEMU root must include the three transfer runtime mount targets.
Run from the repository root with separately built artifact directories:

```sh
python3 -B script/oblivion/run-vm-lab.py --onion-host \
  --image <tui-host-image> --services-bundle <host-artifacts> \
  --gateway-image <onion-control-artifacts> \
  --onion-file-image <onion-file-artifacts> --output <new-directory>
```

Mac ARM64 defaults to HVF for the outer host; nested guests use explicit TCG.
The x86 CI job selects `--architecture x86_64 --accelerator kvm` and requires
KVM with no fallback. The laboratory has no uplink unless `--tor-online` is
explicitly supplied. That option adds the public bootstrap check and external
packet capture, including the pre-enable barrier; it does not perform a
sender/recipient transfer or establish production-profile support.
Both offline and public-bootstrap modes have passed locally on the disposable
ARM64 HVF/TCG host. The public run confirms zero traffic before enable and
TCP-only IPv4 afterward. For an explicit public sender/recipient test, build
`onion-recipient-test` as a Docker image and add:

```sh
--tor-online --onion-recipient <recipient-image> --onion-share
```

The external caller runs two independent Tor daemons with private RAM state,
no capabilities and no Docker logging. A private virtio metadata bridge keeps
access URLs and authorization secrets out of serial logs and evidence. It
checks absent/wrong/valid authorization, upload, selected-only approved import,
close/reopen, selected-file download, revocation and ephemeral byte identity.
`--onion-backup` additionally creates a 512 MiB closed LUKS2 volume and checks
its authenticated first/last MiB Range downloads and streams the entire
container into a recipient-side hash, without storing that container in the
caller's RAM filesystem. This opt-in bulk test has a 65-minute laboratory
budget; production transfer deadlines remain one hour. Keep
bootstrap failures and numeric progress in evidence; a later pass does not
establish reliability on a different network or profile.

## Release branches

All normal development targets `dev`. Promote a fully reviewed commit to
`main` only when it is a release candidate. GitHub Actions builds both image
architectures for each `main` push without publishing them.

After the `Oblivion checks` run for that exact `main` commit is green, a `v*`
tag on the commit rebuilds both architectures and uploads them directly to a
draft GitHub Release. The Release is made public as a pre-release only after
both builds and checksum verification succeed. A tag outside `main` is rejected.

Do not manually attach locally built ISOs to a Release. Until signed provenance
is implemented, published SHA-256 files provide integrity checking rather than
publisher authentication.

## Run from a virtual machine

Oblivion persistence uses free space after the hybrid ISO on its writable boot
medium. Mounting the ISO as a read-only virtual DVD is therefore not equivalent
to booting the complete writable image. Prepare a new sparse raw disk instead:

```sh
bun run vm:disk -- \
  --image artifacts/oblivion-beta-iso/image/oblivion-development-amd64.iso \
  --output artifacts/oblivion-amd64.raw \
  --size-gib 8
```

The helper accepts only a new output file and never opens a physical device.
Attach the resulting raw image as the VM's writable boot disk. The current VM
profile exposes it as a **USB mass-storage device** so the same persistence path
used on physical hardware is exercised. Keep it private: after setup it
contains the encrypted general vault and sessions.

### Nested virtualization is required

The outer Oblivion host starts separate gateway, session and transfer VMs. The
production controller therefore requires a usable `/dev/kvm` and deliberately
has no software-emulation fallback. An outer hypervisor must expose nested
hardware virtualization to Oblivion; booting the manager alone is not a
successful compatibility result.

| Host and hypervisor | Image | Current expectation |
| --- | --- | --- |
| Linux x86_64 with QEMU/KVM and nested KVM | `amd64` | Primary VM target |
| Linux arm64 with QEMU/KVM and nested KVM | `arm64` | Supported design; hardware validation required |
| Windows x86_64 with VirtualBox nested VT-x/AMD-V | `amd64` | Supported design; physical validation required |
| Intel Mac with a hypervisor exposing nested VT-x | `amd64` | Unverified |
| Apple Silicon M3 or newer, macOS 15+, UTM with Apple Virtualization | `arm64` | Native Mac VM target; nested KVM validated on M4 Pro |
| Apple Silicon M1/M2 | `arm64` | Manager may boot, but Apple does not expose nested virtualization |
| Apple Silicon with VirtualBox, VMware, Parallels or UTM's QEMU backend | `arm64` | Full sessions are currently unsupported |
| Windows on ARM with VirtualBox | `arm64` | Manager may boot, but VirtualBox does not expose nested virtualization to ARM guests |

[Oracle documents](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/AdvancedTopics.html#nested-virt)
the generic nested-virtualization switch, while its
[ARM host limitations](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/installation.html#host-arm)
exclude that setting for ARM guests. A hypervisor without this capability cannot
run the current production image completely.

### Apple Silicon with UTM

[UTM](https://github.com/utmapp/UTM) is the supported direction for running
Oblivion natively on Apple Silicon without a project-specific Mac application.
Use a Mac with an M3 or newer chip and macOS 15 or newer. UTM 4.6 and later
enable nested virtualization by default for Linux guests using the **Apple
Virtualization** backend. Do not select UTM's QEMU backend.

Download the ARM64 ISO from the release page and clone this repository for its
disk-preparation script. Python 3 is sufficient; Bun and Docker are needed only
when building Oblivion itself. Prepare a new writable virtual boot disk:

```sh
python3 script/oblivion/prepare-vm-disk.py \
  --image /path/to/oblivion-arm64.iso \
  --output /path/to/oblivion-arm64.raw \
  --size-gib 16
```

In UTM:

1. Create a new **Virtualize → Linux** VM using Apple Virtualization.
2. Assign 8 GiB RAM and four CPU cores for sessions and the optional transfer
   VMs. The earlier chat-only candidate was tested with 4 GiB and two cores;
   that result does not qualify the expanded transfer profile.
3. Use UEFI boot. Add a **removable** drive; after saving the VM, select
   `oblivion-arm64.raw` with its drive/image selector. Keep it writable.
   This is a virtual USB medium; no physical USB stick is required.
4. Use that removable image as the boot medium. An ordinary internal virtio
   disk can boot the welcome screen but the current persistence implementation
   refuses it with `usb_boot_device_required`. Avoid importing the raw image as
   an internal disk. A blank internal disk created by the wizard is unnecessary.
5. Use shared/NAT networking. Enable **Clipboard sharing** for host/guest text
   copy/paste. Keep shared directories, Rosetta and unnecessary device
   passthrough disabled. Clipboard sharing is optional and may be disabled for
   an isolated evaluation; it does not affect Documents import/export.
6. In **Display**, start with **1440 × 900** and disable **Dynamic Resolution**.
   This keeps the terminal readable when the VM window fills a Retina display;
   dynamic resolution can otherwise create a very large terminal grid with tiny
   text. Adjust the display size with the VM stopped if needed.
7. Start Oblivion and open a session. A `kvm_required` error means nested
   virtualization was not exposed and the configuration is unsupported.

UTM's [4.6 release notes](https://github.com/utmapp/UTM/discussions/6715)
document nested Linux virtualization on macOS 15 with M3 or newer, and its
[Apple-backend drive documentation](https://docs.getutm.app/settings-apple/drive/)
states that removable raw images are supported. Apple independently documents
[M3 as the minimum chip](https://developer.apple.com/documentation/virtualization/vzgenericplatformconfiguration/isnestedvirtualizationsupported)
for nested virtualization.

The current ARM candidate was exercised with UTM 5.0.8 on an Apple M4 Pro and
macOS 15.7.3. The test verified an `aarch64` live boot, KVM API version 12, an
unprivileged nested `aarch64` guest boot, RAM-backed runtime filesystems, no
swap, LUKS2 creation and wrong-password rejection, and a production Documents
VM with KVM enabled and no network device. This validates that configuration;
it is not a claim about every Apple Silicon model or UTM release.

### QEMU/KVM on Linux

On an x86_64 Linux host with nested KVM enabled:

```sh
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -m 4G -smp 2 \
  -device qemu-xhci,id=xhci \
  -drive file=artifacts/oblivion-amd64.raw,format=raw,if=none,id=oblivion,cache=none \
  -device usb-storage,bus=xhci.0,drive=oblivion,bootindex=1 \
  -nic user,model=virtio-net-pci
```

The raw image is attached through QEMU's documented
[USB mass-storage device](https://www.qemu.org/docs/master/system/devices/usb.html)
rather than as a SATA disk.

For arm64 use `qemu-system-aarch64`, the QEMU `virt` machine, KVM, an AArch64
UEFI firmware supplied by the host distribution, and the arm64 raw image. The
guest architecture must match the host architecture for hardware acceleration.

### VirtualBox on x86_64

Use a current VirtualBox 7.2 release on an Intel/AMD Windows or Linux host.
Python 3 and VirtualBox are sufficient to prepare downloaded images. From a
checkout of this repository, prepare a new `amd64` boot disk, then convert it
to a dynamically allocated VDI:

```sh
python3 script/oblivion/prepare-vm-disk.py \
  --image /path/to/oblivion-amd64.iso \
  --output /path/to/oblivion-amd64.raw --size-gib 16
VBoxManage convertfromraw /path/to/oblivion-amd64.raw \
  /path/to/oblivion-amd64.vdi --format VDI
```

On Windows replace `python3` with `py -3`, use Windows file paths, and run
`VBoxManage.exe` from the VirtualBox installation directory or add it to PATH.

Create a Linux/Debian 64-bit VM with 8 GiB RAM and four virtual CPUs.
Enable EFI and **Nested VT-x/AMD-V**, add a USB storage controller, and attach
the VDI to that controller as a writable hard disk. VirtualBox can boot virtual
USB storage only through EFI. Use NAT networking and a VMSVGA display. No
physical USB device or outer-host disk needs to be passed through: the VDI is
the VM's writable boot medium, including free space for encrypted persistence.
Keep shared folders and drag-and-drop disabled.

For text copy/paste select **Devices → Shared Clipboard → Bidirectional**.
Leave **Clipboard File Transfers** disabled; documents use Oblivion's explicit
import/export flow. The amd64 build includes the pinned upstream `VBoxClient`
clipboard component and uses Debian's guest kernel driver. It does not install
`VBoxService`, a guest-control service, shared-folder mounts or a runtime
Guest Additions installer. The corresponding CLI settings are:

```sh
VBoxManage modifyvm "Oblivion" --nested-hw-virt on --firmware efi
VBoxManage modifyvm "Oblivion" --clipboard-mode bidirectional \
  --clipboard-file-transfers disabled --drag-and-drop disabled
```

The [Oracle clipboard documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/guestadditions.html#guestadd-clipboard)
and [VBoxManage reference](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage.html)
describe these switches. A guest that reaches the welcome screen but reports
`kvm_required` cannot open protected sessions: check firmware virtualization,
the nested-virtualization setting and conflicts with the Windows hypervisor.
VirtualBox session/clipboard qualification on Windows remains a separate test;
do not infer it from ARM64 UTM results.

### Text copy/paste in a VM

Images built from this revision include the clipboard components; no command or package
installation inside a running Oblivion guest is required. Previously built
ISOs do not acquire these components by enabling a hypervisor checkbox.

- On the outer Mac, copy/paste uses the normal ⌘C/⌘V shortcuts. In the Oblivion
  terminal, select visible text and use Ctrl+C; Ctrl+V pastes clipboard text.
  Super/⌘V is also mapped when the VM forwards that key. UTM may reserve some
  Mac shortcuts for its own menus, so Ctrl+C/Ctrl+V remain the guest shortcuts.
- Copy is an explicit selection action. The session VM cannot send clipboard
  escape sequences to the outer host, and cannot read its clipboard directly.
- The UTM path uses the standard SPICE broker and a restricted open-source
  Wayland adapter, with UTF-8 text and a 256 KiB payload limit. Host text is
  requested lazily on paste. There is no clipboard history, file drag-and-drop,
  network listener or remote-execution agent.
- The VirtualBox path runs only its clipboard client. Temporary PID files and
  display/clipboard state stay in RAM; normal helper output is discarded.
- On bare metal the hypervisor channel is absent. Local terminal copy/paste
  remains available. Clipboard sharing in a VM deliberately makes copied text
  available to its outer OS, whose clipboard history is outside Oblivion.

First-use check: paste harmless accented text from the host into an Oblivion
input, copy a selected reply back, and repeat after closing/reopening a session.
Use the normal session close/lock workflow; text copy/paste does not transfer
session passwords, API keys or documents automatically.

UTM documents the host-side switch and required agent in its
[clipboard guide](https://docs.getutm.app/guest-support/sharing/clipboard/) and
[Linux guest-support guide](https://docs.getutm.app/guest-support/linux/).

A fresh ARM64 development ISO has passed bidirectional clipboard acceptance
on the available UTM Apple-backend Mac with no VM network adapter: physical
Ctrl+V pasted Mac text into the manager, and selected manager text copied with
physical Ctrl+C pasted back into macOS. This used a separate unprovisioned
VM, not a user's archive. Synthetic modifier shortcuts from the UI automation
arrived as ordinary letters, so the two shortcut checks were confirmed by the
human tester. The headless Cage/data-control suite and Unix protocol tests run
separately. The VirtualBox binary/hash/CLI are verified in an amd64 container;
an actual VirtualBox host/guest round trip is still pending.

Running Oblivion inside another operating system weakens its threat model: the
host OS and hypervisor can observe the display, input, memory and virtual disk.
The VM path is for evaluation and development. Booting a verified release image
directly on dedicated hardware remains the intended high-privacy deployment.

For retention-sensitive tests, fully power off the VM after locking Oblivion;
do not suspend it, save its RAM state or take memory snapshots. Keep VM files
outside cloud-synchronized/automatically backed-up folders and protect the
outer disk. These settings reduce accidental retention but do not prevent the
outer OS or hypervisor from reading memory, swapping it or recording input and
display. Oblivion cannot enforce those host policies from inside Debian.

## Disposable audit checks

Use only freshly built, unprovisioned images and disposable synthetic disks.
Never run destructive fixtures against a user's boot medium or archive.
The ARM64 Mac probes use QEMU/HVF with a diagnostic initramfs; they do not install
or change the user's VM and do not qualify physical UEFI boot or nested KVM.

```sh
python3 script/oblivion/run-live-policy-lab.py \
  --iso /absolute/path/to/oblivion-arm64.iso \
  --output artifacts/policy-check

python3 script/oblivion/run-chat-powerloss-lab.py \
  --iso /absolute/path/to/oblivion-arm64.iso \
  --output artifacts/chat-crash-check
```

Output directories must be new. The first probe checks actual host firewall
packets, service confinement and activation order, then records a runtime
metadata inventory. The second kills the outer VM after a compiled chat API
commit, reboots its disposable nested-LUKS disk and checks histories, queued
input, documents and absence of plaintext markers. It does not simulate the
physical host losing power. See [qualification results](STATUS.md#disposable-linux-qualification-2026-10-27)
for the distinct controller/TUI, gateway and live Tor laboratories and their
remaining target-hardware gates.

## TUI development

To run the coding-agent TUI against the currently elected local OpenCode
service:

```sh
bun run dev:live /path/to/project
```

The host manager lives in `packages/oblivion-manager`. The retained coding-agent
TUI lives in `packages/tui`. Preserve the OpenCode chat components and use the
shared semantic theme tokens when extending either interface.

## VM and hardware validation

The scripts under `script/oblivion` build minimal Debian roles and exercise
storage, transfers, gateway policy, boot and chat startup. CI runs the supported
QEMU laboratories on both architectures where practical.

The session terminal uses the existing filtered viewport and guest-only tmux.
Inside a session, F6 selects Chat, F7 Documents and F8 Terminal; Ctrl+Q asks to
close and lock all session processes. In Terminal, Ctrl+B followed by C creates
a window, W lists windows, P opens the user process view and X closes a pane
with confirmation. Ctrl+C interrupts the foreground command. Terminal works
in the offline session VM without a provider key; starting Chat from offline
mode restarts that VM and stops its terminals/jobs. File changes stay on the
same session volume.

Run the real PTY/tmux regression with `python3 script/oblivion/test-session-terminal.py`
(requires tmux). For actual offline guest/service acceptance on an ARM Mac:

```sh
docker buildx build --platform linux/arm64 -f script/oblivion/Dockerfile.vm-lab \
  --target terminal-artifacts --output type=local,dest=artifacts/terminal/image .
cd packages/oblivion-host
cargo build --locked --example viewport-probe
cd ../..
python3 script/oblivion/run-terminal-lab.py --image artifacts/terminal/image \
  --output artifacts/terminal/result
```

The runner uses the production guest terminal service and filtered Rust bridge
with no virtual NIC or provider key. It checks multiple windows, the process
view, resize, interruption and a workspace file across clean guest reboot.
Its disposable ext4 fixture does not qualify the outer LUKS/controller close
path or the physical live image; those remain separate integration gates.
For the controller path, build the `artifacts` target with `HOST=export-host`
and `GUEST=manager-import-guest`, then run `run-vm-lab.py` with the resulting
image, `--refresh-import-test --terminal-only` and a fresh output directory.
That focused test uses the actual authenticated descriptor delegation and
session service, retains a background process through reattachment, verifies
the QEMU PID is reaped before lock success, and reopens the LUKS workspace.

For file transfers, UTM can attach an additional FAT/exFAT/ext4 data image as USB
storage. QEMU profiles may instead attach virtio data media with the explicit
serial `oblivion-import` (always import-only) or `oblivion-export`. Oblivion
excludes its boot/archive disk and all mounted sources; ordinary internal or
unmarked virtual disks are not offered. Imports remain read-only inside the
isolated source VM. The destination picker omits read-only media for export.
Selecting writable media still requires the normal export confirmation.

Documents also provides `Export chat` and `Export diagnostics`. Chat export
lists only the current protected session's chats; choose Markdown or OpenCode
JSON and confirm. The generated file stays under `workspace/chat-exports` and
is selected for a separate `Export selected` operation. Diagnostic reports
show their fixed field allowlist before creation under `workspace/diagnostics`.
Neither operation sends content to a provider or copies it to external media
automatically. JSON transcripts preserve settled message IDs and data; they do
not include queued input or in-progress responses and are not session backups.

To exercise the deployed maintenance services as well as Terminal, use the
same terminal-image command above with `--build-arg TERMINAL_GUEST=opencode-guest`
and a fresh output directory, then pass `--exports` to `run-terminal-lab.py`.
This requires the compiled Linux OpenCode binary and its matching build-evidence
file at the Dockerfile's normal build inputs. The test verifies metadata-only
RPC, JSON/Markdown creation, diagnostic creation, repeated port-slot reuse and
boot cleanup of unfinished staging without removing completed exports.
`test-chat-export.py` additionally exercises a live compiled OpenCode database
with pending/incomplete messages, UTF-8 and tool content, hostile workspace
symlinks and owned staging cleanup. It runs with the compiled-client gateway
laboratory through `vm-gateway-test.py`; no provider calls are involved.

The source manager also exposes `Sessions / Back up` while all sessions are
closed. It prepares metadata in an offline guest, closes the session mapping,
then copies only the encrypted LUKS2 volume to explicitly authorized writable
media as `Oblivion-<operation-id>/files/session.oblivion`. The session password
is still required; general-vault API keys are excluded. This has separate
one-file / 1 TiB / one-hour ceilings and does not widen document transfers.
Preparation is bounded; copying and manifest review can be cancelled. Success
requires the verified receipt, destination flush/detach and worker cleanup.
`Sessions / Restore` opens the selected source read-only, browses it through the
existing paginated picker and copies one encrypted backup after confirmation.
The password is requested after the source VM has been detached. A separate
offline VM checks the copied filesystem, versioned metadata and chat database;
only then is a new session ID published. The original archive/backup are
preserved. Wrong passwords can be retried without another copy. Cancellation
discards the new pending copy; a crash after copying may leave an incomplete
entry that the manager can explicitly discard. A verified copy is never
published by the transport alone. The receiver receives an empty writable
descriptor, not access to the general-vault directory. Supported-candidate
qualification and physical-media acceptance remain pending.
For the focused real-controller test, build the `export-host` /
`manager-import-guest` image above and run `run-vm-lab.py` with
`--refresh-import-test --backup-only` and a fresh output directory. It uses
synthetic passwords, a 512 MiB LUKS volume, an offline session and disposable
ext4 media. It also restores that volume as a separate titled session and checks
wrong-password retry, cancellation, reopened workspace data and unchanged
sources. The guest used in this test has no chat database; it does not prove
real-chat restoration or physical USB behavior. The compiled-client inspection
tests separately check engine compatibility and preservation of SQLite/WAL,
pending prompts and message IDs without provider requests.

For the combined native database/volume test, select
`--build-arg GUEST=backup-chat-guest` instead of `manager-import-guest` when
building the same `export-host` image. Keep the normal compiled-client binary
and matching build-evidence inputs. Run it with `--refresh-import-test
--backup-only`; the marker prevents accidentally running the ordinary import
fixture against this guest. This test seeds two settled synthetic conversations
and pending prompts through OpenCode's API, then compares their IDs, titles,
messages, inbox records and a shared document after the complete encrypted
backup/restore path. It also checks unsupported metadata, corrupt SQLite,
invalid/truncated LUKS volumes and insufficient general-vault space. It makes
no provider requests. Fault fixtures use a separate disposable 128 MiB session;
the normal source/restored archives and external source medium are checked for
unintended changes. The native probe and marker never enter production images.

Writing an image to removable media is intentionally not automated by the
normal build command. Resolve the target device by stable identity, unmount its
partitions and verify its size before any destructive write. Never infer a
removable boot-drive target from a broad device glob.

Physical release-candidate testing must cover at least:

- boot and shutdown on real hardware;
- persistent and ephemeral flows;
- wrong-password and interrupted-write recovery;
- offline Documents without a key or gateway;
- Tor and SOCKS5 startup, failure and revocation;
- chat persistence across lock, reboot and reopen;
- import/export with disconnect and cancellation;
- absence of debug access in the release profile.

## Source policy

The repository retains the OpenCode packages required by the agent runtime and
its TUI. Web, desktop, hosted-service, deployment and marketing packages are
not part of Oblivion. Debian packages are selected by image role; additions
must have a concrete runtime or build-time owner.

Do not commit secrets, user data, encrypted volumes, traffic captures, generated
images or local VM state. See [CONTRIBUTING.md](../CONTRIBUTING.md) for repository
rules.
