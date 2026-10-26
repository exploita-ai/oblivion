# Development

Oblivion is built from the same source for two 64-bit architectures. Physical
USB validation is currently performed on amd64 hardware; arm64 is built for ARM
hardware and compatible virtual machines.

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

## Run from a virtual machine

Oblivion persistence uses free space after the hybrid ISO on the writable boot
USB. Mounting the ISO as a read-only virtual DVD is therefore not equivalent to
writing it to a USB drive. Prepare a new sparse raw disk instead:

```sh
bun run vm:disk -- \
  --image artifacts/oblivion-beta-iso/image/oblivion-development-amd64.iso \
  --output artifacts/oblivion-amd64.raw \
  --size-gib 16
```

The helper accepts only a new output file and never opens a physical device.
Attach the resulting raw image as a writable **USB mass-storage device**. Keep
it private: after setup it contains the encrypted general vault and sessions.

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

Prepare the writable ARM virtual USB:

```sh
bun run vm:disk -- \
  --image artifacts/oblivion-arm-iso/image/oblivion-development-arm64.iso \
  --output artifacts/oblivion-arm64.raw \
  --size-gib 16
```

In UTM:

1. Create a new **Virtualize → Linux** VM using Apple Virtualization.
2. Assign at least 8 GiB RAM and four CPU cores.
3. Use UEFI boot and import `oblivion-arm64.raw` as an external/removable drive.
4. Put that drive first in the boot order and keep it writable.
5. Use shared/NAT networking, but disable shared directories, clipboard sharing,
   Rosetta and every host-device passthrough that Oblivion does not require.
6. Start Oblivion and open a session. A `kvm_required` error means nested
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
  -machine q35,accel=kvm -cpu host -m 8G -smp 4 \
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

Convert the prepared raw disk into a dynamically allocated VDI:

```sh
VBoxManage convertfromraw artifacts/oblivion-amd64.raw \
  artifacts/oblivion-amd64.vdi --format VDI
```

Create a Linux/Debian 64-bit VM with at least 8 GiB RAM and four virtual CPUs.
Enable EFI and **Nested VT-x/AMD-V**, add a USB storage controller, and attach
the VDI to that controller as a writable hard disk. VirtualBox can boot virtual
USB storage only through EFI. NAT is sufficient for ordinary testing; never add
shared folders, shared clipboard, drag-and-drop or host-disk passthrough to a
privacy test VM.

Running Oblivion inside another operating system weakens its threat model: the
host OS and hypervisor can observe the display, input, memory and virtual disk.
The VM path is for evaluation and development. Booting the signed image directly
on dedicated hardware remains the intended high-privacy deployment.

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

Writing an image to removable media is intentionally not automated by the
normal build command. Resolve the target device by stable identity, unmount its
partitions and verify its size before any destructive write. Never infer a USB
target from a broad device glob.

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
