# Development

Oblivion is built and tested on macOS and Linux. Physical USB validation is
currently performed on amd64 hardware; the arm64 image is also used by the Mac
VM laboratory.

## Prerequisites

- Bun 1.4.4
- Docker with Buildx
- Python 3
- QEMU for local VM tests
- sufficient free space for Debian root filesystems and VM disks

Install the JavaScript workspace and run the canonical checks:

```sh
bun install --frozen-lockfile
bun run check
bun run typecheck:tsc
```

Run tests from the package that owns them, never from the repository root. Read
the relevant instructions under `.opencode/skills` before changing tests.

## Build images

```sh
# amd64 live image
bun run build:iso

# arm64 live image for the Mac VM laboratory
OBLIVION_ARCH=arm64 bun run build:iso

# development image with hardware-debug support
bun run build:hardware
```

Generated images, VM disks, logs and evidence are written under `artifacts/`
and are ignored by Git. CI produces per-commit evidence as expiring workflow
artifacts; generated evidence must not be committed as permanent documentation.

Development images are not release images. They may contain diagnostics,
temporary access keys or services that must be absent from a public build.

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
laboratories on both architectures where practical.

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
