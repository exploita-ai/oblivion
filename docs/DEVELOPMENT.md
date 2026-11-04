# Developing Oblivion 1.0

The default branch is `dev`. The privacy-stack refactor replaces the modified
coding agent with pinned official clients and a shared controller. Use fresh
1.0 development installations. There are no beta-format migration readers or
compatibility launch paths.

## Source checks

Install the Bun version recorded in `package.json`, then:

```sh
bun install --frozen-lockfile
bun run check
bun run typecheck:tsc
```

Run tests from their package directory, never from the repository root:

```sh
cd packages/oblivion-manager
bun test --timeout 30000

cd ../oblivion-host
cargo check --locked --lib --bins
cargo test --locked --lib --bin oblivion

cd ../oblivion-share
cargo test --locked --release --test container
```

The CI workflow records the complete current set of package-local suites. Rust
image builds and CI pin Rust 1.88.0. Native C/C++ dependencies also need the
compiler tools listed in that workflow.

## Manager preview

```sh
bun run dev
```

The preview uses local fixture state and does not open a real Safe, authenticate
to a provider or provision a disk. Renderer fixtures under the manager package
exercise real production components. Check 80×24 and 160×50, focus without a
mouse, resize and paste boundaries. An interactive screenshot alone does not
verify controller state.

## Build a development image

With Docker Buildx available:

```sh
OBLIVION_ARCH=amd64 bun run build:iso
OBLIVION_ARCH=arm64 bun run build:iso
```

The current shared builder is `script/oblivion/Dockerfile.vm-lab`, selected via
`build-stack.sh`. Its production target is `stack-runtime-iso`; diagnostic
component targets are separate. Images contain official agent executables from
`install-agents.json`, not an agent built from this repository's UI utilities.

Output lives in `artifacts/oblivion-stack-ARCH/`: the ISO, package inventories,
source hashes, runtime hashes and `SHA256SUMS`. Verify that file before using
the artifact. No source checksum is a substitute for signed release provenance
or the acceptance matrix. A build does not qualify nested virtualization.

## Native launcher and controller

The Rust package `oblivion-host` builds the CLI and Linux controller.
`oblivion-native` builds the macOS Virtualization.framework helper;
`oblivion-native-linux` builds the Linux QEMU/KVM helper for x86_64 and ARM64. A desktop
installation pairs the CLI, manager, helper and matching runtime image. Do not
mix a current CLI with an earlier prototype's internal protocol.

The desktop launcher supports explicit runtime install/update/start/stop/recover
operations. An update must preserve the private persistence disk and refuse
running owners rather than replacing them in place. Test against disposable
state directories. Never target a user's existing UTM disk or provisioned boot
media during automated development checks.

A root-owned `/etc/oblivion/installation.json` marker with `live-launcher` selects
the outer Live launcher. Both desktop and Live use a headless controller VM;
there is no direct-controller fallback on external Debian. `install-runtime.sh`
prepares the trusted inner controller root, not a cross-platform desktop
installation. Live disk authorization reviews only a dedicated partition on
the actual boot USB. RAM-only Live runs do not attach that partition.

The development Debian controller package reuses the Live role-asset packer and
stops before ISO creation:

```sh
OBLIVION_ARCH=amd64 OBLIVION_DEB_VERSION=1.0.0~dev20261104 bun run build:deb
```

Its install/remove/reinstall fixtures exercise real dpkg with synthetic role
assets; they do not start a Safe or qualify hardware. See [Debian packaging](DEBIAN.md)
for exact payloads, dependencies, retained application data and release gates.

## Live and hypervisor tests

The [Live guide](LIVE.md) lists the standard Debian consoles, storage-mode
selection and the boundary between OS preferences and encrypted Oblivion data.

The Live image can be written to supported writable boot media. The standalone
`prepare-vm-disk.py` helper can copy a hybrid ISO into a larger new raw virtual
disk and relocate its GPT backup. It does not modify the input ISO or a physical
drive. A read-only DVD plus an arbitrary secondary data disk is not currently a
qualified first-run persistence path.

UTM/VirtualBox evaluation of a Live image is distinct from the native launcher.
The guest must have the architecture and nested hardware-virtualization support
required by its inner Safe VMs. Current 1.0 Mac testing has not qualified inner
KVM boots on the test configuration. Do not offer TCG as a production fallback.

Keep component fixtures for transfer endpoints, OnionShare, terminal controls
and the network policy separate from whole-product acceptance. The retired fork
UI and provider-broker harnesses have been removed; their past results cannot
qualify current-source images.

## Release gate

The release workflow produces draft prereleases and checksummed images. Automatic
publication is disabled until actual native VM acceptance is recorded for the
commit. Follow the [roadmap](oblivion1.0-roadmap.md) for persistence, login,
native resume in each original agent, interrupted cleanup, concurrent network isolation, Share,
resource use and platform acceptance. Use synthetic conversations and credentials
for fixtures, and clearly separate local protocol checks from real provider or
public Tor tests.
