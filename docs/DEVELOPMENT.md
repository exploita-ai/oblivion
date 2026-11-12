# Developing Oblivion 1.0

The default branch is `dev`. The privacy-stack refactor replaces the modified
coding agent with pinned official clients and a shared controller. Use fresh
1.0 development installations. There are no beta-format migration readers or
compatibility launch paths.

Use the [repository map](REPOSITORY.md) to distinguish shared runtime, desktop,
Live, component laboratories and historical records. Builder and inspection
entrypoints are indexed in [script/oblivion](../script/oblivion/README.md).

## Source checks

Install the Bun version recorded in `package.json`, then:

```sh
bun install --frozen-lockfile
bun run check
bun run typecheck:tsc
```

`check` verifies the pinned Bun version before running lint and the four
TypeScript workspace checks, including before Turbo can reuse a cache. It does
not run Rust, Python, Swift, VM or image tests. To execute the Bun type checks
again instead of reusing their cache, run `bun run typecheck --force`.

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

## Build controller and Live images

With Docker Buildx available:

```sh
# Shared private controller for a desktop bundle
OBLIVION_ARCH=arm64 bun run build:runtime

# Outer Live OS with the matching private controller embedded
export OBLIVION_BUNDLE_CHANNEL=dev
export OBLIVION_DESKTOP_VERSION="1.0.0~dev1.$(git rev-parse --short=12 HEAD)"
OBLIVION_ARCH=amd64 bun run build:live
OBLIVION_ARCH=arm64 bun run build:live
```

Both commands use `script/oblivion/build-image.sh` and the shared
`Dockerfile.vm-lab`. The controller target is `controller-runtime-artifacts`;
the outer Live target is `live-iso-artifacts`. Diagnostic component targets are
separate. Images contain official agent executables from
`install-agents.json`, not an agent built from this repository's UI utilities.

Controller output lives in `artifacts/oblivion-runtime-ARCH/`; outer Live output
lives in `artifacts/oblivion-stack-ARCH/`. Both retain their ISO, package
inventories, source hashes, runtime hashes and `SHA256SUMS`. Verify that file before using
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
required by its inner Safe VMs. Nested Safes have booted on the diagnostic Mac
Apple Virtualization configuration; this does not qualify a different
hypervisor, the distribution kernel profile or physical Live media. Do not
offer TCG as a production fallback.

Keep component fixtures for transfer endpoints, OnionShare, terminal controls
and the network policy separate from whole-product acceptance. The retired fork
UI and provider-broker harnesses have been removed; their past results cannot
qualify current-source images.

## Branch integration and release plan

The privacy stack is integrated into the default `dev` branch through
[PR #1](https://github.com/exploita-ai/oblivion/pull/1), preserving its history;
[PR #2](https://github.com/exploita-ai/oblivion/pull/2) adds the release-channel
contract. Candidate tag `v1.0.0-rc.1` names
`0b65cac9b17d488a7524a7058606a587e3ec7fdf`, whose nine source-check jobs passed in
[run 43119099699](https://github.com/exploita-ai/oblivion/actions/runs/43119099699).
The RC1 desktop builds succeeded. Its Live images also built and verified, but
the release upload exceeded the per-asset size limit. The delivery contract
below addresses that packaging/upload boundary without changing payload bytes.
These are build and component results, not installed-artifact or VM acceptance.

`main` remains at `d0c0958da6e8fdfb78c80a3dc9d6025ec8950cd3`, the published
`v0.1.0-beta.3` baseline. RC1 exists; no stable 1.0 tag has been created and no
1.0 artifact has been qualified. Repository settings have not been changed:
branch protections and release-tag rules remain planned. GitHub had no
protections or rulesets for `dev` and `main` at the initial review.

| Branch | Intended role |
| --- | --- |
| `dev` | Default branch and current 1.0 baseline after PR #1; source checks must pass before further integration. |
| `main` | Qualified release source, advanced by a controlled promotion. It remains at the published baseline until the first 1.0 candidate is qualified. |
| `privacy-stack` | Product transition integrated into `dev` by PR #1. The temporary branch can be retired; do not maintain a third permanent development line. |

Preserve the existing beta tags and releases as historical records. They do not
imply compatibility readers or continued beta development in the 1.0 tree.
Preserve the integration history without resetting the main branches or
force-pushing the transition.

Remaining work:

1. Require successful CI on each selected source SHA. Configure required source checks and
   prevent force-push/deletion of `dev`, `main` and release tags. Require PR
   review for development integration and a controlled release promotion for
   `main`. The promotion mechanism must permit preserving the qualified SHA.
2. Complete the candidate/release path below. Select an immutable SHA **C** from
   `dev`, record the intended platforms, and build the paired components from
   C. An RC tag such as `v1.0.0-rc.1` identifies C; every source correction gets
   a new SHA and RC tag. Do not move an existing tag.
3. Qualify the installable artifacts and record their digests with the source
   SHA and applicable acceptance scenarios. The first release includes only
   qualified platforms; the Mac Apple Silicon track currently has the most
   installed evidence. Other targets stay experimental until separately
   qualified. Shared-code checks remain required.
4. Promote `main` by fast-forward to C, then create the stable tag and publish
   only the qualified artifacts. If a merge creates another commit **M**, build
   and verify M instead of describing it as C. Changes to embedded version,
   signing or packaging also require verification of the resulting artifacts;
   passing an RC does not authorize replacing its bytes after qualification.

### Candidate builds and remaining release gates

- **Version/channel contract:** all desktop producers/readers and the embedded
  Live bundle use manifest v2 with required `dev`, `rc` or `stable` metadata.
  The old manifest and `development_only` field are rejected. See the exact
  [version grammar and local build commands](DESKTOP.md#build). Product versions
  such as `1.0.0~rc1` remain unchanged inside the payload; delivery filenames
  replace `~` with `-` without rebuilding or modifying its bytes.
- **Candidate authorization:** the three distribution workflows use the same
  ref-to-version resolver and source gate. RC tags must name source contained
  in `dev`; stable tags must name source contained in `main`. Tagged builds
  require a successful push/manual `Oblivion checks` run for the exact source
  SHA, with nonempty, entirely successful jobs. Branch builds remain `dev`.
- **Acceptance and publication:** source checks do not qualify an artifact.
  Record acceptance and distribution evidence for each target and resulting
  digest before publication. Tagged builds remain drafts; RC drafts are
  prereleases, stable drafts are not. Automatic publication remains disabled.
- **Artifact coordination:** reuse `oblivion-desktop.yml` for Mac/Windows,
  `oblivion-desktop-deb.yml` for Linux desktop, and the image workflow for Live.
  Run the Live workflow's draft-preparation job for the candidate tag before
  uploading desktop results for that tag. All three workflows use the same
  channel/version and upload to that existing draft through the shared
  uploader. It verifies draft and prerelease status and refuses existing asset
  names. A unified pipeline for the selected targets remains open; desktop
  upload itself is implemented. Publish only qualified targets.
- **Delivery sizes:** files above 1900 MiB are split into raw `.part01`,
  `.part02`, … segments. Each delivery includes the full file's `.sha256`;
  split deliveries also include `.parts.sha256` and `.reassemble.txt` with
  ordered `cat`/`copy /b` and full-hash verification instructions. Reassembly
  restores the original bytes. See [download and reassembly](DESKTOP.md#download-and-reassemble-delivery-assets).
- **Retention and immutability:** candidate bundles, images, manifests, licenses,
  checksums and test evidence must remain available through qualification and
  release. Every distribution workflow retains its staged delivery files in CI
  for 90 days before attempting release upload, so upload failure does not lose
  the completed build. Uploads never replace assets or publish a draft; changed
  candidates need a new identity. Long-term retention of qualified evidence
  remains to be completed.
- **Distribution profile:** close the platform's installation, permission and
  provenance requirements. Mac builds currently use ad hoc signing; Developer
  ID, notarization and Gatekeeper remain in the distribution gate described in
  [Desktop](DESKTOP.md). Keep diagnostic builds distinguishable from the final
  artifacts.

The ordered functional work and completion criteria are maintained in
[roadmap section 9](oblivion1.0-roadmap.md#9-lavoro-rimanente).

## Release gate

The release workflow produces draft prereleases and checksummed images. Automatic
publication is disabled until actual native VM acceptance is recorded for the
commit and the target platforms being published. Unqualified platforms remain
experimental and do not automatically block a qualified target. Follow the
[roadmap](oblivion1.0-roadmap.md) for persistence, login,
native resume in each original agent, interrupted cleanup, concurrent network isolation, Share,
resource use and platform acceptance. Use synthetic conversations and credentials
for fixtures, and clearly separate local protocol checks from real provider or
public Tor tests.
