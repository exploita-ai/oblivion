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

Plan recorded on 11 November 2026; branch promotion and repository settings have
not yet been changed. At the initial review, the remote default was `dev`, and
remote `dev` and `main` both pointed to `d0c0958`, the published beta.3 baseline.
Local `privacy-stack` was at `f5ed189`, 269 commits ahead with no divergence,
plus uncommitted work. The runtime, cleanup and planning work is now being
recorded in separate commits for integration. GitHub had no protections or
rulesets for the two branches at that review.

| Branch | Intended role |
| --- | --- |
| `dev` | Default branch and integration point for current 1.0 work; source checks must pass before integration. |
| `main` | Qualified release source, advanced by a controlled promotion. It remains at the published baseline until the first 1.0 candidate is qualified. |
| `privacy-stack` | Temporary integration branch for the product transition. Retire it after its work is integrated into `dev`; do not maintain a third permanent development line. |

Preserve the existing beta tags and releases as historical records. They do not
imply compatibility readers or continued beta development in the 1.0 tree.
Do not reset the main branches, force-push the transition or cherry-pick all
269 commits independently.

1. Review and commit the current work in coherent changes, keeping the existing
   startup/runtime work distinct from the repository and protocol cleanup.
   Publish `privacy-stack`, open the integration PR against `dev`, and run the
   current full CI on that change. Preserve its history with a normal merge or
   fast-forward rather than squashing or rebasing the entire transition.
2. Verify CI on the resulting `dev` SHA. Configure required source checks and
   prevent force-push/deletion of `dev`, `main` and release tags. Require PR
   review for development integration and a controlled release promotion for
   `main`. The promotion mechanism must permit preserving the qualified SHA.
3. Complete the candidate/release path below. Select an immutable SHA **C** from
   `dev`, record the intended platforms, and build the paired components from
   C. An RC tag such as `v1.0.0-rc.1` identifies C; every source correction gets
   a new SHA and RC tag. Do not move an existing tag.
4. Qualify the installable artifacts and record their digests with the source
   SHA and applicable acceptance scenarios. The first release includes only
   qualified platforms; the Mac Apple Silicon track currently has the most
   installed evidence. Other targets stay experimental until separately
   qualified. Shared-code checks remain required.
5. Promote `main` by fast-forward to C, then create the stable tag and publish
   only the qualified artifacts. If a merge creates another commit **M**, build
   and verify M instead of describing it as C. Changes to embedded version,
   signing or packaging also require verification of the resulting artifacts;
   passing an RC does not authorize replacing its bytes after qualification.

### Candidate and release implementation still required

- **Version/channel contract:** desktop builders and the bundle reader currently
  require `~dev` and `development_only=true`. Implement one current, consistent
  contract for development, RC and stable output across producers and readers.
  A `v1.0.0` tag alone cannot produce a supported stable bundle today.
- **Candidate authorization:** the image workflow currently accepts only `main`
  or tags already contained in `main`. Permit draft RCs from recorded `dev`
  commits; keep stable tags restricted to qualified source on `main`. This must
  work before promoting the candidate.
- **Checks and acceptance:** release builds currently depend on source
  authorization, not the source-check result. Require successful checks for the
  exact candidate SHA and an acceptance record for each published target before
  publication. Keep automatic publication disabled while this is unfinished.
- **Artifact coordination:** reuse `oblivion-desktop.yml` for Mac/Windows,
  `oblivion-desktop-deb.yml` for Linux desktop, and the image workflow for Live.
  Connect them to the same candidate/version and selected target list. They are
  not yet an integrated release pipeline. Publish qualified desktop bundles as
  well as Live images when that target is selected; the current release workflow
  uploads only ISO/checksum pairs.
- **Retention and immutability:** candidate bundles, images, manifests, licenses,
  checksums and test evidence must remain available through qualification and
  release. The current seven-day CI artifact retention is insufficient for that
  record. Do not allow a rerun using `--clobber` to replace published release
  assets; a changed candidate gets a new identity.
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
