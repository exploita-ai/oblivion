# Build and laboratory tools

Run commands from the repository root with the Bun version in `package.json`.
The [repository map](../../docs/REPOSITORY.md) separates current packages,
historical records and local output. The [development guide](../../docs/DEVELOPMENT.md)
describes source checks and the acceptance boundary.

## Product builds

| Entry point | Output and prerequisites |
| --- | --- |
| `OBLIVION_ARCH=arm64 bun run build:runtime` | Private controller ISO and evidence in `artifacts/oblivion-runtime-arm64/`; Bun and Docker Buildx |
| `OBLIVION_ARCH=arm64 bun run build:live` | Outer Live ISO in `artifacts/oblivion-stack-arm64/`, with the matching controller embedded; Bun and Docker Buildx |
| `build-native.sh` | macOS/Linux desktop bundle paired to a prebuilt controller; native compiler tools and explicit development version/runtime paths |
| `build-native-windows.ps1` | Windows x64 build inputs or a paired bundle; native MSVC environment and pinned tools |
| `build-desktop-deb.sh` | Linux desktop `.deb`, including launcher/helper/controller; explicit `OBLIVION_DEB_VERSION` |
| `bun run build:deb` | Development `.deb` for the trusted controller; explicit `OBLIVION_DEB_VERSION` |
| `bun run vm:disk -- --help` | Help for preparing a new raw VM disk from a hybrid ISO; does not write physical drives |

Use `amd64` instead of `arm64` where appropriate. Image commands use
`build-image.sh controller|live`, which selects `controller-runtime-artifacts`
or `live-iso-artifacts` in `Dockerfile.vm-lab`. `build:iso` and the separate
`build-stack.sh`/`build-runtime.sh` wrappers have been replaced by these explicit
entrypoints. The existing output-directory names are preserved.

See [desktop packaging](../../docs/DESKTOP.md),
[controller packaging](../../docs/DEBIAN.md), and [Live](../../docs/LIVE.md)
for full commands and install/update behavior. `install-runtime.sh` installs
the trusted inner Linux controller; it is not a desktop installer.

`install-agents.*`, `install-session-*` and their locks/notices build the Safe
guest environment. `controller-*` and `pack-vm-assets.sh` assemble the shared
controller. `live-*`, `live-os/` and `display/` implement the outer Live system.
Keep these runtime inputs in the source inventory used by
`native-bundle/host-sources.py` when their composition changes.

## Component laboratories

| Tool | Scope |
| --- | --- |
| `Dockerfile.transfer` | Debian build/test of copy endpoints, separate from booting the product |
| `Dockerfile.display` | Cage/Foot display build and configuration validation for Live |
| `run-transfer-vm-lab.py --help` | Synthetic file-copy checks between disposable, networkless QEMU VMs; requires the `transfer-vm-artifacts` target and QEMU |
| `run-onion-lab.py --help` | Onion gateway control laboratory |
| `run-onion-file-lab.py --help` | File-VM service and private transfer laboratory |
| `vm-onion-recipient.py` / `onion-recipient-test` target | Independent public-Tor recipient fixture; online laboratory only |
| `test-*.py`, `live-os-tests/`, `native-bundle/test-bundle.py` | Focused source, packaging, media and protocol tests; consult CI for prerequisites |

VM laboratories can use disposable disks, processes and network connections.
They are not preview commands and do not qualify installed desktop/Live images
by themselves. Component details and exact lab commands are in the
[transfer](../../packages/oblivion-transfer/README.md) and
[OnionShare](../../packages/oblivion-onion/README.md) package guides.

## Manual inspection tools

These tools are deliberately manual; absence from a production call graph is
not a reason to delete them.

- `audit-image.py CONTROLLER.iso --output inventory.json` inventories an
  immutable controller ISO and its embedded role filesystems without booting
  it. Run with Linux `xorriso`, `unsquashfs`, `dpkg-query` and Python 3.11+;
  `Dockerfile.image-audit` supplies the inspection environment. It expects role
  images directly inside the ISO filesystem, so an outer 1.0 Live ISO is not
  interchangeable input.
- `classify-image.py CONTROLLER.iso inventory.json --output decisions.json`
  follows installed Debian dependencies using `python3-apt` and the matching
  image inventory. Its output is a review aid, not a package-removal plan.
- `audit-runtime.py` prints a metadata snapshot from a running Linux laboratory
  host with administrative read access. It reads process/service policy,
  mounts and socket metadata, not conversation contents. It is separate from
  immutable-image evidence and is not a desktop command.

Put reports under ignored `artifacts/` directories, alongside the revision and
checksum evidence they describe. Consult the [acceptance matrix](../../docs/ACCEPTANCE.md)
before treating any component report as proof of a product release gate.
