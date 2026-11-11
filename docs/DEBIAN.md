# Development Debian package

The development `.deb` installs the **private Debian controller component**.
It belongs inside the headless controller VM, on desktop and Live alike. It
contains Safe/gateway roles and controller services; it is not the native
launcher package and does not turn the physical Debian host into a controller.

Use the [desktop package](DESKTOP.md#debian-desktop-package) or the native
bundle on an ordinary Linux desktop. The Live image
preinstalls that same launcher and virtualizer on its outer Debian OS, then
starts the private controller VM. The controller package's installation marker
is `controller-runtime`; the native launcher refuses it rather than adopting a
local daemon. Controller startup also requires the private runtime boot flag.

This is not a qualified public installer. Real KVM/hardware testing and review
of every embedded client's redistribution terms remain release gates. Building
an artifact does not establish permission to redistribute it.

## Build

Use the repository's pinned Bun version, Docker Buildx, and the current source
checkout. An explicit development version is required:

```sh
bun install --frozen-lockfile
OBLIVION_ARCH=amd64 OBLIVION_DEB_VERSION=1.0.0~dev20261104 \
  sh script/oblivion/build-deb.sh
```

`OBLIVION_ARCH=arm64` selects Debian ARM64 artifacts. This describes the package
architecture, not a claim that nested virtualization or a particular ARM
machine is supported. Hardware qualification is still required.

The build compiles the current controller, tools and OpenTUI manager, prepares
the same six immutable VM roles as the Live build, and stops before ISO creation.
It produces a `.deb` and its SHA-256 file in
`artifacts/oblivion-debian-<architecture>/`. Existing package files are not
overwritten. There is no upload or release step.

All downloads occur at source-build time through the pinned client/Node/analysis
locks and Debian repositories. Install and remove scripts download no runtime
assets. Debian repository versions can move; the resulting inventories record
the exact versions used. This is not a bit-for-bit reproducibility claim.

For an already prepared root, the same package assembler is available inside a
matching Debian build environment:

```sh
python3 -B script/oblivion/debian/build-package.py \
  --source /path/to/prepared-root --architecture amd64 \
  --version 1.0.0~dev20261104 --output /path/to/output
```

The input must contain all current role assets, manager assets and build
evidence. It must be a trusted build root, never an opened Safe or an installed
user profile. The assembler validates architecture and the allowed payload;
it does not certify the input's origin or guest bootability.

## Install and remove

The package target is the Debian 13 OS **inside a prepared controller VM**,
booted with `oblivion.runtime=1`, using systemd, a tmpfs
`/run`, cgroup v2 and working KVM for its architecture. Swap must already be
disabled, including zram swap. The package refuses installation with active
swap and never calls `swapoff` or changes system swap configuration. The
controller independently enforces this requirement at runtime.

```sh
sudo apt install ./oblivion-stack_1.0.0~dev20261104_amd64.deb
```

Debconf asks for one existing, non-root local account authorized to use the
controller. It does not guess UID 1000, create a human account, or grant sudo.
For unattended installation, explicitly supply the intended existing account:

```sh
printf '%s\n' 'oblivion-stack oblivion-stack/manager-user string alice' \
  | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt install ./oblivion-stack_1.0.0~dev20261104_amd64.deb
```

The selected account must remain the same on upgrade. Configuration conflicts,
occupied reserved service UIDs/GIDs, unsafe app-path ownership, or a different
installation profile fail configuration rather than being silently rewritten.
The controller is enabled as a system service; no TTY, desktop or manager
autostart is installed. The user launches the CLI/TUI from their terminal.

```sh
sudo apt remove oblivion-stack
```

Removal stops the controller and requires recovery to finish before removing
its executables. An active controller, remaining mappings or failed cleanup
can block removal; resolve the recovery failure rather than forcing it.

**Encrypted archives, generated application configuration and reserved service
identities are retained, including `apt purge`.** This intentional retention
prevents accidental data deletion and UID reuse. There is no automatic
data-erasure command in this packaging increment. Debian's keyboard, time zone,
Wi-Fi, routing, firewall, boot configuration and existing user files are left
to Debian.

## Payload and dependencies

The package owns these current paths only:

| Paths | Contents and ownership |
| --- | --- |
| `/usr/bin/oblivion{,-storage,-control,-copy}` | Current host executables, root-owned 0755 |
| `/usr/bin/oblivion-manager` | Wrapper setting installed OpenTUI assets and private RAM extraction directory |
| `/usr/lib/oblivion/manager/` | Compiled manager, matching OpenTUI native library, included license notices |
| `/usr/lib/oblivion/vm/` | Session, gateway, import, export, onion-gateway, onion-file kernels/initrds/squashfs; confined QEMU root |
| `/usr/lib/systemd/system/oblivion-*.service` | Eight explicitly allowlisted controller/recovery/owner units; no graphical, debug, clipboard, relay or OS-network services |
| `/usr/lib/sysusers.d/oblivion.conf` | Fixed per-role service identities for slots 0–31; collision checked before creation |
| `/etc/oblivion/installation.json` | Root-owned current-format `controller-runtime` marker (private VM only) |
| `/usr/share/oblivion/controller.template.json` | Non-secret controller defaults for initial configuration |
| `/usr/lib/oblivion/debian/` | Configuration helper and dependency/unit declarations |
| `/usr/share/doc/oblivion-stack/` | License notices, exact file manifest and build inventories |

Post-install generates `/etc/oblivion/controller.json` root:root 0600 and the
app-only `/etc/tmpfiles.d/oblivion.conf`. Existing matching configuration is
preserved byte for byte. Application data lives in `/var/lib/oblivion/`
root:root 0700; the default encrypted general archive is `general.luks` there.
OpenTUI extraction uses `/run/oblivion-manager`, mode 0700, owned by the selected
account. It is required to be tmpfs.

Declared Debian dependencies are maintained in
[`runtime-depends.txt`](../script/oblivion/debian/runtime-depends.txt): systemd,
init-system-helpers, Python 3.13+, cryptsetup-bin, dmsetup, e2fsprogs, util-linux,
mount, fdisk, udev and debconf. `dpkg-shlibdeps` adds actual host executable and
OpenTUI ELF library dependencies; missing libraries fail the build. QEMU and
its libraries/data run from the packaged immutable chroot, with their Debian
package/source inventories and available copyright notices included.

Embedded components include the pinned official Codex, Claude Code and
OpenCode2 clients, Node/npm, the current history adapters and MCP tools,
locked Python analysis tools, Tor, OnionShare and Debian guest packages. The
exact selected clients and integrity hashes are in
`build/client-evidence.json`; each role and the QEMU root have their own
`*-packages.tsv` with binary and source versions. `Built-Using` records those
embedded Debian source versions. Non-Debian client terms require separate
review; package inventory is not a redistribution authorization.

`files.json` records packaged file paths, modes, ownership, sizes and SHA-256
hashes, plus the separately generated configuration paths. Build evidence also
records source revision/dirty status, controller/gateway source hashes, runtime
source and lock hashes, and packaging source hashes. These identify build
inputs and outputs; they are not signed provenance or a substitute for source
availability and licensing review.

## Verification status

Run the small, disposable packaging fixture:

```sh
sh script/oblivion/test-deb.sh
```

It uses real Debian `dpkg`, dependency resolution, debconf, sysusers, tmpfiles,
install, remove, purge and reinstall. It verifies the exact payload allowlist,
root ownership/modes, installed manager environment and preservation of app
configuration, encrypted-data sentinel and Debian OS settings. It also rejects
a release version without `~dev` and unexpected manager assets.

The fixture deliberately uses **nonbootable synthetic role assets** and known
system ELF files instead of actual QEMU/agents/OpenTUI. Read-only synthetic
`/proc/swaps` snapshots exercise both the active-swap refusal and the no-swap
installation path without changing Docker Desktop or host swap. Test containers
have no network and use private tmpfs `/run` and `/tmp`. This qualifies package
mechanics only. A full real-role package build, service lifecycle under a real
systemd host, working KVM, Safe persistence/network isolation, supported hardware
and redistribution terms remain to be qualified before release.
