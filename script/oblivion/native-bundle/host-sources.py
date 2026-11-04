#!/usr/bin/env python3
"""The shared, compiler-relative source inventory for desktop runtime pairing."""
import argparse
import hashlib
from pathlib import Path
import stat
import sys


SCRIPT_INPUTS = (
    "Dockerfile.vm-lab", "hypervisor-kernel.py", "hypervisor-qemu.py", "controller-setup.sh", "controller-pack.sh", "live-setup.sh", "live-pack.sh", "live-storage.py", "live-grub.cfg",
    "live-controller.json", "vm-common-setup.sh", "journald-forwarding.conf",
    "session-identities.sh", "pack-vm-assets.sh", "host-firewall.nft",
    "install-agents.py", "install-agents.json", "session-node.json",
    "install-session-node.py", "session-packages.txt", "session-analysis.lock",
    "session-analysis-licenses.json", "install-session-analysis.py",
    "onionshare-source.json", "onionshare-requirements.lock",
    "onionshare-licenses.json", "install-onionshare.py",
    "install-vbox-clipboard.py", "vbox-clipboard.json",
    "native-bundle/host-sources.py", "display", "live-os",
)
PACKAGE_INPUTS = {
    "oblivion-cli": ("Cargo.toml", "Cargo.lock", "src"),
    "oblivion-wire": ("Cargo.toml", "Cargo.lock", "src"),
    "oblivion-transfer": ("Cargo.toml", "Cargo.lock", "src"),
    "oblivion-share": ("Cargo.toml", "Cargo.lock", "src"),
    "oblivion-tor-state": ("Cargo.toml", "src"),
    "oblivion-transport": ("Cargo.toml", "src"),
    "oblivion-history": ("prepare.py", "oblivion_history"),
    "oblivion-tools": ("dist/server.mjs",),
    "oblivion-gateway": ("Cargo.toml", "Cargo.lock", ".cargo", "src", "guest"),
    "oblivion-onion": ("service.py", "guest", "LICENSE", "NOTICE"),
    "oblivion-clipboard": ("Cargo.toml", "Cargo.lock", "src", "LICENSE", "PROVENANCE.md", "upstream.json"),
    "oblivion-manager": ("src", "script/build.ts", "package.json"),
    "theme": ("src",),
    "tui-kit": ("src",),
}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def inventory(host, scripts, workspace):
    roots = [(host, "", ("Cargo.toml", "Cargo.lock", "src", "tests", "host", "examples", "guest", "import", "export"))]
    roots.extend((host.parent / name, "../" + name + "/", names) for name, names in PACKAGE_INPUTS.items())
    roots.extend(((scripts, "../runtime-inputs/", SCRIPT_INPUTS),
                  (workspace, "../workspace-inputs/", ("package.json", "bun.lock", "LICENSE", "NOTICE"))))
    files = {}
    for root, prefix, names in roots:
        for name in names:
            source = root / name
            if source.is_symlink():
                raise ValueError("Symlink in runtime sources: " + str(source))
            entries = [source, *source.rglob("*")] if source.is_dir() else [source]
            for entry in entries:
                relative = entry.relative_to(root)
                if "__pycache__" in relative.parts or entry.name == ".DS_Store" or entry.suffix == ".pyc":
                    continue
                mode = entry.lstat().st_mode
                if stat.S_ISDIR(mode):
                    continue
                if not stat.S_ISREG(mode):
                    raise ValueError("Non-regular runtime source: " + str(entry))
                if root.name == "oblivion-history" and entry.suffix != ".py":
                    continue
                key = prefix + relative.as_posix()
                if not key.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in key) or "\\" in key:
                    raise ValueError("Unsupported source path: " + key)
                files[key] = digest(entry)
    return "".join(files[key] + "  " + key + "\n" for key in sorted(files))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", type=Path, help="oblivion-host package root; /build in the compiler")
    parser.add_argument("--scripts", required=True, type=Path, help="script/oblivion root; /runtime-inputs in the compiler")
    parser.add_argument("--workspace", type=Path, help="repository root; /workspace-inputs in the compiler")
    args = parser.parse_args()
    try:
        sys.stdout.write(inventory(args.host, args.scripts, args.workspace or args.host.parent.parent))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
