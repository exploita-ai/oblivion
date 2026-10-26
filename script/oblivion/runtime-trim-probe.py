#!/usr/bin/env python3
"""Build disposable before/after guest images from an immutable ISO, in Linux.

This experiment prunes generic guest drivers and hardware databases only.
It preserves package databases and every application binary. The explicit
removed-file manifest describes the subset; these images are not a release.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def run(*args):
    return subprocess.check_output(args, text=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def extract(image, path, destination):
    with destination.open("wb") as stream:
        subprocess.run(["unsquashfs", "-cat", str(image), path], stdout=stream, check=True)


def pack(root, output):
    subprocess.run(["mksquashfs", str(root), str(output), "-noappend", "-comp", "zstd", "-processors", "2", "-quiet", "-no-progress"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", choices=["arm64", "amd64"], required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="oblivion-trim-") as directory:
        work = Path(directory)
        host = work / "host.squashfs"
        subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(args.iso), "-extract", "/live/filesystem.squashfs", str(host)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        report = {"iso_sha256": digest(args.iso), "architecture": args.architecture,
                  "scope": "Disposable audit fixtures; no package removal, host changes or release claim", "roles": {}}
        for role in ("session", "gateway", "import", "export"):
            print(f"Preparing {role}", flush=True)
            out = args.output / role
            out.mkdir()
            for name in ("kernel", "initrd", "root.squashfs"):
                extract(host, f"usr/lib/oblivion/vm/{role}/{name}", out / name)
            root = work / role
            subprocess.run(["unsquashfs", "-no-xattrs", "-no-progress", "-processors", "2", "-d", str(root), str(out / "root.squashfs")],
                           check=True, stdout=subprocess.DEVNULL)
            packages = run("dpkg-query", f"--admindir={root / 'var/lib/dpkg'}", "-W", "-f=${Package}\t${Version}\n")
            (out / "packages.tsv").write_text(packages)
            # New product forwarding policy, used identically before and after.
            policy = root / "etc/systemd/journald.conf.d"
            shutil.copyfile(source / "journald-forwarding.conf", policy / "90-oblivion-forwarding.conf")
            (policy / "syslog.conf").symlink_to("/dev/null")
            shutil.copyfile(source / "runtime-trim-probe.sh", root / "usr/libexec/oblivion-trim-probe")
            (root / "usr/libexec/oblivion-trim-probe").chmod(0o755)
            (root / "etc/oblivion-probe-role").write_text(role + "\n")
            dependency = "oblivion-vault.service" if role == "session" else "oblivion-gateway-network.service" if role == "gateway" else "local-fs.target"
            (root / "etc/systemd/system/oblivion-trim-probe.service").write_text(
                f"[Unit]\nRequires={dependency}\nAfter={dependency} systemd-logind.service systemd-udev-trigger.service\n"
                "[Service]\nType=oneshot\nExecStart=/usr/libexec/oblivion-trim-probe\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=60\n")
            wants = root / "etc/systemd/system/multi-user.target.wants"
            wants.mkdir(exist_ok=True)
            (wants / "oblivion-trim-probe.service").symlink_to("../oblivion-trim-probe.service")
            binaries = {str(path.relative_to(root)): digest(path) for base in ("usr/bin", "usr/sbin", "usr/libexec")
                        for path in (root / base).glob("*") if path.is_file() and not path.is_symlink()}
            pack(root, out / "before.squashfs")
            modules = list((root / "usr/lib/modules").iterdir())
            if len(modules) != 1:
                raise ValueError("Expected exactly one kernel version")
            modules = modules[0]
            wanted = ["virtio_pci", "virtio_blk", "virtio_rng", "virtio_console", "squashfs", "ext4", "evdev", "autofs4", "binfmt_misc",
                      "gpio_keys" if args.architecture == "arm64" else "button"]
            if role in ("session", "gateway"):
                wanted.append("virtio_net")
            if role in ("import", "export"):
                wanted.extend(["vfat", "exfat", "nls_utf8", "nls_cp437", "nls_iso8859_1"])
            if role == "gateway":
                # Retain the complete netfilter family for the first experiment,
                # including nft expression modules autoloaded by kernel aliases.
                for base in ("kernel/net/netfilter", "kernel/net/ipv4/netfilter", "kernel/net/ipv6/netfilter"):
                    wanted.extend(path.name.split(".ko")[0] for path in (modules / base).rglob("*.ko*"))
            keep = set()
            for module in sorted(set(wanted)):
                for line in run("modprobe", "-d", str(root), "-S", modules.name, "--show-depends", module).splitlines():
                    if line.startswith("insmod "):
                        keep.add(Path(line.split()[1]).resolve())
            removed = []
            for path in modules.rglob("*.ko*"):
                if path.resolve() not in keep:
                    removed.append({"path": str(path.relative_to(root)), "bytes": path.stat().st_size})
                    path.unlink()
            subprocess.run(["depmod", "-b", str(root), modules.name], check=True)
            for name in ("usr/lib/udev/hwdb.bin", "usr/lib/udev/hwdb.d"):
                path = root / name
                for item in ([path] if path.is_file() else path.rglob("*")):
                    if item.is_file():
                        removed.append({"path": str(item.relative_to(root)), "bytes": item.stat().st_size})
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.exists():
                    path.unlink()
            (root / "etc/systemd/system/systemd-hwdb-update.service").symlink_to("/dev/null")
            for name, expected in binaries.items():
                if digest(root / name) != expected:
                    raise ValueError(f"Application binary changed: {name}")
            pack(root, out / "after.squashfs")
            report["roles"][role] = {"before_bytes": (out / "before.squashfs").stat().st_size,
                                     "after_bytes": (out / "after.squashfs").stat().st_size,
                                     "before_sha256": digest(out / "before.squashfs"), "after_sha256": digest(out / "after.squashfs"),
                                     "requested_modules": sorted(set(wanted)), "retained_module_files": len(keep),
                                     "removed_files": removed, "unchanged_application_files": len(binaries),
                                     "package_manifest_sha256": digest(out / "packages.tsv")}
            shutil.rmtree(root)
            (out / "root.squashfs").unlink()
        disk = args.output / "synthetic.ext4"
        with disk.open("xb") as stream:
            stream.truncate(64 * 1024 * 1024)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(disk)], check=True)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
