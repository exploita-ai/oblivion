#!/usr/bin/env python3
"""Trace installed Debian dependencies with libapt; produce review decisions.

Conservative: alternatives retain every installed satisfying provider. This is
an audit report, never an apt removal plan. Build-only candidates need a separate
runtime composition before removing their package records or files.
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from collections import Counter, deque
from pathlib import Path
import apt_pkg


def cat(image, name, destination):
    with destination.open("wb") as stream:
        subprocess.run(["unsquashfs", "-cat", str(image), name], stdout=stream, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    with args.iso.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != inventory["iso"]["sha256"]:
            raise ValueError("Inventory does not describe this ISO")
    apt_pkg.init_config()
    apt_pkg.config.set("Dir::Etc::sourcelist", "/dev/null")
    apt_pkg.config.set("Dir::Etc::sourceparts", "-")
    apt_pkg.config.set("Dir::Cache::pkgcache", "")
    apt_pkg.config.set("Dir::Cache::srcpkgcache", "")
    apt_pkg.init_system()
    report = {"iso": inventory["iso"], "method": __doc__, "roles": {}}
    with tempfile.TemporaryDirectory(prefix="oblivion-classification-") as directory:
        work = Path(directory)
        host = work / "host.squashfs"
        subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(args.iso), "-extract", "/live/filesystem.squashfs", str(host)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        (work / "lists/partial").mkdir(parents=True)
        apt_pkg.config.set("Dir::State::lists", str(work / "lists"))
        for role, data in inventory["roles"].items():
            image = host
            if role != "host":
                image = work / "guest.squashfs"
                cat(host, f"usr/lib/oblivion/vm/{role}/root.squashfs", image)
            status = work / "status"
            cat(image, "var/lib/dpkg/status", status)
            architecture = next(p["architecture"] for p in data["packages"] if p["architecture"] != "all")
            apt_pkg.config.set("APT::Architecture", architecture)
            apt_pkg.config.set("Dir::State::status", str(status))
            cache = apt_pkg.Cache(None)
            installed = {p.name: p for p in cache.packages if p.current_ver is not None}
            if set(installed) != {p["name"] for p in data["packages"]}:
                raise ValueError(f"APT inventory differs from the package manifest for {role}")
            runtime = ["systemd-sysv", "udev", "dbus", "util-linux", "busybox-static", "kmod", "tzdata"]
            runtime += {"host": ["live-boot", "live-boot-initramfs-tools", "cryptsetup-bin", "dmsetup", "fdisk", "e2fsprogs",
                                 "qemu-system-arm" if architecture == "arm64" else "qemu-system-x86", "network-manager", "wpasupplicant",
                                 "iproute2", "console-setup-mini", "kbd", "xkb-data", "firmware-iwlwifi", "firmware-realtek",
                                 "firmware-atheros", "firmware-brcm80211", "firmware-mediatek"],
                        "session": ["git", "ripgrep", "python3", "ca-certificates"],
                        "gateway": ["tor", "nftables", "iproute2", "ca-certificates"], "import": [], "export": []}[role]
            categories = {
                "retain_runtime": runtime,
                "retain_debian_essential": sorted(name for name, p in installed.items() if p.essential),
                "build_only_candidate": ["apt", "initramfs-tools", "initramfs-tools-core", "adduser", "passwd", "e2fsprogs", "ca-certificates"]
                                        + sorted(name for name in installed if name.startswith("linux-image")),
                "diagnostic_only": ["openssh-server", "sudo", "nftables", "python3", "pciutils", "usbutils", "rfkill"] if role == "host" else [],
                "remove_candidate": ["login"] if role != "host" else [],
            }
            decisions = {}
            unresolved = []
            for category, roots in categories.items():
                paths = {}
                pending = deque([name] for name in roots if name in installed)
                while pending:
                    path = pending.popleft()
                    name = path[-1]
                    if name in paths:
                        continue
                    paths[name] = path
                    decisions.setdefault(name, {"decision": category, "dependency_path": path})
                    for kind in ("Depends", "PreDepends"):
                        for group in installed[name].current_ver.depends_list.get(kind, []):
                            targets = sorted({version.parent_pkg.name for dep in group for version in dep.all_targets()
                                              if version.parent_pkg.current_ver == version})
                            if not targets:
                                unresolved.append({"package": name, "kind": kind,
                                                   "alternatives": [str(dep) for dep in group]})
                            pending.extend(path + [target] for target in targets)
            packages = [{**p, **decisions.get(p["name"], {"decision": "review", "reason": "Host login/PAM package: decide after the Cage/Foot seat/session integration." if role == "host" and p["name"] == "login"
                                                       else "Not required by the declared runtime, essential base, build or diagnostic roots."})}
                        for p in data["packages"]]
            masks = {Path(link["path"]).name for link in data["unit_links"] if link["target"] == "/dev/null"}
            units = []
            for name in sorted({Path(path).name for path in data["installed_units"]}):
                decision, reason = "review_dependency_activation", "Retain until boot/dependency/socket/D-Bus activation is traced; presence is not execution."
                if name in masks:
                    decision, reason = "masked_in_image", "An explicit /dev/null unit mask is present."
                elif name.startswith("oblivion-hardware"):
                    decision, reason = "diagnostic_only", "Administrative laboratory access; exclude from production."
                elif name.startswith("oblivion-"):
                    decision, reason = "retain_product", "Oblivion role lifecycle or explicitly invoked operation."
                elif name.startswith(("systemd-pcr", "systemd-sysext", "systemd-confext", "systemd-hostnamed", "systemd-localed", "systemd-timedated", "systemd-firstboot", "apt-daily", "e2scrub")):
                    decision, reason = "disable_candidate", "Not part of the declared role operations; verify dependencies and activation before masking."
                elif name.startswith(("systemd-udev", "systemd-logind", "systemd-journald", "systemd-tmpfiles", "dbus")):
                    decision, reason = "retain_current_boot", "Current device, shutdown, IPC or volatile-runtime lifecycle dependency."
                units.append({"unit": name, "decision": decision, "reason": reason})
            report["roles"][role] = {"declared_roots": categories, "packages": packages, "units": units,
                                      "package_counts": dict(Counter(p["decision"] for p in packages)),
                                      "unit_counts": dict(Counter(u["decision"] for u in units)),
                                      "unresolved_dependencies": unresolved,
                                      "limits": ["A retain decision follows current Debian package dependencies, not a claim that every file is essential.",
                                                 "Review and disable_candidate entries are not approved removals. No package or service is changed by this report."]}
            if role != "host":
                image.unlink()
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
