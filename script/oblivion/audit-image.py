#!/usr/bin/env python3
"""Inventory a built Oblivion ISO without booting, mounting or executing it.

Requires Linux tools: xorriso, unsquashfs, dpkg-query, Python 3.11+.
Use only immutable build artifacts, never a provisioned USB/session volume.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path


def run(*args):
    return subprocess.check_output(args, text=True, env={**os.environ, "LC_ALL": "C", "TZ": "UTC"})


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def cat(image, name, destination):
    with destination.open("wb") as stream:
        subprocess.run(["unsquashfs", "-cat", str(image), name], stdout=stream, check=True)


def initramfs(path):
    entries = sorted(run("lsinitramfs", str(path)).splitlines())
    return {"bytes": path.stat().st_size, "sha256": digest(path), "entries": entries,
            "module_count": sum(name.endswith((".ko", ".ko.xz", ".ko.zst", ".ko.gz")) for name in entries)}


def inventory(image, role, work, manifests):
    print(f"Inventory: {role}", flush=True)
    entries = []
    for line in run("unsquashfs", "-lln", "-UTC", "-d", "/image", str(image)).splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/image"):
            raise ValueError(f"Unexpected SquashFS listing for {role}")
        path, separator, target = fields[5].partition(" -> ") if fields[0][0] == "l" else (fields[5], "", "")
        entries.append({"path": path.removeprefix("/image") or "/", "mode": fields[0], "owner": fields[1],
                        "bytes": int(fields[2]) if fields[0][0] == "-" else 0,
                        **({"target": target} if separator else {})})
    admin = work / role
    admin.mkdir()
    cat(image, "var/lib/dpkg/status", admin / "status")
    fields = "${Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${Essential}\t${Status}\t${Depends}\t${Pre-Depends}\t${Recommends}\n"
    packages = []
    for line in run("dpkg-query", f"--admindir={admin}", "-W", f"-f={fields}").splitlines():
        name, version, architecture, size, essential, status, depends, predepends, recommends = line.split("\t")
        if status != "install ok installed":
            continue
        packages.append({"name": name, "version": version, "architecture": architecture,
                         "installed_kib": int(size or 0), "essential": essential == "yes",
                         "depends": depends, "pre_depends": predepends, "recommends": recommends})
    packages.sort(key=lambda package: (-package["installed_kib"], package["name"]))
    manifest = manifests / f"{role}-packages.tsv"
    matched = None
    if manifest.is_file():
        expected = {tuple(line.split("\t")) for line in manifest.read_text().splitlines()}
        actual = {(package["name"], package["version"]) for package in packages}
        if expected != actual:
            raise ValueError(f"Package manifest differs from immutable {role} image")
        matched = True
    files = [entry for entry in entries if entry["mode"].startswith("-")]
    groups = defaultdict(int)
    prefixes = ("/usr/lib/oblivion/vm", "/usr/lib/oblivion", "/usr/lib/firmware", "/usr/lib/modules",
                "/usr/bin/oblivion", "/usr/lib", "/usr/bin", "/usr/sbin", "/usr/share", "/var", "/etc")
    for entry in files:
        group = next((prefix for prefix in prefixes if entry["path"].startswith(prefix + "/")
                      or entry["path"] == prefix or (prefix == "/usr/bin/oblivion" and entry["path"].startswith(prefix + "-"))), "other")
        groups[group] += entry["bytes"]
    unit_roots = ("/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/")
    units = [entry for entry in entries if entry["path"].startswith(unit_roots)]
    # Only fixed system policy locations in an immutable build image. Never
    # collect credentials, arbitrary /etc files or provisioning/user volumes.
    policy = {}
    for entry in files:
        path = entry["path"]
        if (path in ("/etc/fstab", "/etc/systemd/journald.conf", "/etc/oblivion/firewall.nft", "/etc/oblivion/host-firewall.nft", "/etc/oblivion/torrc", "/etc/oblivion/onion-file.nft", "/etc/oblivion/onion/firewall.nft", "/etc/oblivion/onion/torrc")
            or path.startswith(("/etc/systemd/journald.conf.d/", "/usr/lib/systemd/journald.conf.d/",
                                "/etc/systemd/system.conf.d/", "/etc/modules-load.d/", "/etc/sysctl.d/",
                                "/etc/NetworkManager/conf.d/", "/etc/systemd/system/NetworkManager.service.d/"))
            or (path.startswith("/etc/systemd/system/oblivion-") and path.endswith((".service", ".conf")))):
            policy[path] = run("unsquashfs", "-cat", str(image), path.lstrip("/"))
    # Bundled components are not necessarily installed Debian packages. Keep
    # their pinned source/hash/license records visible alongside dpkg inventory.
    bundled_tools = {}
    bundled_components = {}
    for entry in files:
        if entry["path"] == "/usr/lib/oblivion/session-tools.json":
            if entry["bytes"] > 1024 * 1024:
                raise ValueError("Session tools manifest exceeds the audit limit")
            bundled_tools = json.loads(run("unsquashfs", "-cat", str(image), entry["path"].lstrip("/")))
        if entry["path"] == "/opt/oblivion-onionshare/inventory.json":
            if entry["bytes"] > 1024 * 1024:
                raise ValueError("OnionShare manifest exceeds the audit limit")
            bundled_components["onionshare"] = json.loads(run("unsquashfs", "-cat", str(image), entry["path"].lstrip("/")))
        if entry["path"] in ("/usr/share/doc/oblivion-clipboard/upstream.json", "/usr/lib/oblivion/virtualbox/provenance.json"):
            if entry["bytes"] > 1024 * 1024:
                raise ValueError("Clipboard provenance exceeds the audit limit")
            name = "clipboard_adapter" if entry["path"].endswith("upstream.json") else "virtualbox_clipboard"
            bundled_components[name] = json.loads(run("unsquashfs", "-cat", str(image), entry["path"].lstrip("/")))
        if entry["path"] in ("/usr/share/doc/spice-vdagent/package.control", "/usr/share/doc/spice-vdagent/SHA256SUMS"):
            bundled_components.setdefault("spice_clipboard_broker", {})[Path(entry["path"]).name] = run("unsquashfs", "-cat", str(image), entry["path"].lstrip("/"))
    return {
        "filesystem_bytes": image.stat().st_size, "filesystem_sha256": digest(image),
        "package_manifest_matches": matched, "package_count": len(packages), "packages": packages,
        "regular_file_count": len(files), "logical_file_bytes": sum(entry["bytes"] for entry in files),
        "logical_file_groups": dict(sorted(groups.items())),
        "largest_files": sorted(files, key=lambda entry: (-entry["bytes"], entry["path"]))[:25],
        "executable_files": sorted((entry for entry in files if any(flag in entry["mode"] for flag in "xst")),
                                   key=lambda entry: entry["path"]),
        "setid_files": sorted((entry for entry in files if entry["mode"][3] in "sS" or entry["mode"][6] in "sS"),
                              key=lambda entry: entry["path"]),
        "installed_units": sorted(entry["path"] for entry in units if entry["mode"].startswith("-")
                                  and entry["path"].endswith((".service", ".socket", ".timer"))),
        "unit_links": sorted((entry for entry in units if "target" in entry), key=lambda entry: entry["path"]),
        "dbus_activation_files": sorted(entry["path"] for entry in files
                                        if entry["path"].startswith("/usr/share/dbus-1/system-services/")),
        "diagnostic_image_marker": any(entry["path"] == "/etc/oblivion/hardware/authorized_key.pub" for entry in files),
        "system_policy_files": policy,
        "bundled_tools": bundled_tools,
        "bundled_components": bundled_components,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--initramfs", action="store_true", help="Also inventory boot archives with Debian lsinitramfs")
    args = parser.parse_args()
    iso = args.iso.resolve(strict=True)
    if iso.suffix != ".iso" or not iso.is_file():
        parser.error("Expected an immutable build .iso file")
    if args.output.resolve() == iso:
        parser.error("Output must not overwrite the input ISO")
    with tempfile.TemporaryDirectory(prefix="oblivion-image-audit-") as directory:
        work = Path(directory)
        subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/live", str(work / "live")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        host = work / "live/filesystem.squashfs"
        roles = {"host": inventory(host, "host", work, iso.parent)}
        boot = {"host": initramfs(work / "live/initrd.img")} if args.initramfs else {}
        available = set(run("unsquashfs", "-ll", str(host)).splitlines())
        for role in ("session", "gateway", "import", "export", "onion-gateway", "onion-file"):
            if role.startswith("onion-") and not any(line.endswith(f"/usr/lib/oblivion/vm/{role}/root.squashfs") for line in available):
                continue
            image = work / f"{role}.squashfs"
            cat(host, f"usr/lib/oblivion/vm/{role}/root.squashfs", image)
            roles[role] = inventory(image, role, work, iso.parent)
            image.unlink()
            if args.initramfs:
                path = work / "guest-initrd"
                cat(host, f"usr/lib/oblivion/vm/{role}/initrd", path)
                boot[role] = initramfs(path)
                path.unlink()
        report = {
            "schema_version": 2, "iso": {"name": iso.name, "bytes": iso.stat().st_size, "sha256": digest(iso)},
            "auditor_sha256": digest(Path(__file__)),
            "tools": dict(line.split("\t") for line in run("dpkg-query", "-W", "-f=${Package}\t${Version}\n",
                                                           "squashfs-tools", "xorriso", "dpkg",
                                                           *(("initramfs-tools-core",) if args.initramfs else ())).splitlines()),
            "boot_files": [{"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)}
                           for path in sorted((work / "live").iterdir()) if path.is_file() and path != host],
            "roles": roles,
            "initramfs": boot,
            "limitations": [
                "Static ISO inventory; no guest binaries executed and no filesystems mounted. No live/user volumes inspected.",
                "Installed units, links and D-Bus activation files do not establish which processes run or which ports listen.",
                "Logical file sizes count each pathname, including hardlinks; they are not compressed ISO costs or removable-byte estimates.",
                "Host file totals include embedded guest images; guest logical totals must not be added to the host total.",
                "Debian Installed-Size is package metadata, not measured compressed size; custom binaries are counted in file metadata.",
                "Optional initramfs inventory lists archive entries only; it does not validate every early-boot script. Xattrs/capabilities, runtime writes, traffic and supply-chain trust need separate audits.",
            ],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Report: {args.output}", flush=True)


if __name__ == "__main__":
    main()
