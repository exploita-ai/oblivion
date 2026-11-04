#!/usr/bin/env python3
"""Verify an existing runtime image, then assemble an unsigned development bundle."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


REPO = Path(__file__).resolve().parents[2]
PLATFORMS = {
    "darwin-arm64": ("arm64", "apple-vz", "@opentui/core-darwin-arm64/libopentui.dylib"),
    "linux-x86_64": ("amd64", "qemu-kvm", "@opentui/core-linux-x64/libopentui.so"),
    "linux-arm64": ("arm64", "qemu-kvm", "@opentui/core-linux-arm64/libopentui.so"),
}
EVIDENCE = ("host-sources.sha256", "gateway-sources.sha256", "iso-sources.sha256",
            "runtime.sha256", "client-evidence.json", "hypervisor-kernel.json", "host-packages.tsv",
            "session-packages.tsv", "gateway-packages.tsv", "import-packages.tsv",
            "export-packages.tsv", "onion-gateway-packages.tsv", "onion-file-packages.tsv",
            "qemu-packages.tsv")
MANAGER_LICENSES = ("@opentui/core", "@opentui/solid", "solid-js", "zod", "shell-quote")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def safe_path(value):
    if (not value or len(value) > 512 or not value.isascii() or value.startswith("/") or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("Unsupported bundle path: " + value)
    return value


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Expected a regular file: " + str(path))
    if info.st_size > 64 * 1024 * 1024 * 1024:
        raise ValueError("Bundle file exceeds 64 GiB: " + str(path))
    return path


def current_sources():
    spec = importlib.util.spec_from_file_location("host_sources", REPO / "script/oblivion/native-bundle/host-sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inventory(REPO / "packages/oblivion-host", REPO / "script/oblivion", REPO).encode("ascii")


def require_current(path):
    if regular(path).read_bytes() != current_sources():
        raise ValueError("Runtime host-sources.sha256 does not match current runtime sources; rebuild the matching development ISO first")
    return digest(path)


def copy(source, target, executable=False):
    regular(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if executable else 0o644)


def prepare(args):
    source = args.runtime.resolve(strict=True)
    sums = regular(source / "SHA256SUMS").read_bytes()
    entries = {}
    for line in sums.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match is None:
            raise ValueError("Malformed runtime SHA256SUMS")
        name = safe_path(match[2])
        if "/" in name or name in entries or name == "SHA256SUMS":
            raise ValueError("Duplicate or nested runtime checksum path: " + name)
        entries[name] = match[1]
    if not entries or len(entries) > 1024:
        raise ValueError("Invalid runtime checksum inventory size")
    images = [name for name in entries if name.endswith(".iso")]
    if len(images) != 1 or not images[0].endswith("-" + PLATFORMS[args.platform][0] + ".iso"):
        raise ValueError("Expected exactly one checksummed ISO for " + args.platform)
    unexpected = set(entries) - set(EVIDENCE) - set(images)
    if unexpected:
        raise ValueError("Unexpected runtime checksum entries: " + ", ".join(sorted(unexpected)))
    for name in EVIDENCE:
        if name not in entries:
            raise ValueError("Missing checksummed runtime evidence: " + name)
    for name, expected in entries.items():
        if digest(regular(source / name)) != expected:
            raise ValueError("Runtime checksum mismatch: " + name)
    source_id = require_current(source / "host-sources.sha256")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Prepared bundle directory already exists")
    tar = shutil.which("bsdtar") or shutil.which("tar")
    if tar is None:
        raise ValueError("Install bsdtar/libarchive for ISO extraction when building")
    image = source / images[0]
    with image.open("rb") as file:
        file.seek(32769)
        if file.read(5) != b"CD001":
            raise ValueError("Runtime image is not an ISO9660 image")
    listing = subprocess.run([tar, "-tf", str(image)], check=True, capture_output=True).stdout.decode("utf-8").splitlines()
    members = {}
    for name in ("live/vmlinuz", "live/initrd.img"):
        matches = [item for item in listing if item in (name, "./" + name)]
        if len(matches) != 1:
            raise ValueError("ISO must contain exactly one " + name)
        members[name] = matches[0]
    args.output.mkdir(parents=True, mode=0o700)
    copy(image, args.output / "runtime/controller.iso")
    for name, target in (("live/vmlinuz", "kernel"), ("live/initrd.img", "initrd")):
        with (args.output / "runtime" / target).open("xb") as file:
            subprocess.run([tar, "-xOf", str(image), members[name]], check=True, stdout=file)
        if (args.output / "runtime" / target).stat().st_size == 0:
            raise ValueError("Empty ISO boot asset: " + name)
    for name in EVIDENCE:
        copy(source / name, args.output / "evidence/runtime" / name)
    copy(source / "SHA256SUMS", args.output / "evidence/runtime/SHA256SUMS")
    # The original checksum filename and the renamed immutable image stay linked.
    (args.output / "evidence/runtime-image.json").write_text(json.dumps({
        "format": "oblivion-desktop-runtime-input", "version": 1,
        "platform": args.platform, "image": images[0], "image_sha256": entries[images[0]],
        "sha256sums_sha256": hashlib.sha256(sums).hexdigest(), "source_sha256": source_id,
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    print(source_id)


def assemble(args):
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{0,63}", args.product_version) or "~dev" not in args.product_version:
        raise ValueError("An explicit ASCII development version containing ~dev is required")
    if (args.prepared / "bundle.json").exists() or (args.prepared / "bundle.json").is_symlink():
        raise ValueError("Prepared bundle already has a manifest")
    source_id = require_current(args.prepared / "evidence/runtime/host-sources.sha256")
    evidence = json.loads((args.prepared / "evidence/runtime-image.json").read_text(encoding="ascii"))
    if evidence["platform"] != args.platform or evidence["source_sha256"] != source_id:
        raise ValueError("Prepared runtime platform or source identity mismatch")
    if digest(args.prepared / "runtime/controller.iso") != evidence["image_sha256"]:
        raise ValueError("Prepared runtime image checksum mismatch")
    for source, target in ((args.cli, "oblivion"), (args.helper, "oblivion-vm"), (args.manager, "oblivion-manager")):
        copy(source, args.prepared / "bin" / target, executable=True)
    if args.manager_assets.is_symlink() or not args.manager_assets.is_dir():
        raise ValueError("Manager assets must be a directory")
    for entry in args.manager_assets.rglob("*"):
        mode = entry.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        copy(entry, args.prepared / "lib/manager" / safe_path(entry.relative_to(args.manager_assets).as_posix()))
    for name in ("LICENSE", "NOTICE"):
        copy(REPO / name, args.prepared / "licenses/oblivion" / name)
    for name in MANAGER_LICENSES:
        copy(REPO / "packages/oblivion-manager/node_modules" / name / "LICENSE",
             args.prepared / "licenses" / name.removeprefix("@").replace("/", "-") / "LICENSE")
    copy(REPO / "script/oblivion/desktop/install.sh", args.prepared / "install.sh", executable=True)
    copy(REPO / "docs/DESKTOP.md", args.prepared / "docs/DESKTOP.md")
    required = ("bin/oblivion", "bin/oblivion-vm", "bin/oblivion-manager",
                "runtime/controller.iso", "runtime/kernel", "runtime/initrd",
                "lib/manager/" + PLATFORMS[args.platform][2],
                "lib/manager/licenses/oblivion/LICENSE", "lib/manager/licenses/termcn/LICENSE")
    for name in required:
        if regular(args.prepared / name).stat().st_size == 0:
            raise ValueError("Empty required bundle file: " + name)
    files = []
    for entry in args.prepared.rglob("*"):
        mode = entry.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        regular(entry)
        files.append({"path": safe_path(entry.relative_to(args.prepared).as_posix()),
                      "sha256": digest(entry), "bytes": entry.stat().st_size,
                      "executable": bool(mode & 0o111)})
    if not files or len(files) > 1024:
        raise ValueError("Bundle must contain between 1 and 1024 files")
    manifest = {"format": "oblivion-desktop", "version": 1, "development_only": True,
                "product_version": args.product_version, "platform": args.platform,
                "backend": PLATFORMS[args.platform][1], "source_sha256": source_id,
                "control_protocol": 1, "assets": "lib/manager",
                "runtime": {"image": "runtime/controller.iso", "kernel": "runtime/kernel", "initrd": "runtime/initrd"},
                "files": sorted(files, key=lambda item: item["path"])}
    manifest["bundle_id"] = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > 1024 * 1024:
        raise ValueError("Bundle manifest exceeds 1 MiB")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Bundle output already exists: " + str(args.output))
    (args.prepared / "bundle.json").write_bytes(encoded)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    os.rename(args.prepared, args.output)
    print(args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="Verify source-image evidence before compiling any host component")
    prep.add_argument("--runtime", required=True, type=Path)
    prep.add_argument("--platform", required=True, choices=PLATFORMS)
    prep.add_argument("--output", required=True, type=Path)
    build = commands.add_parser("assemble", help="Package the verified image and native build outputs")
    build.add_argument("--prepared", required=True, type=Path)
    build.add_argument("--platform", required=True, choices=PLATFORMS)
    build.add_argument("--product-version", required=True)
    for name in ("cli", "helper", "manager", "manager-assets", "output"):
        build.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        (prepare if args.command == "prepare" else assemble)(args)
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
