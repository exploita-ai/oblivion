#!/usr/bin/env python3
"""Package an already paired Linux desktop bundle on matching Debian."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PACKAGE = "oblivion-desktop"
ARCHITECTURES = {
    "amd64": ("linux-x86_64", 62, "qemu-system-x86"),
    "arm64": ("linux-arm64", 183, "qemu-system-arm (>= 1:10.1.0)"),
}
BINARIES = ("bin/oblivion", "bin/oblivion-vm", "bin/oblivion-manager")
BOOT = {"image": "runtime/controller.iso", "kernel": "runtime/kernel", "initrd": "runtime/initrd"}
PACKAGE_FILES = {
    "org.oblivion.desktop.policy": "usr/share/polkit-1/actions/org.oblivion.desktop.policy",
    "oblivion-desktop.conf": "usr/lib/modules-load.d/oblivion-desktop.conf",
    "postinst": "DEBIAN/postinst",
}

spec = importlib.util.spec_from_file_location("bundle_native", HERE.parent / "bundle-native.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def copy_bundle(source, target, platform):
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Expected an assembled bundle directory")
    manifest_path = bundle.regular(source / "bundle.json")
    with manifest_path.open("rb") as reader:
        encoded = reader.read(1024 * 1024 + 1)
    if len(encoded) > 1024 * 1024:
        raise ValueError("Bundle manifest exceeds 1 MiB")
    manifest = json.loads(encoded)
    if (manifest["format"] != "oblivion-desktop" or manifest["version"] != 1
            or manifest["development_only"] is not True or manifest["platform"] != platform
            or manifest["backend"] != "qemu-kvm" or manifest["bundle_id"] != bundle.bundle_identity(manifest)
            or manifest["assets"] != "lib/manager" or manifest["runtime"] != BOOT
            or manifest["control_protocol"] != 1
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["source_sha256"])):
        raise ValueError("Bundle identity or platform does not match the package")
    entries = manifest["files"]
    if not 1 <= len(entries) <= 1024:
        raise ValueError("Invalid bundle inventory size")
    files = {bundle.safe_path(entry["path"]): entry for entry in entries}
    native = "lib/manager/" + bundle.PLATFORMS[platform][2]
    required = {*BINARIES, native, *BOOT.values(), "evidence/runtime/host-sources.sha256", "evidence/runtime-image.json"}
    if len(files) != len(entries) or not required <= files.keys():
        raise ValueError("Missing or duplicate bundle inventory entries")
    directories = {parent.as_posix() for name in files for parent in Path(name).parents if parent != Path(".")}
    seen = set()
    for path in source.rglob("*"):
        name = path.relative_to(source).as_posix()
        mode = path.lstat().st_mode
        if mode & 0o022:
            raise ValueError("Bundle input is writable by other users: " + name)
        if stat.S_ISDIR(mode) and name in directories:
            continue
        if not stat.S_ISREG(mode) or (name not in files and name != "bundle.json"):
            raise ValueError("Unexpected bundle entry: " + name)
        if name != "bundle.json":
            seen.add(name)
    if seen != files.keys():
        raise ValueError("Bundle file missing")
    for name, entry in files.items():
        path = source / name
        if (type(entry["executable"]) is not bool
                or bool(path.stat().st_mode & 0o111) != entry["executable"]
                or name in BINARIES and not entry["executable"]):
            raise ValueError("Bundle executable mode changed: " + name)
        destination = target / name
        bundle.copy(path, destination, entry["executable"])
        if destination.stat().st_size != entry["bytes"] or bundle.digest(destination) != entry["sha256"]:
            raise ValueError("Bundle bytes changed: " + name)
    pairing = json.loads((target / "evidence/runtime-image.json").read_bytes())
    if (pairing["platform"] != platform or pairing["source_sha256"] != manifest["source_sha256"]
            or files["evidence/runtime/host-sources.sha256"]["sha256"] != manifest["source_sha256"]
            or pairing["image_sha256"] != files[BOOT["image"]]["sha256"]):
        raise ValueError("Bundle controller source or image identity changed")
    (target / "bundle.json").write_bytes(encoded)
    return manifest, native


def shared_dependencies(root, binaries, architecture, machine):
    for path in binaries:
        with path.open("rb") as reader:
            header = reader.read(20)
        if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != machine:
            raise ValueError("Expected a native " + architecture + " ELF: " + path.name)
    (root / "debian").mkdir()
    (root / "debian/control").write_text(
        "Source: oblivion-desktop\nSection: utils\nPriority: optional\n"
        "Maintainer: Oblivion development <development@example.invalid>\n\n"
        "Package: oblivion-desktop\nArchitecture: any\nDescription: development desktop launcher\n",
        encoding="ascii",
    )
    command = ["dpkg-shlibdeps", "-O", *("-e" + str(path) for path in binaries)]
    resolved = subprocess.check_output(command, cwd=root, text=True).strip()
    if not resolved.startswith("shlibs:Depends=") or "\n" in resolved:
        raise ValueError("Missing ELF dependency calculation")
    return resolved.removeprefix("shlibs:Depends=")


def evidence(destination, manifest, architecture, revision, dirty):
    destination.mkdir(parents=True)
    inputs = {
        "format": "oblivion-desktop-debian-build", "version": 1, "architecture": architecture,
        "revision": revision, "dirty": dirty, "development_only": True,
        "bundle_id": manifest["bundle_id"], "source_sha256": manifest["source_sha256"],
    }
    (destination / "inputs.json").write_text(json.dumps(inputs, sort_keys=True, indent=2) + "\n", encoding="ascii")
    paths = [HERE / name for name in (*PACKAGE_FILES, "build-package.py")]
    paths += [HERE.parent / name for name in ("build-desktop-deb.sh", "bundle-native.py", "Dockerfile.vm-lab", "Dockerfile.vm-lab.dockerignore")]
    helper = REPO / "packages/oblivion-native-linux"
    paths += [helper / "Cargo.toml", helper / "Cargo.lock"]
    paths += [path for path in (helper / "src").rglob("*") if not path.is_dir()]
    (destination / "packaging-sources.sha256").write_text(
        "".join(f"{bundle.digest(bundle.regular(path))}  {path.relative_to(REPO).as_posix()}\n" for path in sorted(paths)),
        encoding="ascii",
    )


def build(source, architecture, version, revision, dirty, output):
    os.umask(0o022)
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{0,63}", version) or "~dev" not in version:
        raise ValueError("Use an explicit development version containing ~dev")
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", revision):
        raise ValueError("Expected a source commit ID")
    subprocess.run(["dpkg", "--validate-version", version], check=True)
    if subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip() != architecture:
        raise ValueError("Build on Debian matching the desktop package architecture")
    platform, machine, qemu = ARCHITECTURES[architecture]
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{PACKAGE}_{version}_{architecture}.deb"
    checksum = target.with_suffix(".deb.sha256")
    if any(path.exists() or path.is_symlink() for path in (target, checksum)):
        raise ValueError("Desktop package output already exists")
    with tempfile.TemporaryDirectory(prefix=".desktop-package-", dir=output) as temporary:
        work = Path(temporary)
        root = work / "package"
        staged = root / "usr/lib/oblivion-desktop"
        manifest, native = copy_bundle(source, staged, platform)
        if manifest["product_version"] != version:
            raise ValueError("Bundle and desktop package versions differ")
        library_dependencies = shared_dependencies(
            work, [staged / name for name in (*BINARIES, native)], architecture, machine,
        )
        dependencies = ", ".join(filter(None, (qemu, "kmod", "udev", "adduser", "passwd", "pkexec", library_dependencies)))
        entry = root / "usr/bin/oblivion"
        entry.parent.mkdir(parents=True)
        entry.symlink_to("../lib/oblivion-desktop/bin/oblivion")
        for name, destination in PACKAGE_FILES.items():
            bundle.copy(HERE / name, root / destination, name == "postinst")
        evidence(root / "usr/share/doc/oblivion-desktop/build", manifest, architecture, revision, dirty)
        size = sum(path.lstat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink()) // 1024
        (root / "DEBIAN/control").write_text(
            f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: {architecture}\n"
            "Section: utils\nPriority: optional\nMaintainer: Oblivion development <development@example.invalid>\n"
            f"Depends: {dependencies}\n"
            "Recommends: python3-gi, gir1.2-gtk-4.0 (>= 4.6)\n"
            f"Conflicts: oblivion-stack\nInstalled-Size: {size}\n"
            "Homepage: https://github.com/exploita-ai/oblivion\n"
            "Description: Development launcher for the Oblivion desktop privacy runtime\n"
            " Runs the paired controller in a private headless QEMU/KVM virtual machine.\n",
            encoding="ascii",
        )
        package = work / target.name
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(package)], check=True)
        sum_file = work / checksum.name
        sum_file.write_text(f"{bundle.digest(package)}  {target.name}\n", encoding="ascii")
        os.link(package, target)
        os.link(sum_file, checksum)
    print(target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--architecture", choices=ARCHITECTURES, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--dirty", choices=("true", "false"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.source, args.architecture, args.version, args.revision, args.dirty == "true", args.output)
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")
