#!/usr/bin/python3
"""Build a development-only Debian payload from a prepared current runtime.

This validates packaging, not guest bootability, hardware support or permission
to redistribute third-party clients. Install never downloads runtime assets.
"""
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
import tempfile

HERE = Path(__file__).resolve().parent
ROLES = ("session", "gateway", "import", "export", "onion-gateway", "onion-file")
BINARIES = ("oblivion", "oblivion-storage", "oblivion-control", "oblivion-copy")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("Runtime input must be a regular, non-writable-by-others file: " + str(path))
    return info


def elf(path, architecture):
    regular(path)
    with path.open("rb") as source:
        header = source.read(20)
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != {"amd64": 62, "arm64": 183}[architecture]:
        raise ValueError("Runtime executable architecture differs: " + str(path))


def install(source, root, target, mode=0o644):
    regular(source)
    target = root / target.lstrip("/")
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)
    return target


def tree(source, target):
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Runtime tree missing: " + str(source))
    shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)


def manifest(root):
    entries = []
    for path in sorted(root.rglob("*")):
        if path.parts[len(root.parts)] == "DEBIAN":
            continue
        info = path.lstat()
        name = "/" + path.relative_to(root).as_posix()
        value = {"path": name, "uid": 0, "gid": 0, "mode": f"{stat.S_IMODE(info.st_mode):04o}"}
        if stat.S_ISREG(info.st_mode):
            value.update(kind="file", sha256=digest(path), bytes=info.st_size)
        elif stat.S_ISDIR(info.st_mode):
            value.update(kind="directory")
        elif stat.S_ISLNK(info.st_mode):
            # Only the immutable chroot's Debian firmware/data may use links.
            if not name.startswith("/usr/lib/oblivion/vm/qemu-root/"):
                raise ValueError("Unexpected package symlink: " + name)
            value.update(kind="symlink", target=os.readlink(path))
        else:
            raise ValueError("Devices/sockets are not package payload: " + name)
        entries.append(value)
    return {"format": "oblivion-debian-files", "version": 1, "entries": entries,
            "self": "/usr/share/doc/oblivion-stack/files.json",
            "generated_retained": [
                {"path": "/etc/oblivion/controller.json", "uid": 0, "gid": 0, "mode": "0600"},
                {"path": "/etc/tmpfiles.d/oblivion.conf", "uid": 0, "gid": 0, "mode": "0644"},
            ], "data": {"path": "/var/lib/oblivion", "never_remove": True}}


def build(source, architecture, version, output):
    os.umask(0o022)
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", version) or "~dev" not in version:
        raise ValueError("Use an explicit development version containing ~dev")
    subprocess.run(["dpkg", "--validate-version", version], check=True)
    if subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip() != architecture:
        raise ValueError("Build inside Debian matching the package architecture")
    for binary in (*BINARIES, "oblivion-manager"):
        elf(source / "usr/bin" / binary, architecture)
    for role in ROLES:
        for name in ("kernel", "initrd", "root.squashfs"):
            if regular(source / "usr/lib/oblivion/vm" / role / name).st_size == 0:
                raise ValueError("Empty VM asset")
    machine = "aarch64" if architecture == "arm64" else "x86_64"
    elf(source / f"usr/lib/oblivion/vm/qemu-root/usr/bin/qemu-system-{machine}", architecture)
    units = HERE.joinpath("units.txt").read_text().splitlines()
    for unit in units:
        regular(source / "etc/systemd/system" / unit)
    evidence = source / "usr/share/doc/oblivion-stack/build"
    evidence_names = (*[role + "-packages.tsv" for role in ROLES], "qemu-packages.tsv", "client-evidence.json", "host-sources.sha256", "gateway-sources.sha256", "packaging-sources.sha256", "runtime-sources.sha256", "inputs.json")
    for name in evidence_names:
        regular(evidence / name)
    config = json.loads((source / "etc/oblivion/controller.json").read_text())
    if set(config) - {"general_image", "general_mib", "session_mib", "ephemeral_mib", "pbkdf_memory_kib", "manager_uid", "usb_persistence", "gateway_network", "vm", "gateway", "import", "export", "onion"}:
        raise ValueError("Unexpected controller template fields")
    for role in (config["vm"], config["gateway"], config["import"], config["export"], config["onion"]["gateway"], config["onion"]["files"]):
        if set(role) - {"root", "kernel", "initrd", "filesystem", "memory_mib", "cpus", "accelerator"} or role.get("accelerator", "kvm") != "kvm":
            raise ValueError("Unexpected production VM configuration")
        for key in ("root", "kernel", "initrd", "filesystem"):
            path = Path(role[key])
            if not path.is_absolute() or ".." in path.parts or not path.is_relative_to("/usr/lib/oblivion/vm") or not (source / str(path).lstrip("/")).exists():
                raise ValueError("VM configuration points outside packaged assets")
    config.update(general_image="/var/lib/oblivion/general.luks", general_mib=8192,
                  session_mib=2048, usb_persistence=False)
    config.pop("manager_uid", None)
    output.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = output / f"oblivion-stack_{version}_{architecture}.deb"
    if target.exists():
        raise FileExistsError("Refusing to replace an existing package")
    with tempfile.TemporaryDirectory(prefix="oblivion-deb-") as temporary:
        root = Path(temporary) / "payload"
        root.mkdir()
        for binary in BINARIES:
            install(source / "usr/bin" / binary, root, "/usr/bin/" + binary, 0o755)
        tree(source / "usr/lib/oblivion/manager", root / "usr/lib/oblivion/manager")
        native = f"@opentui/core-linux-{'x64' if architecture == 'amd64' else 'arm64'}/libopentui.so"
        for path in (root / "usr/lib/oblivion/manager").rglob("*"):
            if path.is_file() and path.relative_to(root / "usr/lib/oblivion/manager").as_posix() != native and not path.relative_to(root / "usr/lib/oblivion/manager").as_posix().startswith("licenses/"):
                raise ValueError("Unexpected manager asset")
        elf(root / "usr/lib/oblivion/manager" / native, architecture)
        install(source / "usr/bin/oblivion-manager", root, "/usr/lib/oblivion/manager/oblivion-manager", 0o755)
        install(HERE / "manager.sh", root, "/usr/bin/oblivion-manager", 0o755)
        tree(source / "usr/lib/oblivion/vm", root / "usr/lib/oblivion/vm")
        for unit in units:
            install(source / "etc/systemd/system" / unit, root, "/usr/lib/systemd/system/" + unit)
        for name in ("configure.py", "runtime-depends.txt", "units.txt"):
            install(HERE / name, root, "/usr/lib/oblivion/debian/" + name)
        for directory in ("etc/oblivion", "etc/tmpfiles.d", "usr/lib/sysusers.d", "usr/share/oblivion", "var/lib/oblivion"):
            (root / directory).mkdir(mode=0o700 if directory == "var/lib/oblivion" else 0o755, parents=True, exist_ok=True)
        (root / "etc/oblivion/installation.json").write_text('{"version":1,"mode":"direct-controller"}\n')
        (root / "usr/share/oblivion/controller.template.json").write_text(json.dumps(config, indent=2) + "\n")
        module_spec = importlib.util.spec_from_file_location("package_configuration", HERE / "configure.py")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        (root / "usr/lib/sysusers.d/oblivion.conf").write_text("".join(f"u {name} {uid} - /nonexistent /usr/sbin/nologin\n" for uid, name in module.identities()))
        for name in evidence_names:
            install(evidence / name, root, "/usr/share/doc/oblivion-stack/build/" + name)
        for name in ("LICENSE", "NOTICE"):
            install(source / "usr/share/doc/oblivion-stack" / name, root, "/usr/share/doc/oblivion-stack/" + name)
        controls = root / "DEBIAN"
        controls.mkdir()
        for name in ("preinst", "postinst", "prerm", "postrm", "config", "templates"):
            install(HERE / name, root, "/DEBIAN/" + name, 0o644 if name == "templates" else 0o755)
        (controls / "conffiles").write_text("/etc/oblivion/installation.json\n")
        for path in root.rglob("*"):
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o700 if path == root / "var/lib/oblivion" else 0o755)
            else:
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        work = Path(temporary) / "dependencies"
        (work / "debian").mkdir(parents=True)
        (work / "debian/control").write_text("Source: oblivion-stack\nSection: utils\nPriority: optional\nMaintainer: Oblivion development <development@example.invalid>\n\nPackage: oblivion-stack\nArchitecture: any\nDescription: development runtime\n")
        binaries = [root / "usr/bin" / name for name in BINARIES]
        binaries += [root / "usr/lib/oblivion/manager/oblivion-manager"]
        binaries += list((root / "usr/lib/oblivion/manager").rglob("*.so"))
        command = ["dpkg-shlibdeps", "-O", *["-e" + str(path) for path in binaries]]
        dependencies = subprocess.check_output(command, cwd=work, text=True).strip()
        if not dependencies.startswith("shlibs:Depends="):
            raise ValueError("Missing ELF dependency calculation")
        depends = HERE.joinpath("runtime-depends.txt").read_text().splitlines() + [dependencies.removeprefix("shlibs:Depends=")]
        source_packages = set()
        for name in evidence_names:
            if not name.endswith("-packages.tsv"):
                continue
            for line in (evidence / name).read_text().splitlines():
                columns = line.split("\t")
                if len(columns) != 4 or not columns[2] or not columns[3]:
                    raise ValueError("Invalid embedded Debian source inventory")
                source_packages.add(f"{columns[2]} (= {columns[3]})")
        size = sum(path.lstat().st_size for path in root.rglob("*") if stat.S_ISREG(path.lstat().st_mode)) // 1024
        (controls / "control").write_text(f"Package: oblivion-stack\nVersion: {version}\nArchitecture: {architecture}\nSection: utils\nPriority: optional\nMaintainer: Oblivion development <development@example.invalid>\nDepends: {', '.join(depends)}\nBuilt-Using: {', '.join(sorted(source_packages))}\nInstalled-Size: {size}\nHomepage: https://github.com/exploita-ai/oblivion\nDescription: Development privacy stack for isolated CLI agents\n Current-format Debian controller, isolated encrypted Safes and per-Safe gateways.\n This development artifact does not claim hardware qualification or permission\n to redistribute embedded third-party clients. No automatic runtime downloads.\n")
        (root / "usr/share/doc/oblivion-stack/files.json").write_text(json.dumps(manifest(root), indent=2) + "\n")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(target)], check=True)
    (output / (target.name + ".sha256")).write_text(digest(target) + "  " + target.name + "\n")
    print(target.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build(args.source.resolve(), args.architecture, args.version, args.output.resolve())
