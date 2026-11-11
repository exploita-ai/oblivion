#!/usr/bin/python3
"""Real dpkg lifecycle in a disposable root, with explicitly nonbootable assets."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path("/sources")
PACKAGING = REPO / "script/oblivion/debian"
ROLES = ("session", "gateway", "import", "export", "onion-gateway", "onion-file")


def run(*args, **options):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    if result.returncode:
        raise RuntimeError(f"Fixture command failed: {args!r}\n{result.stdout}\n{result.stderr}")
    return result


def write(path, value, mode=0o644):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(mode)


class PackageLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or not Path("/.oblivion-package-fixture").is_file():
            raise RuntimeError("Use script/oblivion/test-deb.sh in its disposable container")
        if Path("/run/systemd/system").exists() or run("stat", "-f", "-c", "%T", "/run").stdout.strip() != "tmpfs":
            raise RuntimeError("Fixture requires isolated tmpfs /run without a systemd host")
        cls.temporary = tempfile.TemporaryDirectory(prefix="package-fixture-")
        cls.source = Path(cls.temporary.name) / "prepared"
        cls.arch = run("dpkg", "--print-architecture").stdout.strip()
        cls.output = Path(cls.temporary.name) / "output"
        for name in ("oblivion", "oblivion-storage", "oblivion-control", "oblivion-copy"):
            path = cls.source / "usr/bin" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2("/usr/bin/true", path)
        shutil.copy2("/usr/bin/env", cls.source / "usr/bin/oblivion-manager")
        triplet = "aarch64-linux-gnu" if cls.arch == "arm64" else "x86_64-linux-gnu"
        native = cls.source / f"usr/lib/oblivion/manager/@opentui/core-linux-{'arm64' if cls.arch == 'arm64' else 'x64'}/libopentui.so"
        native.parent.mkdir(parents=True)
        shutil.copy2(f"/usr/lib/{triplet}/libm.so.6", native)
        write(cls.source / "usr/lib/oblivion/manager/licenses/FIXTURE.txt", "Packaging fixture; not an OpenTUI build.\n")
        assets = cls.source / "usr/lib/oblivion/vm"
        minimal = Path(cls.temporary.name) / "role"
        write(minimal / "FIXTURE", "Nonbootable packaging fixture. No clients or OS.\n")
        squash = Path(cls.temporary.name) / "role.squashfs"
        run("mksquashfs", str(minimal), str(squash), "-noappend", "-processors", "1", "-quiet")
        evidence = cls.source / "usr/share/doc/oblivion-stack/build"
        for role in ROLES:
            write(assets / role / "kernel", "Nonbootable packaging fixture kernel placeholder\n")
            write(assets / role / "initrd", "Nonbootable packaging fixture initrd placeholder\n")
            shutil.copy2(squash, assets / role / "root.squashfs")
            write(evidence / (role + "-packages.tsv"), "")
        machine = "aarch64" if cls.arch == "arm64" else "x86_64"
        qemu = assets / f"qemu-root/usr/bin/qemu-system-{machine}"
        qemu.parent.mkdir(parents=True)
        shutil.copy2("/usr/bin/true", qemu)
        write(evidence / "qemu-packages.tsv", run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\n", "coreutils").stdout)
        write(evidence / "client-evidence.json", '{"fixture":true,"embedded_agents":[]}\n')
        write(evidence / "inputs.json", '{"fixture":true,"development_only":true,"runtime_qualified":false}\n')
        write(evidence / "unselected-profile.json", '{"fixture":"must not be copied"}\n')
        for name in ("host-sources.sha256", "gateway-sources.sha256", "packaging-sources.sha256", "runtime-sources.sha256"):
            write(evidence / name, hashlib.sha256((PACKAGING / "build-package.py").read_bytes()).hexdigest() + "  packaging-fixture-source\n")
        config = cls.source / "etc/oblivion/controller.json"
        config.parent.mkdir(parents=True)
        shutil.copy2(REPO / "script/oblivion/live-controller.json", config)
        write(cls.source / "etc/fstab", "Unselected OS configuration; must never be packaged.\n")
        for unit in (PACKAGING / "units.txt").read_text().splitlines():
            path = cls.source / "etc/systemd/system" / unit
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / "packages/oblivion-host/host" / unit, path)
        for name in ("LICENSE", "NOTICE"):
            shutil.copy2(REPO / name, cls.source / "usr/share/doc/oblivion-stack" / name)
        run("python3", "-B", str(PACKAGING / "build-package.py"), "--source", str(cls.source), "--architecture", cls.arch,
            "--version", "1.0.0~devfixture1", "--output", str(cls.output))
        cls.package = next(cls.output.glob("*.deb"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_payload_dependency_and_preserved_lifecycle(self):
        info = run("dpkg-deb", "--field", str(self.package)).stdout
        for dependency in (PACKAGING / "runtime-depends.txt").read_text().splitlines():
            self.assertIn(dependency, info)
        self.assertIn("libc6 (>=", info)
        self.assertIn("Built-Using: coreutils (=", info)
        payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(self.package)])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = {"/" + member.name.removeprefix("./").rstrip("/"): member for member in archive if member.name != "."}
            for member in members.values():
                self.assertEqual((member.uid, member.gid), (0, 0))
            actual_units = {Path(name).name for name in members if name.startswith("/usr/lib/systemd/system/") and members[name].isfile()}
            self.assertEqual(actual_units, set((PACKAGING / "units.txt").read_text().splitlines()))
            inventory = json.load(archive.extractfile("./usr/share/doc/oblivion-stack/files.json"))
            for entry in inventory["entries"]:
                self.assertIn(entry["path"], members)
                self.assertEqual(int(entry["mode"], 8), members[entry["path"]].mode)
                if entry["kind"] == "file":
                    self.assertEqual(entry["sha256"], hashlib.sha256(archive.extractfile("." + entry["path"]).read()).hexdigest())
            self.assertEqual({name for name in members if members[name].isfile() and name.startswith("/etc/")}, {"/etc/oblivion/installation.json"})
        self.assertFalse(any("oblivion-display" in name or "control-relay" in name or "/boot/" in name for name in members))
        self.assertNotIn("/usr/share/doc/oblivion-stack/build/unselected-profile.json", members)
        run("useradd", "--uid", "1000", "--shell", "/bin/sh", "oblivion-fixture")
        run("useradd", "--uid", "1100", "--shell", "/usr/sbin/nologin", "occupied-fixture")
        self.assertNotEqual(subprocess.run(["python3", "-I", "-B", str(PACKAGING / "configure.py"), "oblivion-fixture"], capture_output=True).returncode, 0)
        self.assertFalse(Path("/etc/oblivion/controller.json").exists())
        run("userdel", "occupied-fixture")
        os_sentinels = (Path("/etc/default/keyboard"), Path("/etc/timezone"), Path("/etc/NetworkManager/system-connections/fixture.nmconnection"))
        for path in os_sentinels:
            write(path, "Host OS fixture must remain unchanged.\n")
        before = {path: path.read_bytes() for path in (*os_sentinels, Path("/etc/hosts"), Path("/etc/resolv.conf"))}
        data = Path("/var/lib/oblivion")
        data.mkdir(mode=0o700)
        opaque = b"Encrypted-data-preservation fixture, not a real LUKS volume.\n"
        (data / "general.luks").write_bytes(opaque)
        config = json.loads((self.source / "etc/oblivion/controller.json").read_text())
        config.update(manager_uid=1000, general_image=str(data / "general.luks"), general_mib=4096)
        config_path = Path("/etc/oblivion/controller.json")
        write(config_path, json.dumps(config) + "\n", 0o600)
        original = config_path.read_bytes()
        run("debconf-set-selections", input="oblivion-stack oblivion-stack/manager-user string oblivion-fixture\n")
        environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        run("dpkg", "--install", str(self.package), env=environment)
        self.assertEqual(config_path.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(Path("/etc/oblivion/installation.json").read_text()), {"version": 1, "mode": "controller-runtime"})
        runtime = Path("/run/oblivion-manager")
        self.assertEqual((runtime.stat().st_uid, stat.S_IMODE(runtime.stat().st_mode)), (1000, 0o700))
        output = run("runuser", "--user", "oblivion-fixture", "--", "/usr/bin/oblivion-manager", "--null").stdout
        self.assertIn("OTUI_ASSET_ROOT=/usr/lib/oblivion/manager\0", output)
        self.assertIn("BUN_TMPDIR=/run/oblivion-manager\0", output)
        self.assertEqual(subprocess.run(["python3", "-I", "-B", "/usr/lib/oblivion/debian/configure.py", "root"], capture_output=True).returncode, 1)
        for action in ("--remove", "--purge"):
            run("dpkg", action, "oblivion-stack", env=environment)
            self.assertEqual(config_path.read_bytes(), original)
            self.assertEqual((data / "general.luks").read_bytes(), opaque)
            self.assertTrue(Path("/etc/tmpfiles.d/oblivion.conf").is_file())
            self.assertFalse(Path("/usr/bin/oblivion").exists())
            self.assertEqual(run("id", "--user", "oblivion-vm").stdout.strip(), "1100")
            for path, content in before.items():
                self.assertEqual(path.read_bytes(), content)
        run("debconf-set-selections", input="oblivion-stack oblivion-stack/manager-user string oblivion-fixture\n")
        run("dpkg", "--install", str(self.package), env=environment)
        self.assertEqual(config_path.read_bytes(), original)
        self.assertEqual((data / "general.luks").read_bytes(), opaque)

    def test_rejects_unversioned_release_and_unexpected_payload(self):
        command = ["python3", "-B", str(PACKAGING / "build-package.py"), "--source", str(self.source), "--architecture", self.arch,
                   "--version", "1.0.0", "--output", str(self.output / "rejected")]
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        path = self.source / "usr/lib/oblivion/manager/UNEXPECTED"
        write(path, "not a permitted asset\n")
        command[command.index("1.0.0")] = "1.0.0~devrejected"
        try:
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse(list((self.output / "rejected").glob("*.deb")))
        finally:
            path.unlink()

    def test_current_inventory_schema_matches_real_dpkg_status(self):
        spec = importlib.util.spec_from_file_location("image_audit", REPO / "script/oblivion/audit-image.py")
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        root = Path(self.temporary.name) / "audit-root"
        write(root / "var/lib/dpkg/status", run("dpkg-query", "-s", "coreutils").stdout)
        image = Path(self.temporary.name) / "audit.squashfs"
        run("mksquashfs", str(root), str(image), "-noappend", "-processors", "1", "-quiet")
        manifests = Path(self.temporary.name) / "audit-manifests"
        host = run("dpkg-query", "-W", "-f=${Package}\t${Version}\n", "coreutils").stdout
        role = run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\n", "coreutils").stdout
        for name, content in (("host", host), ("session", role)):
            write(manifests / (name + "-packages.tsv"), content)
            work = Path(self.temporary.name) / ("audit-" + name)
            work.mkdir()
            report = audit.inventory(image, name, work, manifests)
            self.assertTrue(report["package_manifest_matches"])
            self.assertEqual(report["package_count"], 1)
            self.assertEqual(report["packages"][0]["source_name"], "coreutils")
            write(manifests / (name + "-packages.tsv"), role if name == "host" else host)
            with self.assertRaises(ValueError):
                audit.match_package_manifest(manifests / (name + "-packages.tsv"), name, report["packages"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
