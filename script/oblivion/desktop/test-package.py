#!/usr/bin/env python3
"""Build and inspect a real .deb with small, nonbootable assets on Debian."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as xml


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bundle_native", HERE.parent / "bundle-native.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class DesktopPackage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="oblivion-desktop-package-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "bundle"
        self.output = self.root / "output"
        self.arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        platform, triplet, native = {
            "amd64": ("linux-x86_64", "x86_64-linux-gnu", "x64"),
            "arm64": ("linux-arm64", "aarch64-linux-gnu", "arm64"),
        }[self.arch]
        self.version = "1.0.0~dev-fixture"
        for name in ("oblivion", "oblivion-vm", "oblivion-manager"):
            self.copy(Path("/usr/bin/true"), "bin/" + name)
        self.copy(Path(f"/usr/lib/{triplet}/libm.so.6"), f"lib/manager/@opentui/core-linux-{native}/libopentui.so")
        for name in ("controller.iso", "kernel", "initrd"):
            self.write("runtime/" + name, b"Nonbootable packaging fixture\n")
        sources = b"Controller source evidence fixture\n"
        self.write("evidence/runtime/host-sources.sha256", sources)
        source_id = hashlib.sha256(sources).hexdigest()
        self.write("evidence/runtime-image.json", json.dumps({
            "platform": platform, "source_sha256": source_id,
            "image_sha256": bundle.digest(self.source / "runtime/controller.iso"),
        }).encode("ascii"))
        self.manifest = {
            "format": "oblivion-desktop", "version": 1, "development_only": True,
            "product_version": self.version, "platform": platform, "backend": "qemu-kvm",
            "source_sha256": source_id, "control_protocol": 1, "assets": "lib/manager",
            "runtime": {"image": "runtime/controller.iso", "kernel": "runtime/kernel", "initrd": "runtime/initrd"},
        }
        self.seal()

    def write(self, name, contents):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)

    def copy(self, source, name):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, path)
        path.chmod(0o755 if name.startswith("bin/") else 0o644)

    def seal(self):
        self.manifest["files"] = [
            {"path": path.relative_to(self.source).as_posix(), "sha256": bundle.digest(path),
             "bytes": path.stat().st_size, "executable": bool(path.stat().st_mode & 0o111)}
            for path in sorted(self.source.rglob("*")) if path.is_file() and path.name != "bundle.json"
        ]
        self.manifest["bundle_id"] = bundle.bundle_identity(self.manifest)
        self.write("bundle.json", json.dumps(self.manifest, sort_keys=True).encode("ascii"))

    def build(self):
        return subprocess.run([
            sys.executable, "-B", str(HERE / "build-package.py"), "--source", str(self.source),
            "--architecture", self.arch, "--version", self.version, "--revision", "1" * 40,
            "--dirty", "false", "--output", str(self.output),
        ], capture_output=True, text=True)

    def test_actual_package_has_native_entry_dependencies_and_only_desktop_payload(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        package = self.output / f"oblivion-desktop_{self.version}_{self.arch}.deb"
        checksum = package.with_suffix(".deb.sha256")
        self.assertEqual(checksum.read_text(), f"{bundle.digest(package)}  {package.name}\n")
        info = subprocess.check_output(["dpkg-deb", "--field", package], text=True)
        self.assertIn("Package: oblivion-desktop\n", info)
        self.assertIn(f"Architecture: {self.arch}\n", info)
        self.assertIn("Conflicts: oblivion-stack\n", info)
        expected_qemu = "qemu-system-x86" if self.arch == "amd64" else "qemu-system-arm (>= 1:10.1.0)"
        for dependency in (expected_qemu, "libc6 (>=", "kmod", "udev", "adduser", "passwd", "pkexec"):
            self.assertIn(dependency, info)
        payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", package])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            paths = {entry.name.removeprefix("./"): entry for entry in archive}
            self.assertTrue(all((entry.uid, entry.gid) == (0, 0) for entry in paths.values()))
            self.assertEqual(paths["usr/bin/oblivion"].linkname, "../lib/oblivion-desktop/bin/oblivion")
            self.assertEqual(paths["usr/lib/oblivion-desktop/bin/oblivion-vm"].mode, 0o755)
            self.assertFalse(any("systemd/system" in name or name.startswith(("var/lib", "etc/oblivion")) for name in paths))
            installed = archive.extractfile(paths["usr/lib/oblivion-desktop/bundle.json"]).read()
            self.assertEqual(installed, (self.source / "bundle.json").read_bytes())
            evidence = json.load(archive.extractfile(paths["usr/share/doc/oblivion-desktop/build/inputs.json"]))
            self.assertEqual(evidence["bundle_id"], self.manifest["bundle_id"])
            self.assertEqual(evidence["source_sha256"], self.manifest["source_sha256"])
            inputs = archive.extractfile(paths["usr/share/doc/oblivion-desktop/build/packaging-sources.sha256"]).read()
            self.assertIn(b"packages/oblivion-native-linux/src/kvm.rs", inputs)
            policy = xml.parse(archive.extractfile(paths["usr/share/polkit-1/actions/org.oblivion.desktop.policy"]))
            action = policy.find("action[@id='org.oblivion.desktop.enroll']")
            self.assertEqual(action.findtext("annotate[@key='org.freedesktop.policykit.exec.path']"), "/usr/lib/oblivion-desktop/bin/oblivion-vm")
            self.assertEqual(action.findtext("annotate[@key='org.freedesktop.policykit.exec.argv1']"), "enroll")
            self.assertEqual(action.findtext("defaults/allow_active"), "auth_admin")
            self.assertEqual(archive.extractfile(paths["usr/lib/modules-load.d/oblivion-desktop.conf"]).read(), b"vhost_vsock\n")
        before = checksum.read_bytes()
        self.assertNotEqual(self.build().returncode, 0)
        self.assertEqual(checksum.read_bytes(), before)

    def test_rejects_foreign_elf_even_when_bundle_hashes_match(self):
        helper = self.source / "bin/oblivion-vm"
        executable = bytearray(helper.read_bytes())
        executable[18:20] = (183 if self.arch == "amd64" else 62).to_bytes(2, "little")
        helper.write_bytes(executable)
        self.seal()
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected a native", result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_wrong_controller_even_when_bundle_hashes_match(self):
        self.write("runtime/controller.iso", b"Changed controller fixture")
        self.seal()
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("controller source or image identity changed", result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
