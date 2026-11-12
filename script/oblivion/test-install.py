#!/usr/bin/env python3
"""Exercise the bootstrap's file boundaries without downloads or installation."""
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "install.sh"
spec = importlib.util.spec_from_file_location("release_assets", Path(__file__).with_name("release-assets.py"))
release_assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_assets)


class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oblivion-install-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def shell(self, function, *args):
        return subprocess.run(
            ["/bin/bash", "-c", 'source "$1"; shift; "$@"', "fixture", str(INSTALLER), function, *map(str, args)],
            capture_output=True, text=True,
        )

    def archive(self, name, kind=tarfile.REGTYPE, target=""):
        path = self.root / "fixture.tar"
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.linkname = target
            data = b"synthetic bundle file\n" if kind == tarfile.REGTYPE else b""
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        return path

    def test_help_works_from_file_and_pipe_without_network(self):
        result = subprocess.run(["/bin/bash", str(INSTALLER), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(["/bin/bash", "-s", "--", "--help"], input=INSTALLER.read_text(), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--version", result.stdout)

    def test_only_current_stable_or_explicit_rc_tags_map_to_product_versions(self):
        for tag, expected in (("v1.0.0", "1.0.0"), ("v1.12.3", "1.12.3"), ("v1.0.0-rc.2", "1.0.0~rc2")):
            result = self.shell("release_version", tag)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
        for tag in ("v0.1.0-beta.3", "v2.0.0", "dev", "v1.0.0-rc.0", "v1.0.0-rc.02", "v1.00.0", "v1.0.0/path", "v1.0.0\n"):
            with self.subTest(tag=tag):
                self.assertNotEqual(self.shell("release_version", tag).returncode, 0)

    def test_release_packer_checksums_are_accepted_with_exact_names(self):
        source = self.root / "oblivion-1.0.0~rc2-darwin-arm64.tar"
        source.write_bytes(bytes(range(256)) * 9)
        staged = self.root / "staged"
        release_assets.stage(source, staged, part_bytes=1024)
        delivery = source.name.replace("~", "-")
        checksum = (staged / (delivery + ".sha256")).read_text().rstrip("\n")
        result = self.shell("checksum_digest", checksum, delivery)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(self.shell("verify_digest", source, result.stdout).returncode, 0)
        for index, line in enumerate((staged / (delivery + ".parts.sha256")).read_text().splitlines(), 1):
            name = delivery + f".part{index:02d}"
            result = self.shell("checksum_digest", line, name)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.shell("verify_digest", staged / name, result.stdout).returncode, 0)
            self.assertNotEqual(self.shell("checksum_digest", line, delivery + ".part99").returncode, 0)
        source.write_bytes(b"changed fixture")
        self.assertNotEqual(self.shell("verify_digest", source, checksum[:64]).returncode, 0)

    def test_checksum_records_reject_extra_names_or_commands(self):
        digest = "a" * 64
        name = "oblivion-1.0.0-darwin-arm64.tar"
        for line in (digest + "  ../outside", digest + "  " + name + " extra", digest + " *" + name,
                     digest + "  " + name + "\n" + digest + "  second", "$(touch outside)  " + name):
            with self.subTest(line=line):
                self.assertNotEqual(self.shell("checksum_digest", line, name).returncode, 0)
        self.assertFalse((self.root / "outside").exists())

    def test_archive_accepts_regular_files_with_expected_root(self):
        root = "oblivion-1.0.0~rc2-darwin-arm64"
        path = self.archive(root + "/lib/manager/@opentui/file with spaces")
        result = self.shell("validate_archive", path, root, self.root)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_archive_rejects_traversal_links_special_files_and_other_roots(self):
        root = "oblivion-1.0.0~rc2-darwin-arm64"
        for name, kind, target in (
            ("outside/file", tarfile.REGTYPE, ""),
            ("/absolute/file", tarfile.REGTYPE, ""),
            (root + "/../outside", tarfile.REGTYPE, ""),
            (root + "/./file", tarfile.REGTYPE, ""),
            (root + "/link", tarfile.SYMTYPE, "../../outside"),
            (root + "/link", tarfile.LNKTYPE, "outside"),
            (root + "/fifo", tarfile.FIFOTYPE, ""),
        ):
            with self.subTest(name=name, kind=kind):
                path = self.archive(name, kind, target)
                result = self.shell("validate_archive", path, root, self.root)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
