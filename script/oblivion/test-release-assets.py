#!/usr/bin/env python3
"""Verify release delivery with small real files, without building bundles."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release-assets.py")
spec = importlib.util.spec_from_file_location("release_assets", SCRIPT)
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class ReleaseAssets(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="oblivion-release-assets-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def assert_checksum(self, path, name, payload):
        self.assertEqual(path.read_text(encoding="ascii"),
                         f"{hashlib.sha256(payload).hexdigest()}  {name}\n")

    def test_stable_dev_and_rc_names_preserve_every_payload_byte(self):
        for original, published in (
            ("oblivion-1.0.0-darwin-arm64.tar", "oblivion-1.0.0-darwin-arm64.tar"),
            ("oblivion-1.0.0~dev42.abcdef012345-windows-x86_64.zip",
             "oblivion-1.0.0-dev42.abcdef012345-windows-x86_64.zip"),
            ("oblivion-desktop_1.0.0~rc1_amd64.deb", "oblivion-desktop_1.0.0-rc1_amd64.deb"),
        ):
            with self.subTest(name=original):
                source = self.root / original
                payload = b"binary\x00\xff\n" + original.encode("ascii") + b"\r\n"
                source.write_bytes(payload)
                output = self.root / (published + "-output")
                assets.stage(source, output)
                self.assertEqual({path.name for path in output.iterdir()},
                                 {published, published + ".sha256"})
                self.assertEqual((output / published).read_bytes(), payload)
                self.assertEqual(source.read_bytes(), payload)
                self.assert_checksum(output / (published + ".sha256"), published, payload)

    def test_exact_threshold_stays_whole(self):
        source = self.root / "oblivion-1.0.0~rc1.iso"
        payload = bytes(range(8))
        source.write_bytes(payload)
        output = self.root / "output"
        assets.stage(source, output, part_bytes=8)
        self.assertEqual({path.name for path in output.iterdir()},
                         {"oblivion-1.0.0-rc1.iso", "oblivion-1.0.0-rc1.iso.sha256"})
        self.assertEqual((output / "oblivion-1.0.0-rc1.iso").read_bytes(), payload)
        self.assert_checksum(output / "oblivion-1.0.0-rc1.iso.sha256", "oblivion-1.0.0-rc1.iso", payload)

    def test_split_boundaries_checksums_and_documented_reassembly(self):
        for size, lengths in ((9, [8, 1]), (16, [8, 8]), (25, [8, 8, 8, 1])):
            with self.subTest(size=size):
                source = self.root / f"oblivion-{size}~rc1.iso"
                published = f"oblivion-{size}-rc1.iso"
                payload = bytes(range(size))
                source.write_bytes(payload)
                output = self.root / f"output-{size}"
                assets.stage(source, output, part_bytes=8)
                parts = [published + f".part{number:02d}" for number in range(1, len(lengths) + 1)]
                self.assertEqual({path.name for path in output.iterdir()},
                                 {*parts, published + ".sha256", published + ".parts.sha256",
                                  published + ".reassemble.txt"})
                self.assertEqual([(output / name).stat().st_size for name in parts], lengths)
                self.assertEqual(source.read_bytes(), payload)
                self.assert_checksum(output / (published + ".sha256"), published, payload)
                checksums = (output / (published + ".parts.sha256")).read_text(encoding="ascii").splitlines()
                self.assertEqual([line.split("  ", 1)[1] for line in checksums], parts)
                for line in checksums:
                    checksum, name = line.split("  ", 1)
                    self.assertEqual(checksum, hashlib.sha256((output / name).read_bytes()).hexdigest())

                instructions = (output / (published + ".reassemble.txt")).read_text(encoding="ascii")
                commands = [line.strip() for line in instructions.splitlines()]
                self.assertTrue(any(line.startswith("cat ") for line in commands), instructions)
                self.assertTrue(any(line.lower().startswith("copy /b ") for line in commands), instructions)
                self.assertIn(published + ".sha256", instructions)
                self.assertIn(published + ".parts.sha256", instructions)
                if os.name == "nt":
                    command = next(line for line in commands if line.lower().startswith("copy /b "))
                    # copy is a cmd builtin; CRT argv quoting would alter this recipe.
                    invocation = command
                else:
                    command = next(line for line in commands if line.startswith("cat "))
                    invocation = ["/bin/sh", "-c", command]
                result = subprocess.run(invocation, shell=os.name == "nt", cwd=output,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((output / published).read_bytes(), payload)
                self.assert_checksum(output / (published + ".sha256"), published,
                                     (output / published).read_bytes())

    def test_unsafe_filenames_are_rejected_before_staging(self):
        for name in (".hidden.zip", "-option.zip", "has space.zip", "café.zip",
                     "bundle;echo.zip", "bundle&echo.zip", "bundle$HOME.zip", "bundle'quote.zip"):
            with self.subTest(name=name):
                source = self.root / name
                source.write_bytes(b"original")
                output = self.root / "output"
                with self.assertRaises(ValueError):
                    assets.stage(source, output)
                self.assertEqual(source.read_bytes(), b"original")
                self.assertFalse(output.exists())

    def test_invalid_part_limits_are_rejected(self):
        source = self.root / "bundle.zip"
        source.write_bytes(b"original")
        for limit in (0, -1, True, False, 1.5, "8", None, 2**31, 2**31 + 1):
            with self.subTest(limit=limit):
                output = self.root / "output"
                with self.assertRaises(ValueError):
                    assets.stage(source, output, part_bytes=limit)
                self.assertFalse(output.exists())
        self.assertEqual(source.read_bytes(), b"original")

    def test_empty_and_nonregular_sources_are_rejected(self):
        empty = self.root / "empty.zip"
        empty.touch()
        directory = self.root / "directory.zip"
        directory.mkdir()
        for source in (empty, directory):
            with self.subTest(source=source.name), self.assertRaises(ValueError):
                assets.stage(source, self.root / "output")
        self.assertFalse((self.root / "output").exists())

    def test_no_payload_part_or_sidecar_can_overwrite_an_existing_file(self):
        source = self.root / "bundle~rc1.zip"
        payload = b"0123456789"
        source.write_bytes(payload)
        for limit, collisions in (
            (16, ("bundle-rc1.zip", "bundle-rc1.zip.sha256")),
            (8, ("bundle-rc1.zip.part01", "bundle-rc1.zip.part02", "bundle-rc1.zip.sha256",
                 "bundle-rc1.zip.parts.sha256", "bundle-rc1.zip.reassemble.txt")),
        ):
            for name in collisions:
                with self.subTest(limit=limit, collision=name):
                    output = self.root / f"output-{limit}-{name}"
                    output.mkdir()
                    existing = output / name
                    existing.write_bytes(b"do not replace")
                    with self.assertRaises(FileExistsError):
                        assets.stage(source, output, part_bytes=limit)
                    self.assertEqual(existing.read_bytes(), b"do not replace")
                    self.assertEqual({path.name for path in output.iterdir()}, {name})
        self.assertEqual(source.read_bytes(), payload)

    def test_cli_stages_a_real_file_into_an_existing_directory(self):
        source = self.root / "input with spaces" / "bundle~rc1.tar"
        source.parent.mkdir()
        source.write_bytes(b"real CLI payload\x00\xff")
        output = self.root / "release assets"
        output.mkdir()
        (output / "unrelated.txt").write_bytes(b"preserve")
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--input", str(source),
                                 "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "unrelated.txt").read_bytes(), b"preserve")
        self.assertEqual((output / "bundle-rc1.tar").read_bytes(), source.read_bytes())
        self.assert_checksum(output / "bundle-rc1.tar.sha256", "bundle-rc1.tar", source.read_bytes())


if __name__ == "__main__":
    unittest.main()
