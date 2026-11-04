#!/usr/bin/env python3
"""Source-only fixtures: no real ISO boot, VM, provider or host installation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sources = load("source_inventory", REPO / "script/oblivion/native-bundle/host-sources.py")
builder = load("bundle_native", REPO / "script/oblivion/bundle-native.py")


class DesktopBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = [line[66:] for line in sources.inventory(REPO / "packages/oblivion-host", REPO / "script/oblivion", REPO).splitlines()]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oblivion-desktop-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        for name in self.paths:
            if name.startswith("../runtime-inputs/"):
                target = self.repo / "script/oblivion" / name.removeprefix("../runtime-inputs/")
            elif name.startswith("../workspace-inputs/"):
                target = self.repo / name.removeprefix("../workspace-inputs/")
            elif name.startswith("../"):
                target = self.repo / "packages" / name.removeprefix("../")
            else:
                target = self.repo / "packages/oblivion-host" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("source fixture " + name + "\n")
        shutil.copyfile(REPO / "script/oblivion/native-bundle/host-sources.py", self.repo / "script/oblivion/native-bundle/host-sources.py")
        for name in ("script/oblivion/desktop/install.sh", "docs/DESKTOP.md"):
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("distribution fixture\n")
        for name in builder.MANAGER_LICENSES:
            target = self.repo / "packages/oblivion-manager/node_modules" / name / "LICENSE"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("dependency license fixture\n")
        builder.REPO = self.repo
        self.addCleanup(setattr, builder, "REPO", REPO)

    def prepared(self, platform="darwin-arm64"):
        prepared = self.root / "prepared"
        for name, value in (("runtime/controller.iso", b"source fixture, not a bootable image"),
                            ("runtime/kernel", b"kernel fixture"), ("runtime/initrd", b"initrd fixture"),
                            ("evidence/runtime/host-sources.sha256", builder.current_sources())):
            target = prepared / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
        (prepared / "evidence/runtime-image.json").write_text(json.dumps({
            "platform": platform, "source_sha256": builder.digest(prepared / "evidence/runtime/host-sources.sha256"),
            "image_sha256": builder.digest(prepared / "runtime/controller.iso"),
        }))
        assets = self.root / "assets"
        for name in (builder.PLATFORMS[platform][2], "licenses/oblivion/LICENSE", "licenses/termcn/LICENSE"):
            target = assets / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"asset fixture")
        binary = self.root / "binary"
        binary.write_bytes(b"executable fixture")
        return argparse.Namespace(prepared=prepared, platform=platform, product_version="1.0.0~dev-fixture",
                                  cli=binary, helper=binary, manager=binary, manager_assets=assets, output=self.root / "bundle")

    def runtime(self):
        root = self.root / "runtime-input"
        root.mkdir()
        for name in builder.EVIDENCE:
            (root / name).write_bytes(builder.current_sources() if name == "host-sources.sha256" else b"evidence fixture")
        (root / "fixture-arm64.iso").write_bytes(b"not an ISO")
        self.checksums(root)
        return argparse.Namespace(runtime=root, platform="darwin-arm64", output=self.root / "prepare-output")

    def checksums(self, root):
        (root / "SHA256SUMS").write_text("".join(builder.digest(path) + "  " + path.name + "\n"
                                                for path in sorted(root.iterdir()) if path.name != "SHA256SUMS"))

    def test_inventory_matches_relocated_compiler(self):
        compiler = self.root / "compiler"
        shutil.copytree(self.repo / "packages", compiler)
        shutil.move(compiler / "oblivion-host", compiler / "build")
        shutil.copytree(self.repo / "script/oblivion", compiler / "runtime-inputs")
        (compiler / "workspace-inputs").mkdir()
        for name in ("package.json", "bun.lock", "LICENSE", "NOTICE"):
            shutil.copyfile(self.repo / name, compiler / "workspace-inputs" / name)
        self.assertEqual(builder.current_sources().decode("ascii"), sources.inventory(compiler / "build", compiler / "runtime-inputs", compiler / "workspace-inputs"))

    def test_guest_gateway_and_lock_changes_invalidate_sources(self):
        baseline = builder.current_sources()
        for name in ("packages/oblivion-host/guest/prepare.sh", "packages/oblivion-gateway/src/lib.rs", "script/oblivion/install-agents.json"):
            target = self.repo / name
            original = target.read_bytes()
            target.write_bytes(original + b"changed")
            self.assertNotEqual(baseline, builder.current_sources())
            target.write_bytes(original)

    def test_assembly_manifest_identity_and_complete_inventory(self):
        args = self.prepared()
        args.product_version = "1:0.0~dev-fixture"
        builder.assemble(args)
        manifest = json.loads((args.output / "bundle.json").read_text())
        identity = manifest.pop("bundle_id")
        self.assertEqual(identity, hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest())
        paths = [item["path"] for item in manifest["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(set(paths), {file.relative_to(args.output).as_posix() for file in args.output.rglob("*") if file.is_file() and file.name != "bundle.json"})
        for item in manifest["files"]:
            file = args.output / item["path"]
            self.assertEqual(item["sha256"], builder.digest(file))
            self.assertEqual(item["bytes"], file.stat().st_size)
            self.assertEqual(item["executable"], bool(file.stat().st_mode & 0o111))
        self.assertEqual(manifest["source_sha256"], builder.digest(args.output / "evidence/runtime/host-sources.sha256"))
        self.assertTrue(manifest["development_only"])
        self.assertTrue((args.output / "install.sh").is_file())

    def test_assembly_rejects_symlink(self):
        args = self.prepared()
        (args.prepared / "unexpected-link").symlink_to(self.root / "binary")
        with self.assertRaisesRegex(ValueError, "regular file"):
            builder.assemble(args)
        self.assertFalse(args.output.exists())

    def test_linux_assembly_uses_qemu_and_matching_opentui_library(self):
        args = self.prepared("linux-x86_64")
        builder.assemble(args)
        manifest = json.loads((args.output / "bundle.json").read_text())
        self.assertEqual(manifest["platform"], "linux-x86_64")
        self.assertEqual(manifest["backend"], "qemu-kvm")
        self.assertTrue((args.output / "lib/manager/@opentui/core-linux-x64/libopentui.so").is_file())

    def test_assembly_rejects_non_development_version(self):
        args = self.prepared()
        args.product_version = "1.0.0"
        with self.assertRaisesRegex(ValueError, "~dev"):
            builder.assemble(args)

    def test_assembly_rejects_version_outside_reader_bounds(self):
        for version in ("1.0~dev_underscore", "1~dev" + "a" * 60):
            args = self.prepared()
            args.product_version = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "development version"):
                builder.assemble(args)

    def test_preparation_rejects_checksum_mismatch(self):
        args = self.runtime()
        (args.runtime / "client-evidence.json").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            builder.prepare(args)
        self.assertFalse(args.output.exists())

    def test_preparation_rejects_stale_sources(self):
        args = self.runtime()
        (args.runtime / "host-sources.sha256").write_bytes(b"old sources")
        self.checksums(args.runtime)
        with self.assertRaisesRegex(ValueError, "does not match current"):
            builder.prepare(args)
        self.assertFalse(args.output.exists())

    def test_preparation_rejects_unexpected_checksummed_sidecar(self):
        args = self.runtime()
        (args.runtime / "unexpected-user-profile.json").write_bytes(b"private fixture")
        self.checksums(args.runtime)
        with self.assertRaisesRegex(ValueError, "Unexpected runtime checksum entries"):
            builder.prepare(args)
        self.assertFalse(args.output.exists())

    def test_preparation_rejects_non_iso_archive(self):
        args = self.runtime()
        with self.assertRaisesRegex(ValueError, "not an ISO9660"):
            builder.prepare(args)

    def test_unsafe_paths(self):
        for name in ("/absolute", "../outside", "a/./b", "a//b", "a\\b", "nonascii-\N{SNOWMAN}", "line\nbreak", "x" * 513):
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.safe_path(name)

    def test_oversize_file_is_rejected_without_reading_it(self):
        target = self.root / "oversize-sparse-fixture"
        with target.open("wb") as file:
            file.truncate(64 * 1024 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "exceeds 64 GiB"):
            builder.regular(target)


if __name__ == "__main__":
    unittest.main()
