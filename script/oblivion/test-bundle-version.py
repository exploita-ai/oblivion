#!/usr/bin/env python3
"""Exercise the shared release naming policy without building artifacts."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).with_name("bundle-version.py")
spec = importlib.util.spec_from_file_location("bundle_version", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = "abcdef012345" + "a" * 28


class BundleVersion(unittest.TestCase):
    def test_all_channels_and_exact_length_boundary(self):
        for channel, version in (("dev", "0.0.0~dev1.abcdef012345"), ("rc", "1.20.300~rc12"), ("stable", "1.0.0")):
            with self.subTest(channel=channel):
                release.validate(channel, version)
        release.validate("stable", "1" * 60 + ".0.0")
        with self.assertRaises(ValueError):
            release.validate("stable", "1" * 61 + ".0.0")

    def test_noncanonical_and_mismatched_versions_are_rejected(self):
        cases = (
            ("dev", "1.0.0"), ("rc", "1.0.0"), ("stable", "1.0.0~rc1"),
            ("dev", "1.0.0~rc1"), ("stable", "v1.0.0"), ("stable", "01.0.0"),
            ("stable", "1.00.0"), ("stable", "1.0.00"), ("stable", "1.0"),
            ("stable", "1.0.0+build"), ("stable", "1.0.0\n"), ("stable", "１.0.0"),
            ("dev", "1.0.0~dev0.abcdef012345"), ("dev", "1.0.0~dev01.abcdef012345"),
            ("dev", "1.0.0~dev1.ABCDEF012345"), ("dev", "1.0.0~dev1.abcdef01234"),
            ("dev", "1.0.0~dev1.abcdef0123456"), ("dev", "1.0.0~dev-fixture"),
            ("rc", "1.0.0~rc0"), ("rc", "1.0.0~rc01"), ("rc", "1.0.0-rc.1"),
            ("release", "1.0.0"), (None, "1.0.0"), ([], "1.0.0"), ("stable", 1),
        )
        for channel, version in cases:
            with self.subTest(channel=channel, version=version), self.assertRaisesRegex(ValueError, "invalid_bundle_channel_or_version"):
                release.validate(channel, version)

    def test_source_refs_resolve_to_one_explicit_channel(self):
        for ref, channel, version in (
            ("refs/heads/dev", "dev", "1.0.0~dev42.abcdef012345"),
            ("refs/heads/release/bundle", "dev", "1.0.0~dev42.abcdef012345"),
            ("refs/pull/17/merge", "dev", "1.0.0~dev42.abcdef012345"),
            ("refs/tags/v2.3.4-rc.12", "rc", "2.3.4~rc12"),
            ("refs/tags/v2.3.4", "stable", "2.3.4"),
        ):
            with self.subTest(ref=ref):
                self.assertEqual(release.resolve(ref, SHA, "42"), {
                    "channel": channel, "product_version": version,
                })
        self.assertEqual(release.resolve("refs/heads/dev", SHA, "1", "2.0.0")["product_version"],
                         "2.0.0~dev1.abcdef012345")

    def test_unknown_or_malformed_refs_and_source_inputs_are_rejected(self):
        for ref in ("dev", "refs/tags/latest", "refs/tags/v01.0.0", "refs/tags/v1.0.0-rc.0",
                    "refs/tags/v1.0.0-rc.01", "refs/tags/v1.0.0~rc1", "refs/tags/v1.0.0-extra",
                    "refs/pull/0/merge", "refs/pull/01/merge", "refs/pull/1/head", "refs/heads/",
                    "refs/heads/.hidden", "refs/heads/a..b", "refs/heads/a//b", "refs/heads/a.lock",
                    "refs/heads/a.", "refs/heads/a/", "refs/heads/a b", "refs/heads/a\nb"):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "invalid_bundle_source_ref"):
                release.resolve(ref, SHA, "42")
        for revision in (SHA.upper(), "a" * 39, "a" * 41, "g" * 40):
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "invalid_bundle_source_revision"):
                release.resolve("refs/heads/dev", revision, "1")
        for number in ("0", "01", "-1", "1.0", "1\n"):
            with self.subTest(number=number), self.assertRaisesRegex(ValueError, "invalid_bundle_run_number"):
                release.resolve("refs/heads/dev", SHA, number)
        with self.assertRaises(ValueError):
            release.resolve("refs/heads/dev", SHA, "1", "1.0.0~rc1")
        with self.assertRaises(ValueError):
            release.resolve("refs/heads/dev", SHA, "1" * 64)

    def test_cli_validation_is_silent_and_resolver_outputs_exact_assignments(self):
        command = [sys.executable, "-B", str(SCRIPT)]
        result = subprocess.run([*command, "validate", "--channel", "stable", "--product-version", "1.0.0"],
                                capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        result = subprocess.run([*command, "resolve", "--ref", "refs/tags/v1.0.0-rc.1",
                                 "--revision", SHA, "--run-number", "2"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "channel=rc\nproduct_version=1.0.0~rc1\n")
        for arguments in (("validate", "--channel", "dev", "--product-version", "1.0.0"),
                          ("validate", "--product-version", "1.0.0"),
                          ("resolve", "--ref", "refs/tags/v1.0.0-rc.0", "--revision", SHA, "--run-number", "1")):
            result = subprocess.run([*command, *arguments], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    @unittest.skipUnless(shutil.which("dpkg"), "requires dpkg")
    def test_debian_orders_development_before_candidate_before_stable(self):
        for earlier, later in (("1.0.0~dev42.abcdef012345", "1.0.0~rc1"),
                               ("1.0.0~rc1", "1.0.0~rc2"), ("1.0.0~rc2", "1.0.0")):
            subprocess.run(["dpkg", "--compare-versions", earlier, "lt", later], check=True)


if __name__ == "__main__":
    unittest.main()
