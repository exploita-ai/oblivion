"""Actual package/notice installation fixtures; no network, provider or ISO build."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "script/oblivion"
spec = importlib.util.spec_from_file_location("install_agents", SCRIPTS / "install-agents.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class Response(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url


class OfficialClients(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oblivion-agent-distribution-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / "root"
        self.root.mkdir()
        self.lock_path = self.work / "install-agents.json"
        self.lock = json.loads((SCRIPTS / "install-agents.json").read_text())
        shutil.copytree(SCRIPTS / "agent-notices", self.work / "agent-notices")
        self.archives = {}
        self.members = {}
        self.requests = []
        for agent, metadata in self.lock["agents"].items():
            for architecture, source in metadata["architectures"].items():
                members = {
                    "package.json": (json.dumps({"name": source["package"], "version": source["version"],
                                                 "license": metadata["distribution"]["package_license"]}) + "\n").encode(),
                    source["executable"]: f'#!/bin/sh\nprintf "%s\\n" "official-fixture {metadata["version"]}"\n'.encode(),
                    "licenses/THIRD_PARTY_NOTICE.txt": b"Synthetic upstream dependency notice\n",
                    "unchanged-resource.txt": b"Original package resource, preserved verbatim\n",
                }
                self.archive(source, members)
                self.members[(agent, architecture)] = members
        self.save()

    def archive(self, source, members):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in members.items():
                entry = tarfile.TarInfo("package/" + name)
                entry.size = len(data)
                entry.mode = 0o644
                archive.addfile(entry, io.BytesIO(data))
        self.archives[source["url"]] = output.getvalue()
        source["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(output.getvalue()).digest()).decode("ascii")

    def save(self):
        self.lock_path.write_text(json.dumps(self.lock) + "\n")

    def open(self, url, timeout):
        self.requests.append(url)
        self.assertEqual(timeout, 60)
        return Response(self.archives[url], url)

    def install(self, agents, architecture="arm64", opener=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return builder.install_selected(self.lock_path, architecture, agents, self.root, True, opener=opener or self.open)

    def test_original_packages_and_required_notices_have_actual_installed_inventory(self):
        evidence = self.install(["codex", "claude", "opencode2"])
        self.assertEqual(evidence["architecture"], "arm64")
        self.assertEqual([client["id"] for client in evidence["clients"]], ["codex", "claude", "opencode2"])
        for client in evidence["clients"]:
            agent = client["id"]
            package = self.root / "usr/lib/oblivion/agents" / agent
            for name, original in self.members[(agent, "arm64")].items():
                self.assertEqual((package / name).read_bytes(), original)
            self.assertEqual((self.root / "usr/lib/oblivion/agents/bin" / agent).resolve(),
                             (package / self.lock["agents"][agent]["architectures"]["arm64"]["executable"]).resolve())
            self.assertEqual(client["executable"]["sha256"], hashlib.sha256((self.root / client["executable"]["path"]).read_bytes()).hexdigest())
            for notice in client["notices"]:
                locked = next(value for value in self.lock["agents"][agent]["distribution"]["notices"]
                              if Path(value["path"]).name == Path(notice["path"]).name)
                self.assertEqual((self.root / notice["path"]).read_bytes(), (self.work / "agent-notices" / locked["path"]).read_bytes())
                self.assertEqual(notice["sha256"], locked["sha256"])
            self.assertEqual(client["upstream_notices"], [{
                "path": f"usr/lib/oblivion/agents/{agent}/licenses/THIRD_PARTY_NOTICE.txt",
                "sha256": hashlib.sha256(b"Synthetic upstream dependency notice\n").hexdigest(),
            }])
        claude = evidence["clients"][1]["distribution"]
        self.assertEqual(claude["category"], "commercial-native")
        self.assertIn("native-authentication-methods-preserved", claude["conditions"])
        self.assertIn("direct-provider-billing", claude["conditions"])
        self.assertEqual(builder.verify_installed(self.root), evidence)

    def test_inventory_contains_only_installed_subset_and_architecture(self):
        evidence = self.install(["codex", "codex"], "amd64")
        self.assertEqual(evidence["architecture"], "amd64")
        self.assertEqual(len(evidence["clients"]), 1)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(evidence["clients"][0]["package"]["version"], "0.159.2-linux-x64")
        self.assertNotIn("claude", (self.root / builder.EVIDENCE).read_text())
        with self.assertRaisesRegex(ValueError, "Unlisted or incomplete"):
            self.install(["codex"], "amd64")
        self.assertEqual(len(self.requests), 1)

    def test_missing_changed_and_downgraded_notice_policies_fail_before_download(self):
        for invalid in ("missing", "changed", "downgrade", "conditions", "required"):
            with self.subTest(invalid=invalid):
                original = json.loads(json.dumps(self.lock))
                policy = self.lock["agents"]["claude"]["distribution"]
                notice = self.work / "agent-notices" / policy["notices"][0]["path"]
                content = notice.read_bytes()
                if invalid == "missing":
                    notice.unlink()
                if invalid == "changed":
                    notice.write_bytes(content + b"changed")
                if invalid == "downgrade":
                    policy["category"] = "permissive"
                if invalid == "conditions":
                    policy["conditions"].remove("native-authentication-methods-preserved")
                if invalid == "required":
                    policy["notices"] = []
                self.save()
                with self.assertRaises(ValueError):
                    self.install(["codex", "claude"])
                self.assertEqual(self.requests, [])
                self.assertFalse((self.root / builder.EVIDENCE).exists())
                self.assertFalse((self.root / "usr/lib/oblivion/agents").exists())
                self.lock = original
                notice.write_bytes(content)
                self.save()

    def test_integrity_package_license_and_official_origin_are_independent_checks(self):
        source = self.lock["agents"]["codex"]["architectures"]["arm64"]
        self.archives[source["url"]] += b"tampered"
        with self.assertRaisesRegex(ValueError, "archive differs"):
            self.install(["codex"])
        members = dict(self.members[("codex", "arm64")])
        members["package.json"] = json.dumps({"name": source["package"], "version": source["version"], "license": "MIT"}).encode()
        self.archive(source, members)
        self.save()
        with self.assertRaisesRegex(ValueError, "identity or license differs"):
            self.install(["codex"])
        with self.assertRaisesRegex(ValueError, "left the official npm registry"):
            self.install(["codex"], opener=lambda url, timeout: Response(self.archives[url], "https://registry.npmjs.org.attacker.invalid/package.tgz"))
        self.assertFalse((self.root / builder.EVIDENCE).exists())
        self.assertFalse((self.root / "usr/lib/oblivion/agents/codex").exists())

    def test_installed_verification_rejects_lost_notices_changed_policy_and_false_evidence(self):
        evidence = self.install(["codex"])
        notice = self.root / evidence["clients"][0]["notices"][0]["path"]
        data = notice.read_bytes()
        notice.unlink()
        with self.assertRaisesRegex(ValueError, "notice is missing or changed"):
            builder.verify_installed(self.root)
        notice.write_bytes(data + b"changed")
        with self.assertRaisesRegex(ValueError, "notice is missing or changed"):
            builder.verify_installed(self.root)
        notice.write_bytes(data)
        policy = self.root / evidence["clients"][0]["policy"]["path"]
        original = policy.read_bytes()
        policy.write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "distribution policy differs"):
            builder.verify_installed(self.root)
        policy.write_bytes(original)
        native = self.root / "usr/lib/oblivion/agents/bin/codex"
        destination = native.readlink()
        native.unlink()
        native.symlink_to("../claude/claude")
        with self.assertRaisesRegex(ValueError, "entrypoint differs"):
            builder.verify_installed(self.root)
        native.unlink()
        native.symlink_to(destination)
        evidence["clients"][0]["executable"]["sha256"] = "0" * 64
        (self.root / builder.EVIDENCE).write_bytes(builder.encoded(evidence))
        with self.assertRaisesRegex(ValueError, "evidence differs"):
            builder.verify_installed(self.root)

    def test_prior_partial_or_unlisted_installation_cannot_be_omitted(self):
        for relative in ("usr/lib/oblivion/agents/claude", "usr/lib/oblivion/agents/bin/claude", "usr/bin/claude"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"Prior interrupted install; preserve these bytes")
                with self.assertRaisesRegex(ValueError, "Unlisted or incomplete"):
                    self.install(["codex"])
                self.assertEqual(path.read_bytes(), b"Prior interrupted install; preserve these bytes")
                self.assertEqual(self.requests, [])
                self.assertFalse((self.root / builder.EVIDENCE).exists())
                path.unlink()
        self.install(["codex"])
        extra = self.root / "usr/lib/oblivion/agents/claude"
        extra.mkdir()
        with self.assertRaisesRegex(ValueError, "Unlisted or incomplete"):
            builder.verify_installed(self.root)

    def test_pinned_notices_are_in_the_consumed_native_source_inventory(self):
        spec = importlib.util.spec_from_file_location("agent_sources", SCRIPTS / "native-bundle/host-sources.py")
        sources = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sources)
        inventory = sources.inventory(REPO / "packages/oblivion-host", SCRIPTS, REPO)
        actual = json.loads((SCRIPTS / "install-agents.json").read_text())
        for agent, metadata in actual["agents"].items():
            builder.notice_inputs(SCRIPTS / "install-agents.json", agent, metadata)
            for notice in metadata["distribution"]["notices"]:
                self.assertIn(notice["sha256"] + "  ../runtime-inputs/agent-notices/" + notice["path"] + "\n", inventory)


if __name__ == "__main__":
    unittest.main()
