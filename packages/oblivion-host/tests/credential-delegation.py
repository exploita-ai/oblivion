"""Synthetic profiles only; never inspect the test runner's native accounts."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("delegation", Path(__file__).parents[1] / "guest/credential-delegation.py")
delegation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delegation)


class Delegation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oblivion-credential-fixture-")
        self.vault = Path(self.temporary.name)
        for name in ("home", "config", "state", "workspace"):
            (self.vault / name).mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, value):
        delegation.write_json(self.vault, path, value)

    def export(self, agent, env=None):
        return delegation.export(self.vault, agent, auth_environment=env or {})

    def test_codex_key_and_personal_token_are_independent_native_stores(self):
        for value in ({"kind": "codex-api-key", "key": "synthetic-key-only"},
                      {"kind": "codex-access-token", "token": "at-synthetic-account-only"}):
            path = self.vault / "home/.codex/auth.json"
            path.unlink(missing_ok=True)
            delegation.install(self.vault, value)
            self.assertEqual(self.export("codex"), value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(set(path.parent.iterdir()), {path})
            delegation.install(self.vault, value)
            self.assertFalse((self.vault / "home/.claude").exists())

    def test_managed_oauth_and_custom_routing_never_fall_back_to_api_billing(self):
        self.write("home/.codex/auth.json", {"auth_mode": "chatgpt", "tokens": {"access_token": "fixture-access", "refresh_token": "fixture-refresh"}})
        with self.assertRaisesRegex(delegation.Rejected, "unsupported-oauth"):
            self.export("codex", {"OPENAI_API_KEY": "fixture-unrelated-billing-key"})
        (self.vault / "home/.codex/auth.json").unlink()
        for env in ({"OPENAI_BASE_URL": "https://custom.invalid", "OPENAI_API_KEY": "fixture-key"},
                    {"CODEX_HOME": "/different/profile", "OPENAI_API_KEY": "fixture-key"}):
            with self.assertRaisesRegex(delegation.Rejected, "unsupported-routing"):
                self.export("codex", env)
        (self.vault / "home/.codex/config.toml").write_text('model_provider="custom"\n')
        with self.assertRaisesRegex(delegation.Rejected, "unsupported-routing"):
            self.export("codex", {"OPENAI_API_KEY": "fixture-key"})

    def test_claude_only_projects_identity_env_and_refuses_ambiguous_account(self):
        self.write("home/.claude/settings.json", {"env": {"CLAUDE_CODE_OAUTH_TOKEN": "fixture-setup-token"}, "hooks": {"not": "copied"}})
        value = self.export("claude")
        self.assertEqual(value, {"kind": "claude-setup-token", "token": "fixture-setup-token"})
        with tempfile.TemporaryDirectory(prefix="oblivion-child-fixture-") as child:
            child = Path(child)
            delegation.install(child, value)
            installed = json.loads((child / "home/.claude/settings.json").read_text())
            self.assertEqual(installed, {"env": {"CLAUDE_CODE_OAUTH_TOKEN": "fixture-setup-token"}})
        with self.assertRaisesRegex(delegation.Rejected, "ambiguous-auth"):
            self.export("claude", {"ANTHROPIC_API_KEY": "fixture-api-key"})
        with self.assertRaisesRegex(delegation.Rejected, "unsupported-routing"):
            self.export("claude", {"ANTHROPIC_BASE_URL": "https://custom.invalid"})
        self.write("home/.claude/settings.json", {})
        self.write("home/.claude/.credentials.json", {"claudeAiOauth": {"accessToken": "fixture-only", "refreshToken": "fixture-refresh"}})
        with self.assertRaisesRegex(delegation.Rejected, "unsupported-oauth"):
            self.export("claude")

    def test_conflicts_and_symlinks_do_not_replace_existing_native_identity(self):
        first = {"kind": "codex-api-key", "key": "fixture-first-key"}
        delegation.install(self.vault, first)
        with self.assertRaisesRegex(delegation.Rejected, "auth-conflict"):
            delegation.install(self.vault, {"kind": "codex-api-key", "key": "fixture-other-key"})
        self.assertEqual(self.export("codex"), first)
        path = self.vault / "home/.codex/auth.json"
        path.unlink()
        path.symlink_to(self.vault / "workspace/outside.json")
        with self.assertRaises(OSError):
            delegation.install(self.vault, first)
        self.assertFalse((self.vault / "workspace/outside.json").exists())

    def test_opencode_reads_only_selected_native_key_and_explicit_default_model(self):
        self.write("config/opencode/opencode.json", {"model": "openai/gpt-fixture", "mcp": {"never": "copied"}})
        path = self.vault / "state/opencode"
        path.mkdir(mode=0o700)
        db = sqlite3.connect(path / "opencode.db")
        try:
            db.execute("CREATE TABLE credential (id TEXT,integration_id TEXT,active INTEGER,time_created INTEGER,value TEXT)")
            db.executemany("INSERT INTO credential VALUES (?,?,?,?,?)", [("one", "openai", 1, 2, json.dumps({"type": "key", "key": "fixture-selected"})), ("two", "anthropic", 1, 1, json.dumps({"type": "key", "key": "fixture-not-selected"}))])
            db.commit()
            os.chmod(path / "opencode.db", 0o600)
            if Path("/proc/self/fd").exists():
                self.assertEqual(self.export("opencode2"), {"kind": "opencode-key", "integration_id": "openai", "key": "fixture-selected", "model": "openai/gpt-fixture"})
                self.assertEqual(self.export("opencode2", {"OPENAI_API_KEY": "fixture-selected"})["key"], "fixture-selected")
                with self.assertRaisesRegex(delegation.Rejected, "ambiguous-auth"):
                    self.export("opencode2", {"OPENAI_API_KEY": "fixture-different-native-env-key"})
                db.execute("UPDATE credential SET value=? WHERE integration_id='openai'", (json.dumps({"type": "oauth", "refresh": "fixture-only"}),))
                db.commit()
                with self.assertRaisesRegex(delegation.Rejected, "unsupported-oauth"):
                    self.export("opencode2")
            self.write("config/opencode/opencode.json", {"model": "openai/gpt-fixture", "providers": {"openai": {"settings": {"baseURL": "https://custom.invalid"}}}})
            with self.assertRaisesRegex(delegation.Rejected, "unsupported-routing"):
                self.export("opencode2")
        finally:
            db.close()

    def test_opencode_config_and_catalog_environment_never_fall_back_to_old_database(self):
        expected_keys = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "OPENCODE_API_KEY", "XAI_API_KEY", "CEREBRAS_API_KEY", "ABLIT_KEY"}
        self.assertTrue(expected_keys.issubset(delegation.AUTH_ENV["opencode2"]))
        for name in delegation.OPENCODE_ROUTE_ENV:
            for value in ("unqualified-fixture-override", ""):
                with self.assertRaisesRegex(delegation.Rejected, "unsupported-routing"):
                    self.export("opencode2", {name: value, "ABLIT_KEY": "fixture-current-env-key"})
        self.write("config/opencode/opencode.json", {"model": "abliteration-ai/abliterated-model"})
        with self.assertRaisesRegex(delegation.Rejected, "needs-auth"):
            self.export("opencode2", {"ABLIT_KEY": "fixture-env-only-without-native-record"})

    def test_first_native_profile_initialization_preserves_offline_installed_identity(self):
        guest = Path(__file__).parents[1] / "guest"
        common = guest / "agent-profiles/common.sh"
        delegation.install(self.vault, {"kind": "codex-api-key", "key": "fixture-codex-key"})
        delegation.install(self.vault, {"kind": "claude-setup-token", "token": "fixture-setup-token"})
        self.write("config/opencode/opencode.json", {"model": "openai/gpt-fixture"})
        profiles = [("codex", self.vault / "home/.codex/config.toml", "codex.toml"),
                    ("claude", self.vault / "home/.claude/settings.json", "claude.json"),
                    ("opencode2", self.vault / "config/opencode/opencode.json", "opencode2.json")]
        before = (self.vault / "home/.codex/auth.json").read_bytes()
        for agent, destination, filename in profiles:
            subprocess.run(["/bin/sh", "-eu", "-c", '. "$1"; initialize_agent_config "$2" "$3"', "profile-fixture", str(common), str(guest / "agent-profiles" / filename), str(destination)],
                env={"PATH": os.defpath, "HOME": str(self.vault / "home")}, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        spec = importlib.util.spec_from_file_location("native_tools", guest / "native-tools/configure.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        native.configure("claude", self.vault / "home", self.vault / "config")
        native.configure("opencode2", self.vault / "home", self.vault / "config")
        self.assertEqual((self.vault / "home/.codex/auth.json").read_bytes(), before)
        self.assertIn('cli_auth_credentials_store = "file"', (self.vault / "home/.codex/config.toml").read_text())
        self.assertEqual(json.loads((self.vault / "home/.claude/settings.json").read_text())["env"], {"CLAUDE_CODE_OAUTH_TOKEN": "fixture-setup-token"})
        self.assertEqual(json.loads((self.vault / "config/opencode/opencode.json").read_text())["model"], "openai/gpt-fixture")

    def test_effective_cli_overrides_are_not_mistaken_for_default_routing(self):
        for agent, argv in [("codex", ["-c", "model_providers.openai.base_url=fixture"]),
                            ("codex", ["--profile=other"]), ("codex", ["--oss"]),
                            ("claude", ["--settings", "fixture.json"]), ("claude", ["--setting-sources=project"]),
                            ("opencode2", ["--server=http://127.0.0.1:9999"]), ("opencode2", ["run", "-m", "different/model"])]:
            self.assertTrue(delegation.route_overrides(agent, argv))
        self.assertFalse(delegation.route_overrides("codex", ["exec", "--json", "-"]))
        self.assertFalse(delegation.route_overrides("opencode2", ["run", "--standalone", "--format", "json"]))
        self.assertFalse(delegation.route_overrides("claude", ["--", "--settings"]))
        for agent, filename in [("codex", ".codex/config.toml"), ("claude", ".claude/settings.local.json"), ("opencode2", "opencode.jsonc")]:
            project = self.vault / "workspace" / agent
            project.mkdir()
            nested = project / "nested"
            nested.mkdir()
            self.assertFalse(delegation.project_overrides(self.vault, agent, nested))
            candidate = project / filename
            candidate.parent.mkdir(exist_ok=True)
            candidate.write_text("This content is intentionally not parsed or executed")
            self.assertTrue(delegation.project_overrides(self.vault, agent, nested))
        self.write("config/opencode/opencode.json", {"model": "openai/gpt-fixture", "plugins": ["must-not-run"]})
        with self.assertRaisesRegex(delegation.Rejected, "unsupported-routing"):
            self.export("opencode2")


if __name__ == "__main__":
    unittest.main()
