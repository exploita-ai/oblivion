import json
from pathlib import Path
import tempfile
import unittest
from configure import configure


class ProfileConfig(unittest.TestCase):
    def test_preserves_profiles_and_adds_only_its_server(self):
        for agent, filename, section in [
            ("claude", ".claude.json", "mcpServers"),
            ("opencode2", ".config/opencode/opencode.json", "mcp"),
        ]:
            with self.subTest(agent=agent), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                destination = home / filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                server = {"other": {"disabled": True, "command": "custom"}}
                original = {"provider": {"private": {"model": "custom"}},
                            section: {"servers": server, "custom": True} if agent == "opencode2" else server}
                destination.write_text(json.dumps(original))
                configure(agent, home, home / ".config")
                updated = json.loads(destination.read_text())
                self.assertEqual(updated["provider"], original["provider"])
                servers = updated[section]["servers"] if agent == "opencode2" else updated[section]
                self.assertEqual(servers["other"], server["other"])
                self.assertIn("oblivion", servers)
                if agent == "opencode2":
                    self.assertTrue(updated[section]["custom"])
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                before = destination.read_bytes()
                configure(agent, home, home / ".config")
                self.assertEqual(destination.read_bytes(), before)

    def test_respects_existing_disabled_server(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            destination = home / ".claude.json"
            original = '{"mcpServers":{"oblivion":{"disabled":true}},"theme":"dark"}\n'
            destination.write_text(original)
            configure("claude", home, home / ".config")
            self.assertEqual(destination.read_text(), original)

    def test_rejects_invalid_profile_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            destination = home / ".claude.json"
            destination.write_text('{"mcpServers":[]}')
            with self.assertRaises(ValueError):
                configure("claude", home, home / ".config")
            self.assertEqual(destination.read_text(), '{"mcpServers":[]}')


if __name__ == "__main__":
    unittest.main()
