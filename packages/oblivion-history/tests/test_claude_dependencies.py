import json
from pathlib import Path
import tempfile
import unittest

from native_fixture import vault, claude
from oblivion_history.claude_dependencies import collect


class ClaudeDependencies(unittest.TestCase):
    def test_inline_attachments_and_native_sidecars_exclude_profile_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            _, transcript, rows = claude(root)
            rows[0]["message"]["content"] = [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "aGVsbG8="}}]
            native = transcript.parent / transcript.stem
            subagents = native / "subagents"
            subagents.mkdir(parents=True)
            sidecar = subagents / "agent-example.jsonl"
            sidecar.write_text(json.dumps(rows[0]) + "\n")
            results = native / "tool-results"
            results.mkdir()
            output = results / "toolu_example.txt"
            output.write_text("Native tool output")
            (root / "home/.claude/settings.json").write_text("PROFILE-CREDENTIAL-CANARY")
            result = collect(root, transcript, rows)
            self.assertEqual(result["artifacts"], sorted([sidecar, output]))
            self.assertEqual(result["required_paths"], [])
            rows[1]["message"]["content"] = [{"type": "tool_use", "input": {"type": "image", "source": "a code-generation argument"}}]
            self.assertEqual(collect(root, transcript, rows), result)

    def test_file_history_includes_only_referenced_backups_of_workspace_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            _, transcript, rows = claude(root)
            backup = root / "home/.claude/file-history" / transcript.stem / "abc123@v1"
            backup.parent.mkdir(parents=True)
            backup.write_text("Original document")
            rows.append({"type": "file-history-snapshot", "snapshot": {"trackedFileBackups": {"document.txt": {"backupFileName": backup.name}}}})
            self.assertEqual(collect(root, transcript, rows)["artifacts"], [backup])
            rows[-1]["snapshot"]["trackedFileBackups"] = {str(root / "home/.claude/settings.json"): {"backupFileName": backup.name}}
            with self.assertRaisesRegex(ValueError, "unsupported_claude_external_file"):
                collect(root, transcript, rows)

    def test_local_attachment_requires_explicit_file_selection_and_missing_file_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            _, transcript, rows = claude(root)
            document = root / "workspace/document.pdf"
            document.write_bytes(b"%PDF synthetic attachment")
            rows[0]["message"]["content"] = [{"type": "document", "source": {"type": "file", "path": str(document)}}]
            self.assertEqual(collect(root, transcript, rows), {"artifacts": [], "required_paths": ["workspace/document.pdf"]})
            rows[0]["message"]["content"][0]["source"]["path"] = "/vault/workspace/document.pdf"
            self.assertEqual(collect(root, transcript, rows), {"artifacts": [], "required_paths": ["workspace/document.pdf"]})
            document.unlink()
            with self.assertRaises(FileNotFoundError):
                collect(root, transcript, rows)

    def test_provider_file_ids_external_paths_and_symlink_backups_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            _, transcript, rows = claude(root)
            rows[0]["message"]["content"] = [{"type": "document", "source": {"type": "file", "file_id": "file_providerSpecific"}}]
            with self.assertRaisesRegex(ValueError, "unsupported_claude_external_attachment"):
                collect(root, transcript, rows)
            rows[0]["message"]["content"] = "question"
            backup = root / "home/.claude/file-history" / transcript.stem / "abc123@v1"
            backup.parent.mkdir(parents=True)
            backup.symlink_to(root / "workspace/document.txt")
            rows.append({"type": "file-history-snapshot", "snapshot": {"trackedFileBackups": {"document.txt": {"backupFileName": backup.name}}}})
            with self.assertRaisesRegex(ValueError, "claude_dependency_symlink"):
                collect(root, transcript, rows)


if __name__ == "__main__":
    unittest.main()
