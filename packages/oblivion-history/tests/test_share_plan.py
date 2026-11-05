import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from native_fixture import claude, codex, opencode
from oblivion_history.portable import encode

spec = importlib.util.spec_from_file_location("share_plan", Path(__file__).resolve().parents[2] / "oblivion-host/guest/share_plan.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SharePlanTests(unittest.TestCase):
    def vault(self, root):
        root = root.resolve()
        for name in ("home", "state", "workspace", "imports"):
            (root / name).mkdir(mode=0o700)
        return root

    def request(self, **values):
        return {"version": 1, "operation": "plan", "request_id": uuid.uuid4().hex,
                "paths": ["workspace", "imports"], "chat_ids": [], "exclude_paths": [], "exclude_chats": [],
                "include_sensitive_paths": [], "include_sensitive_chats": [], **values}

    def test_positive_scope_default_exclusions_and_explicit_sensitive_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            secret = b"sk-publicfixturecredential123456789"
            (vault / "home/auth.json").write_bytes(secret)
            (vault / "workspace/code.py").write_text("print('safe')")
            (vault / "workspace/.env").write_bytes(b"API_KEY=" + secret)
            (vault / "workspace/.npmrc").write_text("registry=https://example.invalid")
            (vault / "workspace/.git").mkdir()
            (vault / "workspace/.git/config").write_text("credential.helper=store")
            (vault / "workspace/auth.json").write_bytes(secret)
            (vault / "workspace/.ssh").mkdir()
            (vault / "workspace/.ssh/id_rsa").write_bytes(secret)
            (vault / "workspace/escape").symlink_to(vault / "home")
            plan = module.Plan(vault, self.request())
            paths = {entry["path"] for entry in plan.public["manifest"]}
            self.assertIn("workspace/code.py", paths)
            for excluded in ("workspace/.env", "workspace/.npmrc", "workspace/.git/config", "workspace/auth.json", "workspace/.ssh", "workspace/escape"):
                self.assertNotIn(excluded, paths)
            self.assertNotIn(secret.decode(), json.dumps(plan.public))
            self.assertFalse((vault / "state/.oblivion-share").exists())
            with self.assertRaisesRegex(ValueError, "share_plan_not_approved"):
                plan.approve(plan.request["request_id"], "0" * 64)
            approved = plan.approve(plan.request["request_id"], plan.plan_sha256)
            self.assertEqual(approved["aliases"], ["workspace/code.py"])
            plan.close()
            plan = module.Plan(vault, self.request(include_sensitive_paths=["workspace/.env"]))
            self.assertIn("workspace/.env", {entry["path"] for entry in plan.public["manifest"]})
            plan.close()

    def test_native_chat_selection_is_filtered_and_cancel_only_removes_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            secret = "sk-publicfixturecredential123456789"
            chat, transcript, rows = codex(vault, text=secret)
            (vault / "home/.codex/session_index.jsonl").write_text(
                encode({"id": rows[0]["payload"]["id"], "thread_name": secret}) + "\n"
            )
            plan = module.Plan(vault, self.request(chat_ids=[chat]))
            self.assertEqual(plan.public["chats"], [])
            self.assertNotIn("history/chats.jsonl", {entry["path"] for entry in plan.public["manifest"]})
            plan.close()
            plan = module.Plan(vault, self.request(chat_ids=[chat], include_sensitive_chats=[chat]))
            self.assertEqual(plan.public["chats"], [{"id": chat, "agent": "codex", "title": None}])
            self.assertNotIn(secret, json.dumps(plan.public))
            self.assertIn("history/chats.jsonl", {entry["path"] for entry in plan.public["manifest"]})
            generated = plan.stage / "chats.jsonl"
            self.assertTrue(generated.is_file())
            plan.close()
            self.assertFalse(generated.exists())
            self.assertTrue(transcript.is_file())

    def test_review_lists_included_native_titles_in_selection_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            codex_id, _, _ = codex(vault, text="DO-NOT-USE-AS-TITLE")
            claude_id, _, _ = claude(vault)
            opencode_id, _ = opencode(vault)
            plan = module.Plan(vault, self.request(chat_ids=[opencode_id, claude_id, codex_id]))
            self.assertEqual(plan.public["chats"], sorted([
                {"id": codex_id, "agent": "codex", "title": None},
                {"id": claude_id, "agent": "claude", "title": "Claude research"},
                {"id": opencode_id, "agent": "opencode2", "title": "Native OpenCode chat"},
            ], key=lambda entry: entry["id"]))
            self.assertNotIn("DO-NOT-USE-AS-TITLE", json.dumps(plan.public))
            review = {key: value for key, value in plan.public.items() if key != "plan_sha256"}
            self.assertEqual(plan.plan_sha256, hashlib.sha256(module.encode(review)).hexdigest())
            plan.close()

    def test_review_title_omits_controls_bidi_and_oversize_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            chat, transcript, rows = claude(vault)
            for title in (" \t", "name\u0085next", "name\u061c", "name\u202e", "name\u2028next", "é" * 129, "é" * 128):
                rows[-1]["customTitle"] = title
                transcript.write_text("".join(encode(row) + "\n" for row in rows))
                plan = module.Plan(vault, self.request(chat_ids=[chat]))
                self.assertEqual(plan.public["chats"][0]["title"], title if title == "é" * 128 else None)
                plan.close()

    def test_explicitly_excluded_codex_prefix_refuses_selected_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            parent, parent_transcript, parent_rows = codex(vault)
            child, child_transcript, child_rows = codex(vault)
            physical_id = str(uuid.uuid4())
            parent_rollout = parent_transcript.with_name(
                parent_transcript.name.replace(parent_rows[0]["payload"]["id"], physical_id)
            )
            parent_transcript.rename(parent_rollout)
            prefix = b"".join(parent_rollout.read_bytes().splitlines(keepends=True)[:2])
            child_rows[0]["payload"]["history_base"] = {
                "thread_id": physical_id,
                "end_ordinal_exclusive": 2,
                "end_byte_offset": len(prefix),
            }
            child_transcript.write_text("".join(encode(row) + "\n" for row in child_rows))
            plan = module.Plan(vault, self.request(chat_ids=[child]))
            self.assertEqual([entry["id"] for entry in plan.public["chats"]], [child])
            self.assertIn({"reason": "native_history_dependency_included", "chat_id": child, "included": True},
                          plan.public["warnings"])
            plan.close()
            denied = self.request(chat_ids=[child], exclude_chats=[parent])
            with self.assertRaisesRegex(ValueError, "^share_excluded_chat_required$"):
                module.Plan(vault, denied)
            self.assertFalse((vault / "state/.oblivion-share" / denied["request_id"]).exists())
            self.assertTrue(parent_rollout.is_file())
            self.assertTrue(child_transcript.is_file())

    def test_native_attachment_must_be_explicitly_selected_in_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            selected, transcript, rows = claude(vault)
            document = vault / "workspace/document.pdf"
            document.write_bytes(b"%PDF synthetic native attachment")
            rows[0]["message"]["content"] = [{"type": "document", "source": {"type": "file", "path": "/vault/workspace/document.pdf"}}]
            transcript.write_text("".join(encode(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "share_native_dependency_not_selected"):
                module.Plan(vault, self.request(paths=[], chat_ids=[selected]))
            plan = module.Plan(vault, self.request(paths=["workspace/document.pdf"], chat_ids=[selected]))
            self.assertEqual(plan.public["chats"], [{"id": selected, "agent": "claude", "title": "Claude research"}])
            self.assertIn("workspace/document.pdf", {entry["path"] for entry in plan.public["manifest"]})
            plan.close()

    def test_explicit_credential_subtree_and_host_path_are_not_share_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            (vault / "workspace/.ssh").mkdir()
            (vault / "workspace/.ssh/id_rsa").write_text("never read")
            plan = module.Plan(vault, self.request(paths=["workspace/.ssh/id_rsa"]))
            self.assertEqual(plan.public["manifest"], [{"kind": "directory", "path": "workspace"}])
            plan.close()
            for invalid in ("home", "workspace/../../home", "/etc", "workspace\\auth"):
                with self.assertRaises(ValueError):
                    module.Plan(vault, self.request(paths=[invalid]))

    def test_over_limit_sparse_source_is_rejected_before_opening_or_hashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            source = vault / "workspace/sparse.bin"
            with source.open("wb") as file:
                file.truncate(module.MAX_BYTES + 1)
            with patch.object(module.os, "fdopen", side_effect=AssertionError("over-limit source was opened")):
                with self.assertRaisesRegex(ValueError, "share_content_limit"):
                    module.Plan(vault, self.request())
            self.assertFalse((vault / "state/.oblivion-share").exists())

    def test_growing_real_file_is_read_only_to_initial_size_plus_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = self.vault(Path(tmp))
            source = vault / "workspace/growing.bin"
            source.write_bytes(b"original")
            fdopen = os.fdopen
            consumed = []

            class GrowingReader:
                def __init__(self, descriptor, mode):
                    self.file = fdopen(descriptor, mode)
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    self.file.close()
                def fileno(self):
                    return self.file.fileno()
                def read(self, size):
                    with source.open("ab") as writer:
                        writer.write(b"x" * 65536)
                    block = self.file.read(size)
                    consumed.append(len(block))
                    return block

            with patch.object(module.os, "fdopen", GrowingReader):
                with self.assertRaisesRegex(ValueError, "share_source_changed"):
                    module.Plan(vault, self.request())
            self.assertEqual(sum(consumed), len(b"original") + 1)
            self.assertFalse((vault / "state/.oblivion-share").exists())


if __name__ == "__main__":
    unittest.main()
