import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

from native_fixture import codex
from oblivion_history.portable import encode, export_histories

HISTORY = Path(__file__).resolve().parents[1]
GUEST = HISTORY.parent / "oblivion-host/guest"
DRIVER = """
import importlib.util,os,sys
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[2])
spec=importlib.util.spec_from_file_location('share_channel',sys.argv[2]+'/share-channel.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
original=int(sys.argv[3])
if original!=3: os.dup2(original,3);os.close(original)
try:
 if sys.argv[5]=='export': module.export(3,module.Path(sys.argv[4]),copy=sys.argv[6])
 else: module.receive(3,module.Path(sys.argv[4]),copy=sys.argv[6])
except Exception: sys.exit(1)
"""


def exact(stream, size):
    value = bytearray()
    while len(value) < size:
        part = stream.recv(size - len(value))
        if not part:
            raise EOFError()
        value.extend(part)
    return bytes(value)


def frame(stream, value):
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    stream.sendall(struct.pack(">I", len(data)) + data)


def read_frame(stream):
    size, = struct.unpack(">I", exact(stream, 4))
    return json.loads(exact(stream, size))


class ShareChannelTests(unittest.TestCase):
    def vault(self, root, with_chat=True):
        root = root.resolve()
        for name in ("home", "state", "workspace", "imports"):
            (root / name).mkdir(mode=0o700, parents=True)
        chat = codex(root)[0] if with_chat else None
        return root, chat

    def start(self, vault, operation="export"):
        client, server = socket.socketpair()
        client.settimeout(15)
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", DRIVER, str(HISTORY), str(GUEST), str(server.fileno()),
                                  str(vault), operation, os.environ.get("OBLIVION_COPY_TEST_BINARY", "/unused")],
                                 pass_fds=(server.fileno(),), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server.close()
        self.addCleanup(client.close)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        return client, child

    def request(self, chat):
        return {"version": 1, "operation": "plan", "request_id": uuid.uuid4().hex, "paths": ["workspace", "imports"],
                "chat_ids": [chat], "exclude_paths": [], "exclude_chats": [], "include_sensitive_paths": [], "include_sensitive_chats": []}

    def test_cancel_cleans_native_archive_without_touching_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault, chat = self.vault(Path(tmp))
            client, child = self.start(vault)
            request = self.request(chat)
            frame(client, request)
            plan = read_frame(client)
            generated = vault / "state/.oblivion-share" / request["request_id"]
            self.assertTrue((generated / "chats.jsonl").is_file())
            frame(client, {"version": 1, "operation": "cancel", "request_id": request["request_id"]})
            self.assertTrue(read_frame(client)["cancelled"])
            self.assertEqual(child.wait(timeout=15), 0)
            self.assertFalse(generated.exists())
            self.assertEqual(len(list((vault / "home/.codex/sessions").rglob("*.jsonl"))), 1)
            self.assertIn("history/chats.jsonl", [entry["path"] for entry in plan["manifest"]])

    def test_disconnect_after_plan_also_cleans_private_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault, chat = self.vault(Path(tmp))
            client, child = self.start(vault)
            request = self.request(chat)
            frame(client, request); read_frame(client)
            client.close()
            self.assertNotEqual(child.wait(timeout=15), 0)
            self.assertFalse((vault / "state/.oblivion-share" / request["request_id"]).exists())

    @unittest.skipUnless(sys.platform == "linux" and os.environ.get("OBLIVION_COPY_TEST_BINARY"), "requires real Linux oblivion-copy binary")
    def test_confirm_streams_real_copy_protocol_and_acknowledges_only_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault, chat = self.vault(Path(tmp))
            (vault / "workspace/résumé.md").write_text("Synthetic shared file\n")
            (vault / "home/auth.json").write_text("SYNTHETIC-CREDENTIAL-MUST-NOT-EXPORT")
            client, child = self.start(vault)
            request = self.request(chat)
            frame(client, request)
            plan = read_frame(client)
            frame(client, {"version": 1, "operation": "confirm", "request_id": request["request_id"], "plan_sha256": plan["plan_sha256"]})
            self.assertEqual(exact(client, 8), b"OBLVCP01")
            size, = struct.unpack(">I", exact(client, 4))
            manifest = exact(client, size)
            self.assertEqual(hashlib.sha256(manifest).hexdigest(), plan["manifest_sha256"])
            entries = json.loads(manifest)
            payload = {}
            for entry in entries:
                if entry["kind"] == "file":
                    content = exact(client, entry["size"])
                    self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"])
                    payload[entry["path"]] = content
            self.assertEqual(exact(client, 8), b"OBLVEND1")
            frame(client, {"id": request["request_id"], "manifest_sha256": plan["manifest_sha256"], "entries": len(entries), "bytes": plan["bytes"]})
            self.assertEqual(exact(client, 7), b"copied\n")
            self.assertFalse((vault / "state/.oblivion-share" / request["request_id"]).exists())
            self.assertEqual(child.wait(timeout=15), 0)
            self.assertEqual(payload["workspace/résumé.md"], b"Synthetic shared file\n")
            self.assertNotIn(b"SYNTHETIC-CREDENTIAL-MUST-NOT-EXPORT", b"".join(payload.values()))

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and os.environ.get("OBLIVION_COPY_TEST_BINARY"), "requires root and real Linux oblivion-copy")
    def test_import_restores_only_original_native_history_and_correct_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault, _ = self.vault(Path(tmp), with_chat=False)
            client, child = self.start(vault, "import")
            request_id = uuid.uuid4().hex
            frame(client, {"version": 1, "operation": "import", "request_id": request_id})
            source, chat = self.vault(Path(tmp) / "source")
            archive = Path(tmp) / "native.jsonl"
            export_histories(source, [chat], archive)
            history = archive.read_bytes()
            contents = {"history/chats.jsonl": history, "workspace/code.txt": b"Imported data"}
            entries = [{"kind": "directory", "path": "history"}, {"kind": "file", "path": "history/chats.jsonl", "size": len(history), "sha256": hashlib.sha256(history).hexdigest()},
                       {"kind": "directory", "path": "workspace"}, {"kind": "file", "path": "workspace/code.txt", "size": 13, "sha256": hashlib.sha256(b"Imported data").hexdigest()}]
            manifest = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode()
            client.sendall(b"OBLVCP01" + struct.pack(">I", len(manifest)) + manifest)
            for entry in entries:
                if entry["kind"] == "file": client.sendall(contents[entry["path"]])
            client.sendall(b"OBLVEND1")
            receipt = read_frame(client)
            self.assertEqual(receipt["id"], request_id)
            self.assertEqual(child.wait(timeout=15), 0)
            self.assertEqual((vault / "workspace/code.txt").read_bytes(), b"Imported data")
            self.assertEqual((vault / "workspace/code.txt").stat().st_uid, 1000)
            transcript = next((vault / "home/.codex/sessions").rglob("*.jsonl"))
            self.assertEqual(transcript.stat().st_uid, 1000)
            self.assertIn("Synthetic native conversation", transcript.read_text())
            self.assertFalse((vault / "home/.claude").exists())
            self.assertFalse((vault / "home/.oblivion-history").exists())
            self.assertFalse((vault / "state/.oblivion-share" / request_id).exists())


if __name__ == "__main__":
    unittest.main()
