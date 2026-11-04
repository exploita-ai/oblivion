#!/usr/bin/env python3
"""Exercise fixed-root native Files dispatch without a VM or production data."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import unittest

spec = importlib.util.spec_from_file_location("file_channel", Path(__file__).resolve().parents[1] / "guest/file-channel.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeFiles(unittest.TestCase):
    def request(self, value):
        sender, receiver = socket.socketpair()
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        data = json.dumps(value).encode()
        sender.sendall(struct.pack(">I", len(data)) + data)
        return module.command(receiver.fileno())

    def test_import_and_recovery_pass_only_bounded_metadata_to_fixed_guest_roots(self):
        for operation in ("import", "status", "recover", "discard"):
            request = {"operation": operation, "id": "a" * 32, "safe_id": "b" * 32, "opening": "c" * 32}
            if operation == "import":
                request["name"] = "project città"
            command, metadata = self.request(request)
            self.assertEqual(command, ["/usr/bin/oblivion-copy", "native-files", "/vault/home/.oblivion-file-staging", "/vault/workspace", "3600000"])
            self.assertEqual(json.loads(metadata), request)
            self.assertNotIn(request["id"], command)

    def test_unknown_fields_bad_ids_and_path_expansion_never_select_another_root(self):
        request = {"operation": "status", "id": "a" * 32, "safe_id": "b" * 32, "opening": "c" * 32}
        for invalid in ({**request, "root": "/etc"}, {**request, "id": "../outside"}, {**request, "opening": None}, {**request, "operation": "remove"},
                        {**request, "operation": "import", "name": "../outside"}, {**request, "operation": "import", "name": ""}):
            with self.assertRaises(ValueError):
                self.request(invalid)

    def test_export_retains_only_explicit_guest_roots(self):
        for root in ("workspace", "imports"):
            command, metadata = self.request({"operation": "export", "root": root})
            self.assertEqual(command, ["/usr/bin/oblivion-copy", "send", "/vault/" + root, "3600000"])
            self.assertIsNone(metadata)
        with self.assertRaises(ValueError):
            self.request({"operation": "export", "root": "home"})


if __name__ == "__main__":
    unittest.main()
