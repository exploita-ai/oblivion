"""Exercise the real tagged request reader over a private local socket."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import unittest

spec = importlib.util.spec_from_file_location("agent_channel", Path(__file__).parents[1] / "guest/agent-channel.py")
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)


class Requests(unittest.TestCase):
    def read(self, value):
        payload = json.dumps(value).encode()
        sender, receiver = socket.socketpair()
        with sender, receiver:
            sender.sendall(struct.pack(">I", len(payload)) + payload)
            return channel.request(receiver.fileno())

    def test_exact_native_arguments_and_managed_request(self):
        value = {"kind": "agent", "agent": "codex", "argv": ["--resume", "space ; $HOME", "", "à"], "terminal": None, "managed": None}
        self.assertEqual(self.read(value), value)
        value.update(argv=[], managed={"operation": "start", "job_id": "a"*32, "request_id": "b"*32, "task": "bounded task"})
        self.assertEqual(self.read(value), value)

    def test_workspace_only_accepts_interactive_size(self):
        value = {"kind": "workspace", "terminal": {"rows": 24, "cols": 80}}
        self.assertEqual(self.read(value), value)
        for invalid in (value | {"argv": ["/bin/sh"]}, value | {"agent": "claude"}, value | {"terminal": None}, value | {"terminal": {"rows": True, "cols": 80}}, value | {"terminal": {"rows": 24, "cols": 1001}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.read(invalid)

    def test_no_untagged_or_unknown_compatibility_reader(self):
        value = {"agent": "codex", "argv": [], "terminal": None, "managed": None}
        for invalid in (value, value | {"kind": "shell"}, value | {"kind": "agent", "agent": "opencode"}, value | {"kind": "agent", "managed": {"operation": "inspect", "job_id": "a"*32}, "argv": ["exec"]}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.read(invalid)

    def test_real_channel_reports_relay_failure_without_an_agent_exit(self):
        sender, receiver = socket.socketpair()
        with sender:
            with receiver:
                payload = b"invalid request with synthetic private content"
                sender.sendall(struct.pack(">I", len(payload)) + payload)
                channel.serve(receiver.fileno())
            with sender.makefile("rb") as output:
                diagnostic = b"The agent connection could not be completed.\n"
                self.assertEqual(output.read(6), b"ready\n")
                self.assertEqual(struct.unpack(">BI", output.read(5)), (2, len(diagnostic)))
                self.assertEqual(output.read(len(diagnostic)), diagnostic)
                self.assertEqual(struct.unpack(">BI", output.read(5)), (7, 0))
                self.assertEqual(output.read(), b"")


if __name__ == "__main__":
    unittest.main()
