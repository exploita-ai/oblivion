import importlib.util
import os
from pathlib import Path
import select
import socket
import tempfile
import threading
import time
import unittest


spec = importlib.util.spec_from_file_location(
    "safe_relay", Path(__file__).parents[1] / "guest/safe-tools-relay.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
OFFERED = {"version": 1, "kind": "capabilities", "operations": ["safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"], "limit": relay.LIMIT}


class Protocol(unittest.TestCase):
    def test_typed_request_rejects_guest_authority_and_response_mismatch(self):
        request = {"version": 1, "request_id": "1" * 32,
                   "call": {"operation": "safe-status", "offset": 0}}
        self.assertEqual(relay.request(request), request)
        with self.assertRaises(ValueError):
            relay.request({**request, "safe_id": "2" * 32})
        with self.assertRaises(ValueError):
            relay.response({"version": 1, "request_id": "2" * 32, "ok": True, "result": {}}, "1" * 32)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED") and os.geteuid() in (0, 1000), "Linux Safe user required")
    def test_discovery_stays_responsive_and_busy_never_forwards_a_second_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "tools.sock")
            host, guest = socket.socketpair()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(8)

            def serve():
                try:
                    relay.serve(guest.fileno(), listener, OFFERED)
                except EOFError:
                    pass

            server = threading.Thread(target=serve, daemon=True)
            server.start()

            def connect():
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(path)
                self.assertEqual(relay.read_frame(client.fileno(), time.monotonic() + 2), OFFERED)
                return client

            first = connect()
            request = {"version": 1, "request_id": "1" * 32,
                       "call": {"operation": "safe-create", "agent": "codex", "task": "explicit task"}}
            relay.write_frame(first.fileno(), request, time.monotonic() + 2)
            self.assertEqual(relay.read_frame(host.fileno(), time.monotonic() + 2), request)
            # Discovery is independent of the in-flight host RPC.
            with connect():
                pass
            with connect() as second:
                duplicate = {**request, "request_id": "2" * 32}
                relay.write_frame(second.fileno(), duplicate, time.monotonic() + 2)
                busy = relay.read_frame(second.fileno(), time.monotonic() + 2)
                self.assertEqual(busy["error"], "safe_tools_busy")
                self.assertEqual(busy["request_id"], "2" * 32)
                self.assertFalse(select.select([host], [], [], 0)[0])
            # The first caller disappears after the request was committed.
            first.close()
            relay.write_frame(host.fileno(), {"version": 1, "request_id": "1" * 32,
                              "ok": True, "result": {"id": "3" * 32, "state": "awaiting-start"}}, time.monotonic() + 2)
            # A subsequent status must receive its own response, never the
            # abandoned creation response. Busy is a read-only local rejection.
            deadline = time.monotonic() + 2
            while True:
                self.assertLess(time.monotonic(), deadline)
                client = connect()
                status = {"version": 1, "request_id": "4" * 32,
                          "call": {"operation": "safe-status", "offset": 0}}
                relay.write_frame(client.fileno(), status, deadline)
                ready, _, _ = select.select([host, client], [], [], deadline - time.monotonic())
                if host in ready:
                    self.assertEqual(relay.read_frame(host.fileno(), deadline), status)
                    relay.write_frame(host.fileno(), {"version": 1, "request_id": "4" * 32,
                                      "ok": True, "result": {"safe_id": "5" * 32}}, deadline)
                    self.assertEqual(relay.read_frame(client.fileno(), deadline)["result"], {"safe_id": "5" * 32})
                    client.close()
                    break
                self.assertEqual(relay.read_frame(client.fileno(), deadline)["error"], "safe_tools_busy")
                client.close()
            host.close()
            server.join(2)
            self.assertFalse(server.is_alive())
            guest.close()
            listener.close()


if __name__ == "__main__":
    unittest.main()
