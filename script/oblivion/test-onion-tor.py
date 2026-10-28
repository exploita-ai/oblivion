#!/usr/bin/python3 -B
"""Actual Tor ownership/private-service lifecycle, without external networking.

No simulated Tor responses. The production Tor controller is compiled into a
lab-only probe; this fixture starts the pinned Debian daemon as UID 1200 with
its state/cookie in tmpfs. No API keys, private user files or real recipients.
"""
import base64
import contextlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import time
import unittest

VERSION = "0.4.9.14"


class Tor:
    def __init__(self):
        for root in (Path("/run/tor"), Path("/var/lib/tor")):
            for path in root.iterdir():
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        self.process = subprocess.Popen([
            "/usr/bin/setpriv", "--reuid=1200", "--regid=1200", "--clear-groups",
            "/usr/bin/tor", "-f", "/etc/oblivion/onion/torrc",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={})
        deadline = time.monotonic() + 15
        while True:
            try:
                self.control("GETINFO version")
                return
            except (OSError, AssertionError):
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    self.stop()
                    raise AssertionError("Real Tor did not become ready")
                # This waits for a real daemon socket, not a product timer.
                time.sleep(0.02)

    def control(self, command):
        with socket.socket(socket.AF_UNIX) as control:
            control.settimeout(5)
            control.connect("/run/tor/control")
            with control.makefile("rb") as reader:
                cookie = Path("/run/tor/control.authcookie").read_bytes()
                assert len(cookie) == 32
                control.sendall(b"AUTHENTICATE " + cookie.hex().encode() + b"\r\n")
                assert reader.readline(1024) == b"250 OK\r\n"
                control.sendall(command.encode() + b"\r\n")
                lines = []
                while True:
                    line = reader.readline(4096)
                    assert line.startswith(b"250") and len(line) < 4096
                    if line == b"250 OK\r\n":
                        return lines
                    lines.append(line.decode())
                    assert len(lines) < 32

    def stopped(self):
        self.process.wait(timeout=10)
        assert self.process.returncode == 0, "Tor did not shut down cleanly"
        assert not Path("/run/tor/control").exists()

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class Probe:
    def __init__(self):
        self.process = subprocess.Popen(["/usr/bin/oblivion-onion-probe"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={}, bufsize=0)
        self.pending = b""

    def read(self):
        deadline = time.monotonic() + 10
        while b"\n" not in self.pending:
            ready, _, _ = select.select([self.process.stdout], [], [], max(0, deadline - time.monotonic()))
            assert ready, "Probe response deadline expired"
            chunk = os.read(self.process.stdout.fileno(), 4096)
            assert chunk, "Probe exited before its response"
            self.pending += chunk
            assert len(self.pending) <= 4096
        line, self.pending = self.pending.split(b"\n", 1)
        return json.loads(line)

    def send(self, value):
        self.process.stdin.write(json.dumps(value).encode() + b"\n")
        self.process.stdin.flush()

    def finish(self, success=True):
        output, errors = self.process.communicate(timeout=10)
        assert not output and not errors, "Unexpected probe output"
        assert (self.process.returncode == 0) == success

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate(timeout=10)


def public_key():
    # Standard OpenSSL X25519 generation, no hand-written cryptography. The
    # synthetic private key exists only in these pipes/RAM and is never logged.
    private = subprocess.check_output(["openssl", "genpkey", "-algorithm", "X25519"], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private, stderr=subprocess.DEVNULL)
    assert len(public) == 44 and public[:12] == bytes.fromhex("302a300506032b656e032100")
    return base64.b32encode(public[12:]).decode().rstrip("=")


class OnionTorTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.getuid(), 0)
        self.tor = Tor()
        self.probe = None
        self.assertEqual(self.tor.control("GETINFO version"), [f"250-version={VERSION}\r\n"])

    def tearDown(self):
        if self.probe is not None:
            with contextlib.suppress(OSError):
                self.probe.stop()
        self.tor.stop()

    def publish(self):
        self.probe = Probe()
        self.assertEqual(self.probe.read(), {"owned": True, "bootstrap": 0})
        self.probe.send({"operation": "publish", "client_auth": public_key()})
        reply = self.probe.read()
        self.assertEqual(set(reply), {"published", "id"})
        self.assertTrue(reply["published"])
        self.assertRegex(reply["id"], "^[a-z2-7]{56}$")
        return reply["id"]

    def test_real_private_service_is_revoked_and_tor_exits(self):
        self.publish()
        self.probe.send({"operation": "revoke"})
        self.assertEqual(self.probe.read(), {"revoked": True})
        self.probe.finish()
        self.tor.stopped()
        self.assertFalse(list(Path("/var/lib/tor").rglob("hs_ed25519*")))
        self.assertFalse(list(Path("/var/lib/tor").rglob("*.auth")))

    def test_dropping_controller_removes_service_and_stops_real_tor(self):
        self.publish()
        self.probe.send({"operation": "drop"})
        self.assertEqual(self.probe.read(), {"dropped": True})
        self.probe.finish()
        self.tor.stopped()

    def test_sigkill_of_controller_stops_real_tor(self):
        self.publish()
        self.probe.process.send_signal(signal.SIGKILL)
        self.probe.process.wait(timeout=10)
        self.tor.stopped()

    def test_invalid_public_key_fails_closed_without_protocol_injection(self):
        self.probe = Probe()
        self.assertEqual(self.probe.read(), {"owned": True, "bootstrap": 0})
        self.probe.send({"operation": "publish", "client_auth": "A" * 52 + "\r\nSETCONF DisableNetwork=0"})
        output, errors = self.probe.process.communicate(timeout=10)
        self.assertNotEqual(self.probe.process.returncode, 0)
        self.assertEqual(output, b"")
        self.assertEqual(errors, b"onion-probe: failed\n")
        self.tor.stopped()

    def test_each_operation_uses_a_new_service_identity(self):
        first = self.publish()
        self.probe.send({"operation": "revoke"})
        self.assertEqual(self.probe.read(), {"revoked": True})
        self.probe.finish()
        self.tor.stopped()
        self.tor = Tor()
        second = self.publish()
        self.assertNotEqual(first, second)
        self.probe.send({"operation": "drop"})
        self.assertEqual(self.probe.read(), {"dropped": True})
        self.probe.finish()
        self.tor.stopped()


if __name__ == "__main__":
    unittest.main(verbosity=2)
