#!/usr/bin/python3 -B
"""Exercise the real OnionShare worker with a read-only root and no network.

Run the onionshare-test target as UID 1000, cap-drop ALL, with private tmpfs
mounts at /tmp and /run/oblivion-onion. No Tor, provider or personal files.
"""
import contextlib
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
import zipfile

ROOT = Path("/run/oblivion-onion")
PYTHON = "/opt/oblivion-onionshare/bin/python"
SERVICE = "/usr/lib/oblivion/onion/service.py"
CANARY = b"Oblivion OnionShare synthetic private bytes - not a log"


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(ROOT / "http/service.sock"))


class Worker:
    def __init__(self):
        self.control, child = socket.socketpair()
        self.control.settimeout(15)
        self.reader = self.control.makefile("rb")
        self.process = subprocess.Popen([
            PYTHON, "-I", "-B", SERVICE, "--control-fd", str(child.fileno()),
        ], pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
        child.close()

    def command(self, value):
        self.control.sendall(json.dumps(value).encode() + b"\n")
        return self.read()

    def read(self):
        line = self.reader.readline(512 * 1024)
        if not line.endswith(b"\n"):
            raise AssertionError(f"Worker closed its control channel: exit={self.process.poll()}")
        return json.loads(line)

    def start(self, mode, max_bytes=65536, max_files=32, ttl=30):
        return self.command({"op": "start", "mode": mode, "max_bytes": max_bytes,
                             "max_files": max_files, "ttl_seconds": ttl})

    def close(self, eof=False):
        if self.process.poll() is None:
            if eof:
                self.control.shutdown(socket.SHUT_RDWR)
            else:
                response = self.command({"op": "stop"})
                if not response["ok"]:
                    raise AssertionError(response)
        self.reader.close()
        self.control.close()
        output, errors = self.process.communicate(timeout=10)
        if output or errors:
            raise AssertionError("Worker wrote to stdout/stderr")
        return self.process.returncode


def http(method, path, body=None, headers=None):
    connection = UnixHTTP("localhost", timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def multipart(files):
    boundary = b"oblivion-synthetic-boundary"
    body = b"".join(
        b"--" + boundary + b'\r\nContent-Disposition: form-data; name="file[]"; filename="'
        + name.encode() + b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
        + data + b"\r\n" for name, data in files
    )
    return body + b"--" + boundary + b"--\r\n", {"Content-Type": "multipart/form-data; boundary=" + boundary.decode()}


class OnionShareTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.getuid(), 0)
        self.assertEqual(list(ROOT.iterdir()), [])
        self.worker = None

    def tearDown(self):
        if self.worker is not None:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, AssertionError):
                self.worker.close()
            if self.worker.process.poll() is None:
                self.worker.process.kill()
                self.worker.process.communicate(timeout=5)
        for path in ROOT.iterdir():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()

    def start(self, mode, **options):
        self.worker = Worker()
        response = self.worker.start(mode, **options)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["status"]["state"], "serving")
        self.assertTrue((ROOT / "http/service.sock").is_socket())
        self.assertEqual((ROOT / "http/service.sock").stat().st_mode & 0o777, 0o600)

    def freeze(self):
        response = self.worker.command({"op": "freeze"})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["status"]["state"], "frozen")
        self.assertFalse((ROOT / "http/service.sock").exists())
        return response["status"]

    def test_locked_bundle_has_provenance_licenses_and_no_installer(self):
        manifest = json.loads(Path("/opt/oblivion-onionshare/inventory.json").read_text())
        self.assertEqual(manifest["upstream"]["version"], "2.7")
        self.assertGreater(len(manifest["components"]), 40)
        self.assertEqual(manifest["requirements_sha256"], hashlib.sha256(Path("/opt/oblivion-onionshare/requirements.lock").read_bytes()).hexdigest())
        upstream = next(value for value in manifest["components"] if value["name"] == "onionshare-cli")
        self.assertEqual(upstream["sha256"], manifest["upstream"]["wheel_sha256"])
        for value in manifest["components"]:
            self.assertRegex(value["sha256"], "^[a-f0-9]{64}$")
            self.assertTrue(value["url"].startswith("https://files.pythonhosted.org/"))
            self.assertTrue(value["licenses"], value["name"])
            for license in value["licenses"]:
                self.assertEqual(hashlib.sha256((Path("/opt/oblivion-onionshare") / license["path"]).read_bytes()).hexdigest(), license["sha256"])
        self.assertFalse(Path("/opt/oblivion-onionshare/bin/pip").exists())

    def test_share_download_range_and_path_boundaries(self):
        (ROOT / "share").mkdir(mode=0o700)
        (ROOT / "share/città.txt").write_bytes(CANARY)
        self.start("share")
        (ROOT / "home/hidden.txt").write_bytes(b"not-selected-private-canary")
        status, headers, body = http("GET", "/download")
        self.assertEqual(status, 200)
        self.assertEqual(body, CANARY)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        status, headers, body = http("GET", "/download", headers={"Range": "bytes=3-12"})
        self.assertEqual(status, 206)
        self.assertEqual(body, CANARY[3:13])
        for value in (f"bytes={len(CANARY)}-", "bytes=3-1", "bytes=invalid", "bytes=0-1,3-4"):
            self.assertEqual(http("GET", "/download", headers={"Range": value})[0], 416)
        status, headers, body = http("GET", "/download", headers={"Range": f"bytes=-{len(CANARY)+10}"})
        self.assertEqual(body, CANARY)
        for path in ("/../home/hidden.txt", "/%2e%2e/home/hidden.txt", "/etc/passwd", "/download?path=/etc/passwd"):
            status, headers, body = http("GET", path)
            self.assertNotIn(b"not-selected-private-canary", body)
            self.assertNotIn(b"root:x:", body)
        self.freeze()
        self.assertEqual(self.worker.close(), 0)
        self.worker = None
        self.assertEqual(list(ROOT.iterdir()), [])

    def test_share_archive_uses_upstream_zip(self):
        (ROOT / "share/nested").mkdir(mode=0o700, parents=True)
        (ROOT / "share/a.txt").write_bytes(CANARY)
        (ROOT / "share/nested/b.txt").write_bytes(b"second synthetic file")
        self.start("share")
        status, headers, body = http("GET", "/download")
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            self.assertEqual(archive.read("a.txt"), CANARY)
            self.assertEqual(archive.read("nested/b.txt"), b"second synthetic file")

    def test_share_range_progress_counts_only_served_bytes(self):
        (ROOT / "share").mkdir(mode=0o700)
        (ROOT / "share/selected.txt").write_bytes(CANARY)
        self.start("share")
        status, headers, body = http("GET", "/download", headers={"Range": "bytes=3-12"})
        self.assertEqual(status, 206)
        self.assertEqual(body, CANARY[3:13])
        status = self.freeze()
        self.assertEqual(status["transferred_bytes"], 10)
        self.assertEqual(status["bytes"], len(CANARY))

    def test_receive_freezes_complete_files_before_review(self):
        self.start("receive")
        body, headers = multipart([("città.txt", CANARY), ("../../escape.txt", b"untrusted bytes")])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 200)
        status = self.freeze()
        self.assertEqual(status["files"], 2)
        paths = [ROOT / "receive" / value["path"] for value in status["received"]]
        self.assertEqual({path.name for path in paths}, {"citta.txt", "escape.txt"})
        self.assertEqual({path.read_bytes() for path in paths}, {CANARY, b"untrusted bytes"})
        self.assertFalse((ROOT / "escape.txt").exists())
        self.assertFalse((ROOT / "imports").exists())
        self.assertFalse(any(path.suffix == ".log" for path in ROOT.rglob("*")))

    def test_receive_lifetime_byte_quota(self):
        self.start("receive", max_bytes=4096)
        body, headers = multipart([("first.bin", b"a" * 3000)])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 200)
        body, headers = multipart([("second.bin", b"b" * 1500)])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 413)
        status = self.freeze()
        self.assertEqual(status["bytes"], 3000)
        self.assertEqual(status["files"], 1)
        self.assertGreater(status["rejected"], 0)
        self.assertEqual([path.name for path in (ROOT / "receive").rglob("*") if path.is_file()], ["first.bin"])

    def test_receive_handoff_exits_without_losing_files_for_approval(self):
        self.start("receive")
        body, headers = multipart([("approved-later.txt", CANARY)])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 200)
        response = self.worker.command({"op": "handoff"})
        self.assertTrue(response["ok"], response)
        self.worker.process.wait(timeout=10)
        self.assertEqual(self.worker.close(), 0)
        self.worker = None
        self.assertFalse((ROOT / "http/service.sock").exists())
        paths = [ROOT / "receive" / value["path"] for value in response["status"]["received"]]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].read_bytes(), CANARY)
        self.assertFalse((ROOT / "imports").exists())

    def test_receive_partial_suffix_collision_cannot_replace_another_file(self):
        self.start("receive")
        body, headers = multipart([("report.part", CANARY), ("report", b"different bytes")])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 400)
        status = self.freeze()
        self.assertEqual(status["files"], 0)
        self.assertFalse(any(path.is_file() for path in (ROOT / "receive").rglob("*")))

    def test_receive_unexpected_fields_are_not_left_outside_the_review_list(self):
        self.start("receive")
        body, headers = multipart([("accepted.txt", CANARY), ("unlisted.txt", b"not in file array")])
        body = body.replace(b'name="file[]"; filename="unlisted.txt"', b'name="other"; filename="unlisted.txt"')
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 200)
        status = self.freeze()
        self.assertEqual(status["files"], 1)
        self.assertEqual([path.name for path in (ROOT / "receive").rglob("*") if path.is_file()], ["accepted.txt"])

    def test_receive_duplicate_names_malformed_body_and_file_quota(self):
        self.start("receive", max_files=2)
        body, headers = multipart([("same.txt", CANARY), ("same.txt", b"overwrite")])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 400)
        body, headers = multipart([("unfinished.txt", CANARY)])
        self.assertIn(http("POST", "/upload-ajax", body[:-45], headers)[0], (200, 400, 413))
        body, headers = multipart([("third.txt", CANARY)])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 413)
        status = self.freeze()
        self.assertEqual(status["files"], 0)
        self.assertFalse(any(path.is_file() for path in (ROOT / "receive").rglob("*")))

    def test_disconnect_and_control_owner_death_remove_staging(self):
        self.start("receive")
        client = socket.socket(socket.AF_UNIX)
        client.connect(str(ROOT / "http/service.sock"))
        body, headers = multipart([("unfinished.txt", CANARY)])
        client.sendall(b"POST /upload-ajax HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30000\r\n"
                       + b"Content-Type: " + headers["Content-Type"].encode() + b"\r\n\r\n" + body[:100])
        client.close()
        self.assertEqual(self.worker.close(eof=True), 0)
        self.worker = None
        self.assertEqual(list(ROOT.iterdir()), [])

    def test_share_refuses_links_and_oversized_selection(self):
        for kind in ("symlink", "hardlink", "oversized"):
            with self.subTest(kind=kind):
                (ROOT / "share").mkdir(mode=0o700)
                target = ROOT / "share/selected.txt"
                target.write_bytes(CANARY)
                if kind == "symlink":
                    (ROOT / "share/link").symlink_to("/etc/passwd")
                if kind == "hardlink":
                    (ROOT / "share/link").hardlink_to(target)
                self.worker = Worker()
                response = self.worker.start("share", max_bytes=1 if kind == "oversized" else 65536)
                self.assertFalse(response["ok"])
                self.assertIn(response["error"], ("invalid_source", "source_limit"))
                self.worker.process.wait(timeout=10)
                self.assertEqual(self.worker.close(), 1)
                self.worker = None
                self.assertEqual(list(ROOT.iterdir()), [])

    def test_expiry_stops_http_and_deletes_unapproved_uploads(self):
        self.start("receive", ttl=1)
        body, headers = multipart([("temporary.txt", CANARY)])
        self.assertEqual(http("POST", "/upload-ajax", body, headers)[0], 200)
        self.assertEqual(self.worker.read(), {"ok": False, "error": "expired"})
        self.worker.process.wait(timeout=10)
        self.assertEqual(self.worker.close(), 0)
        self.worker = None
        self.assertEqual(list(ROOT.iterdir()), [])

    def test_persistent_runtime_is_refused_without_cleanup(self):
        sys.path.insert(0, str(Path(SERVICE).parent))
        from service import Service, Refused
        service = Service(Path("/fixture-persistent"))
        with self.assertRaisesRegex(Refused, "runtime_not_volatile"):
            service.start({"op": "start", "mode": "receive", "max_bytes": 1024,
                           "max_files": 1, "ttl_seconds": 10})
        service.stop()
        self.assertEqual(Path("/fixture-persistent/canary").read_text(), "preserve me\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
