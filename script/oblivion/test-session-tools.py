#!/usr/bin/env python3
"""Exercise the real Debian session tools with only loopback fixture servers.

Run in the session-tools-test image with --network none, a read-only root and
tmpfs /vault, /tmp and /run. This does not qualify the gateway firewall or Tor.
"""
import base64
from functools import partial
import http.server
import io
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import tarfile
import tempfile
import threading
import unittest
import zipfile

GUEST = Path("/usr/lib/oblivion/guest")
AUTH = "Basic " + base64.b64encode(b"oblivion-tools:" + b"a" * 64).decode()


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        stream = self.request.makefile("rb")
        method, target, _ = stream.readline(8192).decode().split()
        headers = {}
        while line := stream.readline(8192):
            if line == b"\r\n":
                break
            key, value = line.decode().split(":", 1)
            headers[key.lower()] = value.strip()
        if headers.get("proxy-authorization") != AUTH:
            self.request.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="oblivion"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
            return
        self.server.observed.append((method, target))
        if self.server.deny or method != "CONNECT" or target != self.server.target:
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        with socket.create_connection(("127.0.0.1", self.server.destination), timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            try:
                while ready := select.select([self.request, upstream], [], [], 5)[0]:
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.request else self.request).sendall(data)
            except (ConnectionResetError, BrokenPipeError):
                # TLS rejection deliberately closes a still-active tunnel.
                return


class HTTP(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


class SessionToolsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 1000:
            raise RuntimeError("Run this test as the unprivileged session user")
        Path("/vault/workspace").mkdir(parents=True, exist_ok=True)
        Path("/vault/home").mkdir(parents=True, exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(prefix=".tools-test-", dir="/vault/workspace")
        cls.root = Path(cls.directory.name)
        cls.cache = tempfile.TemporaryDirectory(prefix="oblivion-tools-cache-", dir="/tmp")
        cls.environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/vault/home", "TERM": "xterm-256color",
            "XDG_CACHE_HOME": cls.cache.name, "TMPDIR": "/tmp",
            "XDG_CONFIG_HOME": "/vault/config", "XDG_STATE_HOME": "/vault/state", "XDG_DATA_HOME": "/vault/state",
        }

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()
        cls.cache.cleanup()

    def command(self, *command, input=None, cwd=None, env=None, check=True):
        result = subprocess.run(
            ["/bin/sh", "-ec", '. "$1"; shift; exec "$@"', "tools-test", str(GUEST / "session-environment.sh"), *command],
            cwd=cwd or self.root, env=self.environment | (env or {}), input=input,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[:1500])
        return result

    def test_manifest_matches_image_and_runtime_controls(self):
        manifest = json.loads(self.command("oblivion-tools", "--json").stdout)
        self.assertEqual(manifest["format_version"], 1)
        self.assertTrue(all(Path(path).is_file() for path in manifest["commands"].values()))
        self.assertTrue({"curl", "node", "npm", "python3", "pdftotext", "nano", "jq"} <= manifest["commands"].keys())
        self.assertTrue({"python3-venv", "poppler-utils"} <= manifest["packages"].keys())
        self.assertEqual(self.command("node", "--version").stdout.decode().strip(), "v" + manifest["components"]["node"]["version"])
        self.assertEqual(self.command("npm", "--version").stdout.decode().strip(), manifest["components"]["node"]["npm"])
        self.assertTrue(manifest["components"]["node"]["npm_packages"])
        environment = json.loads(self.command("python3", "-c", "import json,os; print(json.dumps(dict(os.environ)))").stdout)
        for name in ("HISTFILE", "LESSHISTFILE", "SQLITE_HISTORY", "NODE_REPL_HISTORY", "PYTHON_HISTORY"):
            self.assertEqual(environment[name], "/dev/null")
        self.assertEqual(environment["npm_config_logs_max"], "0")
        self.assertEqual(environment["npm_config_audit"], "false")
        self.assertEqual(environment["npm_config_update_notifier"], "false")
        self.assertEqual(environment["NODE_USE_ENV_PROXY"], "1")
        self.assertTrue(environment["npm_config_cache"].startswith("/tmp/"))
        self.assertTrue(environment["PIP_CACHE_DIR"].startswith("/tmp/"))
        self.assertTrue(environment["npm_config_prefix"].startswith("/vault/home/"))
        self.assertEqual(self.command("npm", "config", "get", "logs-max").stdout.strip(), b"0")
        self.assertEqual(self.command("npm", "config", "get", "audit").stdout.strip(), b"false")
        self.assertEqual(self.command("node", "-e", "process.stdout.write(String(typeof fetch))").stdout, b"function")

    def test_files_archives_json_sqlite_and_pdf(self):
        work = self.root / "files"
        work.mkdir()
        (work / "sample.txt").write_text("Oblivion UTF-8: città\n")
        self.command("zip", "-q", "sample.zip", "sample.txt", cwd=work)
        self.assertEqual(self.command("unzip", "-p", "sample.zip", "sample.txt", cwd=work).stdout.decode(), (work / "sample.txt").read_text())
        self.assertIn(b"text/plain", self.command("file", "--mime-type", "sample.txt", cwd=work).stdout)
        self.assertIn(b"sample.txt", self.command("tree", "--noreport", cwd=work).stdout)
        self.assertEqual(self.command("jq", "-cS", ".", input=b'{"b":2,"a":1}').stdout, b'{"a":1,"b":2}\n')
        self.assertEqual(self.command("sqlite3", "sample.db", "create table t (value text); insert into t values ('ok'); select value from t;", cwd=work).stdout, b"ok\n")
        document = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        contents = b"BT /F1 12 Tf 20 100 Td (Oblivion PDF fixture) Tj ET"
        objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                   b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
                   b"<< /Length " + str(len(contents)).encode() + b" >>\nstream\n" + contents + b"\nendstream"]
        for index, value in enumerate(objects, 1):
            offsets.append(len(document))
            document.extend(f"{index} 0 obj\n".encode() + value + b"\nendobj\n")
        start = len(document)
        document.extend(b"xref\n0 6\n0000000000 65535 f \n")
        document.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
        document.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode())
        (work / "sample.pdf").write_bytes(document)
        self.assertIn(b"Pages:           1", self.command("pdfinfo", "sample.pdf", cwd=work).stdout)
        self.assertIn(b"Oblivion PDF fixture", self.command("pdftotext", "sample.pdf", "-", cwd=work).stdout)

    @unittest.skipUnless(Path("/usr/bin/oblivion").is_file(), "Run the session-tools-chat-test image to include the compiled client")
    def test_compiled_chat_start_loads_the_tool_instructions(self):
        work = self.root / "chat-start"
        work.mkdir()
        capability = Path("/run/oblivion-api")
        capability.mkdir(mode=0o700)
        (capability / "token").write_text("a" * 64)
        (capability / "provider").write_text("abliteration-ai")
        environment = self.environment | {
            "HOME": str(work / "home"), "XDG_CONFIG_HOME": str(work / "config"),
            "XDG_DATA_HOME": str(work / "data"), "XDG_STATE_HOME": str(work / "state"),
            "OPENCODE_CONFIG_DIR": str(work / "config"),
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1", "OPENCODE_DISABLE_FILEWATCHER": "1", "OPENCODE_DISABLE_FFF": "1",
        }
        # The public API CLI starts the real standalone server, inheriting the
        # exact production launcher configuration; no test-specific launch mode.
        entries = json.loads(self.command("/bin/sh", str(GUEST / "chat.sh"), "api", "GET", "/api/config", env=environment, cwd=work).stdout)
        instructions = [path for entry in entries if entry["type"] == "document" for path in entry["info"].get("instructions", [])]
        self.assertIn("/usr/lib/oblivion/session-tools.md", instructions)
        self.assertTrue((work / "data/opencode/oblivion.db").is_file())

    def test_https_proxy_for_curl_python_node_git_npm_and_pip(self):
        work = self.root / "https"
        work.mkdir()
        (work / "answer.txt").write_text("fixture-response")
        (work / "npm-project").mkdir()
        (work / "npm-project/package.json").write_text('{"name":"fixture-consumer","version":"1.0.0","private":true}')
        package = json.dumps({"name": "oblivion-fixture", "version": "0.0.1", "main": "index.js"}).encode()
        with tarfile.open(work / "fixture.tgz", "w:gz") as archive:
            for name, content in (("package/package.json", package), ("package/index.js", b"module.exports = 'installed';")):
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        with zipfile.ZipFile(work / "oblivion_fixture-0.0.1-py3-none-any.whl", "w") as archive:
            archive.writestr("oblivion_fixture.py", "value = 'installed'\n")
            archive.writestr("oblivion_fixture-0.0.1.dist-info/METADATA", "Metadata-Version: 2.1\nName: oblivion-fixture\nVersion: 0.0.1\n")
            archive.writestr("oblivion_fixture-0.0.1.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: oblivion-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
            archive.writestr("oblivion_fixture-0.0.1.dist-info/RECORD", "")
        self.command("git", "init", "--bare", "fixture.git", cwd=work)
        self.command("git", "--git-dir=fixture.git", "update-server-info", cwd=work)
        self.command("python3", "-m", "venv", str(work / "venv"))
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), partial(HTTP, directory=work)) as server, Server(("127.0.0.1", 0), Proxy) as proxy:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain("/fixture/cert.pem", "/fixture/key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
            proxy.destination = server.server_port
            proxy.target = f"api.abliteration.ai:{server.server_port}"
            proxy.observed = []
            proxy.deny = False
            servers = [threading.Thread(target=value.serve_forever, daemon=True) for value in (server, proxy)]
            for thread in servers:
                thread.start()
            try:
                address = f"http://oblivion-tools:{'a' * 64}@127.0.0.1:{proxy.server_address[1]}"
                environment = {key: address for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
                environment |= {"NO_PROXY": "", "no_proxy": "", "SSL_CERT_FILE": "/fixture/ca.pem", "CURL_CA_BUNDLE": "/fixture/ca.pem",
                                "GIT_SSL_CAINFO": "/fixture/ca.pem", "NODE_EXTRA_CA_CERTS": "/fixture/ca.pem", "PIP_CERT": "/fixture/ca.pem"}
                base = f"https://{proxy.target}"
                clients = [
                    ("curl", "--fail", "--silent", "--show-error", "--max-time", "10", base + "/answer.txt"),
                    ("python3", "-c", "import urllib.request; print(urllib.request.urlopen(__import__('sys').argv[1], timeout=10).read().decode(), end='')", base + "/answer.txt"),
                    ("node", "-e", "fetch(process.argv[1]).then(r => { if (!r.ok) throw Error('refused'); return r.text() }).then(t => process.stdout.write(t)).catch(() => process.exit(1))", base + "/answer.txt"),
                    ("node", "-e", "require('node:https').get(process.argv[1], r => { if (r.statusCode !== 200) process.exit(1); r.pipe(process.stdout) }).on('error', () => process.exit(1))", base + "/answer.txt"),
                ]
                for command in clients:
                    with self.subTest(client=command[0]):
                        result = self.command(*command, env=environment)
                        self.assertEqual(result.stdout, b"fixture-response")
                        self.assertEqual(result.stderr, b"")
                self.command("git", "clone", "--quiet", base + "/fixture.git", "cloned", cwd=work, env=environment)
                self.command("npm", "install", "--ignore-scripts", "--no-package-lock", "--no-save", base + "/fixture.tgz", cwd=work / "npm-project", env=environment)
                self.assertEqual(self.command("node", "-e", "process.stdout.write(require('oblivion-fixture'))", cwd=work / "npm-project").stdout, b"installed")
                self.command(str(work / "venv/bin/python"), "-m", "pip", "install", "--no-deps", "--no-index", base + "/oblivion_fixture-0.0.1-py3-none-any.whl", env=environment)
                self.assertEqual(self.command(str(work / "venv/bin/python"), "-c", "import oblivion_fixture; print(oblivion_fixture.value, end='')").stdout, b"installed")
                self.assertTrue(len(proxy.observed) >= 6)
                self.assertTrue(all(method == "CONNECT" and target == proxy.target for method, target in proxy.observed))
                untrusted = environment | {"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt", "CURL_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt", "NODE_EXTRA_CA_CERTS": "/dev/null"}
                for command in clients:
                    with self.subTest(untrusted_tls=command[0]):
                        self.assertNotEqual(self.command(*command, env=untrusted, check=False).returncode, 0)
                proxy.deny = True
                for command in clients:
                    with self.subTest(refused=command[0]):
                        self.assertNotEqual(self.command(*command, env=environment, check=False).returncode, 0)
                self.assertFalse(any((Path(self.cache.name) / "npm/_logs").glob("*.log")))
            finally:
                for value in (server, proxy):
                    value.shutdown()
                for thread in servers:
                    thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
