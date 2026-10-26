#!/usr/bin/env python3
"""Native checks of the VM's synthetic peer; this is not a gateway/Bun test."""
import contextlib
import http.client
import importlib.util
import json
import shlex
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from stream_fixture_tls import generate

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stream_fixture", root / "vm-stream-provider.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.EXTERNAL = True
tls = tempfile.TemporaryDirectory(prefix="oblivion-stream-tls-")
certificate, key = generate(Path(tls.name))
fixture.context.load_cert_chain(certificate, key)


@contextlib.contextmanager
def connection(port):
    client, server = socket.socketpair()
    client.settimeout(5)
    worker = threading.Thread(target=fixture.serve, args=(server,), daemon=True)
    worker.start()
    try:
        client.sendall(b"\x05\x01\x02")
        assert fixture.exact(client, 2) == b"\x05\x02"
        username, password = b"OBLIVION_PROXY_USER_CANARY_31d2", b"OBLIVION_PROXY_PASSWORD_CANARY_72a4"
        client.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        assert fixture.exact(client, 2) == b"\x01\x00"
        host = b"api.abliteration.ai"
        client.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", port))
        assert fixture.exact(client, 10) == b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"
        if port == 443:
            client = ssl.create_default_context(cafile=str(certificate)).wrap_socket(client, server_hostname=host.decode())
        yield client
    finally:
        client.close()
        worker.join(5)
        assert not worker.is_alive(), "fixture did not close its stream"
        assert fixture.errors == [], fixture.errors


def model(client, messages):
    body = json.dumps({"model": "abliterated-model", "stream": True, "messages": messages,
        "tools": [{"type": "function", "function": {"name": name}} for name in ["webfetch", "shell"]]}).encode()
    client.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.abliteration.ai\r\nAuthorization: Bearer OBLIVION_API_KEY_CANARY_5c91\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\n\r\n" + body)
    response = http.client.HTTPResponse(client)
    response.begin()
    assert response.status == 200
    return response


class StreamFixture(unittest.TestCase):
    def test_web_calls_roundtrip_and_redirect(self):
        initial = {"role": "user", "content": "OBLIVION_WEB_TOOLS_REQUEST"}
        with connection(443) as client:
            payload = model(client, [initial]).read().decode()
        chunks = [json.loads(line[6:]) for line in payload.splitlines() if line.startswith("data: {")]
        calls = chunks[0]["choices"][0]["delta"]["tool_calls"]
        self.assertEqual(len(calls), 6)
        shell = next(call for call in calls if call["id"] == "web_shell")
        command = shlex.split(json.loads(shell["function"]["arguments"])["command"])
        self.assertEqual(command[:2], ["python3", "-c"])
        compile(command[2], "<synthetic-shell>", "exec")
        for port, path, result in [(80, "/tools", b"OBLIVION_WEB_HTTP\n"), (443, "/tools", b"OBLIVION_WEB_HTTPS\n"), (80, "/shell", b"OBLIVION_WEB_SHELL\n")]:
            with connection(port) as client:
                client.sendall(f"GET {path} HTTP/1.1\r\nHost: api.abliteration.ai\r\n\r\n".encode())
                response = http.client.HTTPResponse(client)
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), result)
        with connection(80) as client:
            client.sendall(b"GET /redirect HTTP/1.1\r\nHost: api.abliteration.ai\r\n\r\n")
            response = http.client.HTTPResponse(client)
            response.begin()
            self.assertEqual(response.status, 302)
            self.assertEqual(response.getheader("Location"), "https://denied.example.com/tools")
            self.assertEqual(response.read(), b"")
        results = {"web_http": "OBLIVION_WEB_HTTP", "web_https": "OBLIVION_WEB_HTTPS", "web_shell": "OBLIVION_SHELL_PROXY_OK",
            "web_redirect": "Transport error (GET http://api.abliteration.ai/redirect)",
            "web_unknown": "Transport error (GET https://unknown.example.com/tools)",
            "web_port": "Transport error (GET https://api.abliteration.ai:4443/tools)"}
        with connection(443) as client:
            payload = model(client, [initial, *[{"role": "tool", "tool_call_id": name, "content": value} for name, value in results.items()]]).read()
        self.assertIn(b"OBLIVION_WEB_TOOLS_VERIFIED", payload)
        self.assertEqual(fixture.web, {"http": 1, "https": 1, "shell": 1, "redirect": 1, "completed": 1})

    def test_held_api_stream_closes_at_the_peer(self):
        with connection(443) as client:
            response = model(client, [{"role": "user", "content": "OBLIVION_STREAM_REQUEST"}])
            self.assertIn(b"Synthetic open stream", response.read1(8192))
            self.assertEqual(fixture.active, {1})
            response.close()
        self.assertEqual(fixture.active, set())
        self.assertEqual(fixture.closed, {1})


if __name__ == "__main__":
    unittest.main()
