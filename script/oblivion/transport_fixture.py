"""Loopback-only SOCKS/TLS fixture. Never opens an upstream connection."""
import json
import socketserver
import ssl
import struct
import threading
from pathlib import Path

KEY = "OBLIVION_API_" + "KEY_CANARY_5c91"
USERNAME = "oblivion-proxy-fixture"
PASSWORD = "OBLIVION_PROXY_" + "PASSWORD_CANARY_72a4"


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        assert chunk, "incomplete fixture input"
        data.extend(chunk)
    return bytes(data)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture = self.server.fixture
        fixture.record("contacts")
        mode = fixture.mode
        try:
            self.request.settimeout(30)
            method = 2 if fixture.authenticated else 0
            assert exact(self.request, 1) == b"\x05"
            methods = exact(self.request, exact(self.request, 1)[0])
            assert method in methods
            if methods == bytes([method]):
                fixture.record("single_method")
            if mode == "method-rejected":
                self.request.sendall(bytes([5, 0 if method == 2 else 2]))
                assert self.request.recv(1) == b"", "client accepted an unoffered method"
                fixture.record("method_rejected")
                return
            self.request.sendall(bytes([5, method]))
            if method == 2:
                assert exact(self.request, 1) == b"\x01"
                assert exact(self.request, exact(self.request, 1)[0]) == USERNAME.encode()
                assert exact(self.request, exact(self.request, 1)[0]) == PASSWORD.encode()
                if mode == "auth-rejected":
                    self.request.sendall(b"\x01\x01")
                    assert self.request.recv(1) == b"", "client continued after rejected credentials"
                    fixture.record("auth_rejected")
                    return
                self.request.sendall(b"\x01\x00")
            assert exact(self.request, 4) == b"\x05\x01\x00\x03"
            assert exact(self.request, exact(self.request, 1)[0]) == b"api.abliteration.ai"
            port = struct.unpack("!H", exact(self.request, 2))[0]
            assert port == 443 or (fixture.tools and port == 80)
            if mode == "connect-rejected":
                self.request.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                assert self.request.recv(1) == b"", "client continued after CONNECT rejection"
                fixture.record("connect_rejected")
                return
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            if port == 80:
                with self.request.makefile("rb") as reader:
                    assert reader.readline(8192) == b"GET /tools HTTP/1.1\r\n"
                    self.tools_response(self.request, reader, mode, False)
                return
            with fixture.context.wrap_socket(self.request, server_side=True) as tls:
                with tls.makefile("rb") as reader:
                    request = reader.readline(8192)
                    if request == b"GET /tools HTTP/1.1\r\n":
                        self.tools_response(tls, reader, mode, True)
                        return
                    assert request == b"POST /v1/chat/completions HTTP/1.1\r\n"
                    headers = {}
                    while True:
                        line = reader.readline(8192)
                        if line == b"\r\n":
                            break
                        assert line.endswith(b"\r\n") and len(headers) < 32
                        name, value = line.split(b":", 1)
                        assert name.lower() not in headers
                        headers[name.lower()] = value.strip()
                    assert headers[b"authorization"] == ("Bearer " + KEY).encode()
                    assert headers[b"host"] == b"api.abliteration.ai"
                    size = int(headers[b"content-length"])
                    assert 0 < size <= 65536
                    body = json.loads(reader.read(size))
                    assert body["model"] == "abliterated-model" and body["stream"] is True
                    assert body["messages"] == [{"role": "user", "content": "synthetic network fixture"}]
                    fixture.record("http_requests")
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    value = {"id": "chatcmpl-fixture", "object": "chat.completion.chunk", "created": 1,
                        "model": "abliterated-model", "choices": [{"index": 0,
                        "delta": {"role": "assistant", "content": "Synthetic transport response"}, "finish_reason": None}]}
                    payload = ("data: " + json.dumps(value) + "\n\n").encode()
                    tls.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                    if mode == "hold":
                        fixture.record("stream_started")
                        # A timeout fails the test. Only actual EOF/reset is
                        # evidence that revocation reached the upstream socket.
                        try:
                            assert tls.recv(1) == b"", "unexpected bytes during held response"
                        except (ssl.SSLEOFError, ConnectionResetError):
                            pass
                        fixture.record("stream_closed")
                        return
                    assert mode == "normal"
                    payload = b"data: [DONE]\n\n"
                    tls.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n")
        except Exception as error:
            with fixture.condition:
                # Never include raw input, headers or exception messages.
                fixture.errors.append(type(error).__name__)
                fixture.condition.notify_all()
        finally:
            fixture.record("finished")

    def tools_response(self, connection, reader, mode, tls):
        fixture = self.server.fixture
        assert fixture.tools and mode in ["normal", "hold"]
        headers = {}
        while True:
            line = reader.readline(8192)
            if line == b"\r\n":
                break
            assert line.endswith(b"\r\n") and len(headers) < 32
            name, value = line.split(b":", 1)
            assert name.lower() not in headers
            headers[name.lower()] = value.strip()
        assert headers[b"host"] == b"api.abliteration.ai"
        assert not any(name in headers for name in [b"authorization", b"proxy-authorization", b"x-local-hop"])
        assert int(headers.get(b"content-length", b"0")) == 0
        fixture.record("tools_requests")
        fixture.record("tools_https" if tls else "tools_http")
        connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        payload = b"Synthetic tools response\n"
        connection.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
        if mode == "normal":
            connection.sendall(b"0\r\n\r\n")
            return
        fixture.record("tools_stream_started")
        try:
            assert connection.recv(1) == b"", "unexpected bytes during held tools response"
        except (ssl.SSLEOFError, ConnectionResetError):
            pass
        fixture.record("tools_stream_closed")


class Proxy:
    def __init__(self, authenticated, tools=False, certificate=None, key=None):
        self.authenticated = authenticated
        self.tools = tools
        self.condition = threading.Condition()
        self.events = {}
        self.errors = []
        self.mode = "normal"
        self.port = 0
        self.server = None
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        root = Path(__file__).parent
        self.context.load_cert_chain(certificate or root / "fixture-cert.pem", key or root / "fixture-key.pem")

        def sni(connection, name, context):
            assert name == "api.abliteration.ai"
        self.context.set_servername_callback(sni)

    def start(self):
        assert self.server is None
        self.server = Server(("127.0.0.1", self.port), Handler)
        self.server.fixture = self
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()
        self.server = None

    def record(self, event):
        with self.condition:
            self.events[event] = self.events.get(event, 0) + 1
            self.condition.notify_all()

    def wait(self, event, count):
        with self.condition:
            assert self.condition.wait_for(lambda: self.events.get(event, 0) == count or self.errors, timeout=15), (event, count)
            assert not self.errors, self.errors

    def snapshot(self):
        with self.condition:
            assert not self.errors, self.errors
            return self.events.copy()
