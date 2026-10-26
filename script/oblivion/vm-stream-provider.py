#!/usr/bin/python3
"""Lab-only SOCKS/TLS provider. Synthetic credentials, counters on private serial."""
import hashlib
import json
import os
import shlex
import socket
import ssl
import struct
import sys
import threading
import traceback
import tty
from pathlib import Path

ROOT = Path("/usr/lib/oblivion-stream-fixture")
EXTERNAL = False
KEYS = {b"Bearer OBLIVION_API_KEY_CANARY_5c91": "initial", b"Bearer OBLIVION_API_NEXT_CANARY_86ab": "alternate",
    b"Bearer OBLIVION_API_RAM_CANARY_a13e": "temporary"}
lock = threading.Lock()
active = set()
closed = set()
errors = []
sequence = 0
credentials = {}
web = {"http": 0, "https": 0, "redirect": 0, "shell": 0, "completed": 0}
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        assert chunk, "incomplete fixture input"
        data.extend(chunk)
    return bytes(data)


def headers(reader):
    values = {}
    while True:
        line = reader.readline(8192)
        if line == b"\r\n":
            return values
        assert line.endswith(b"\r\n") and len(values) < 32
        name, value = line.split(b":", 1)
        assert name.lower() not in values
        values[name.lower()] = value.strip()


def web_response(connection, reader, line, secure):
    assert EXTERNAL
    values = headers(reader)
    assert values[b"host"] == b"api.abliteration.ai"
    assert not any(name in values for name in [b"authorization", b"proxy-authorization"])
    assert int(values.get(b"content-length", b"0")) == 0
    if line == b"GET /redirect HTTP/1.1\r\n":
        assert not secure
        with lock:
            web["redirect"] += 1
        connection.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://denied.example.com/tools\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    assert line in [b"GET /tools HTTP/1.1\r\n", b"GET /shell HTTP/1.1\r\n"]
    kind = "shell" if line.startswith(b"GET /shell ") else "https" if secure else "http"
    with lock:
        web[kind] += 1
    payload = ("OBLIVION_WEB_" + kind.upper() + "\n").encode()
    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: "
        + str(len(payload)).encode() + b"\r\n\r\n" + payload)


def web_model(connection, body):
    messages = body["messages"]
    start = next(index for index in range(len(messages) - 1, -1, -1) if messages[index]["role"] == "user")
    if "OBLIVION_WEB_TOOLS_REQUEST" not in json.dumps(messages[start]["content"]):
        return False
    results = {item["tool_call_id"]: json.dumps(item["content"]) for item in messages[start + 1:] if item["role"] == "tool"}
    if not body.get("tools"):
        delta, finish = {"role": "assistant", "content": "Synthetic web tools title"}, "stop"
    elif results:
        assert set(results) == {"web_http", "web_https", "web_redirect", "web_unknown", "web_port", "web_shell"}
        assert "OBLIVION_WEB_HTTP" in results["web_http"]
        assert "OBLIVION_WEB_HTTPS" in results["web_https"]
        assert "OBLIVION_SHELL_PROXY_OK" in results["web_shell"]
        for name, url in [("web_redirect", "http://api.abliteration.ai/redirect"),
                ("web_unknown", "https://unknown.example.com/tools"),
                ("web_port", "https://api.abliteration.ai:4443/tools")]:
            assert f"Transport error (GET {url})" in results[name], name
        with lock:
            web["completed"] += 1
        delta, finish = {"role": "assistant", "content": "OBLIVION_WEB_TOOLS_VERIFIED"}, "stop"
    else:
        available = {tool["function"]["name"] for tool in body["tools"]}
        assert {"webfetch", "shell"} <= available
        # The shell reads the capability only inside the guest and never prints it.
        command = "python3 -c " + shlex.quote('''import os,socket,urllib.request
from pathlib import Path
token=Path('/run/oblivion-api/token').read_text()
expected='http://oblivion-tools:'+token+'@10.88.0.1:8112'
assert all(os.environ[name]==expected for name in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'])
with urllib.request.urlopen('http://api.abliteration.ai/shell',timeout=15) as response:
    assert response.read()==b'OBLIVION_WEB_SHELL\\n'
with socket.socket() as direct:
    direct.settimeout(1)
    assert direct.connect_ex(('10.0.2.2',9050))!=0
print('OBLIVION_SHELL_PROXY_OK')''')
        calls = [("web_http", "webfetch", {"url": "http://api.abliteration.ai/tools", "format": "text"}),
            ("web_https", "webfetch", {"url": "https://api.abliteration.ai/tools", "format": "text"}),
            ("web_redirect", "webfetch", {"url": "http://api.abliteration.ai/redirect", "format": "text"}),
            ("web_unknown", "webfetch", {"url": "https://unknown.example.com/tools", "format": "text"}),
            ("web_port", "webfetch", {"url": "https://api.abliteration.ai:4443/tools", "format": "text"}),
            ("web_shell", "shell", {"command": command})]
        delta = {"role": "assistant", "tool_calls": [{"index": index, "id": identifier, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}} for index, (identifier, name, arguments) in enumerate(calls)]}
        finish = "tool_calls"
    chunks = [{"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
        {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}]
    payload = ("".join("data: " + json.dumps({"id": "chatcmpl-web", "object": "chat.completion.chunk", "created": 1,
        "model": body["model"], **chunk}) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n").encode()
    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\nContent-Length: "
        + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    return True


def serve(connection):
    global sequence
    identifier = None
    try:
        with connection:
            connection.settimeout(180)
            assert exact(connection, 1) == b"\x05"
            methods = exact(connection, exact(connection, 1)[0])
            assert 2 in methods
            connection.sendall(b"\x05\x02")
            assert exact(connection, 1) == b"\x01"
            assert exact(connection, exact(connection, 1)[0]) == (b"OBLIVION_PROXY_USER_CANARY_31d2" if EXTERNAL else b"oblivion-api")
            token = exact(connection, exact(connection, 1)[0])
            if EXTERNAL:
                assert token == b"OBLIVION_PROXY_PASSWORD_CANARY_72a4"
            else:
                assert len(token) == 64 and all(byte in b"0123456789abcdef" for byte in token)
            connection.sendall(b"\x01\x00")
            assert exact(connection, 4) == b"\x05\x01\x00\x03"
            assert exact(connection, exact(connection, 1)[0]) == b"api.abliteration.ai"
            port = struct.unpack(">H", exact(connection, 2))[0]
            assert port == 443 or (EXTERNAL and port == 80)
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            if port == 80:
                with connection.makefile("rb") as reader:
                    web_response(connection, reader, reader.readline(8192), False)
                return
            with context.wrap_socket(connection, server_side=True) as tls:
                with tls.makefile("rb") as reader:
                    line = reader.readline(8192)
                    if line.startswith(b"GET "):
                        web_response(tls, reader, line, True)
                        return
                    assert line == b"POST /v1/chat/completions HTTP/1.1\r\n"
                    values = headers(reader)
                    assert values[b"authorization"] in KEYS
                    assert values[b"host"] == b"api.abliteration.ai"
                    size = int(values[b"content-length"])
                    assert 0 < size <= 16 * 1024 * 1024
                    body = json.loads(reader.read(size))
                    assert body["model"] == "abliterated-model" and body["stream"] is True
                    if EXTERNAL and web_model(tls, body):
                        return
                    if "OBLIVION_STREAM_REQUEST" not in json.dumps(body["messages"]):
                        return  # Existing offline probes still receive provider_unavailable.
                    chat = bool(body.get("tools"))
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    value = {"id": "chatcmpl-fixture", "object": "chat.completion.chunk", "created": 1,
                        "model": "abliterated-model", "choices": [{"index": 0,
                        "delta": {"role": "assistant", "content": "Synthetic open stream"}, "finish_reason": None}]}
                    payload = ("data: " + json.dumps(value) + "\n\n").encode()
                    if not chat:
                        value["choices"][0] = {"index": 0, "delta": {}, "finish_reason": "stop"}
                        payload += ("data: " + json.dumps(value) + "\n\ndata: [DONE]\n\n").encode()
                    if chat:
                        with lock:
                            sequence += 1
                            identifier = sequence
                            active.add(identifier)
                            credentials[identifier] = KEYS[values[b"authorization"]]
                    tls.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                    if not chat:
                        tls.sendall(b"0\r\n\r\n")
                        return
                    # The response remains open until the real broker closes its
                    # upstream TLS socket. A fixture timeout is a failure, not EOF.
                    try:
                        assert tls.recv(1) == b"", "unexpected request after streaming"
                    except (ssl.SSLEOFError, ConnectionResetError):
                        pass
                    with lock:
                        active.remove(identifier)
                        closed.add(identifier)
    except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
        with lock:
            if identifier is not None:
                active.discard(identifier)
                closed.add(identifier)
    except BaseException as error:
        with lock:
            # Retain the failing fixture line, never the request or credentials.
            errors.append({"type": type(error).__name__, "line": traceback.extract_tb(error.__traceback__)[-1].lineno})


def accept(listener):
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=serve, args=(connection,), daemon=True).start()


def status(line):
    request = json.loads(line)
    assert set(request) == {"operation", "id"} and request["operation"] == "status"
    with lock:
        value = {"id": request["id"], "active": sorted(active), "closed": sorted(closed), "errors": errors.copy(), "credentials": credentials.copy(), "web": web.copy()}
    value["fixture_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if not EXTERNAL:
        value["api_sha256"] = hashlib.sha256(Path("/usr/bin/oblivion-api").read_bytes()).hexdigest()
    return json.dumps(value, separators=(",", ":"))


def main():
    global EXTERNAL
    EXTERNAL = sys.argv[1:] == ["--external"]
    assert EXTERNAL or sys.argv[1:] == []
    assert os.getuid() == 0
    assert len(Path("/proc/swaps").read_text().splitlines()) == 1
    context.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 9050))
    listener.listen(16)
    threading.Thread(target=accept, args=(listener,), daemon=True).start()
    if EXTERNAL:
        os.umask(0o077)
        with socket.socket(socket.AF_UNIX) as control:
            control.bind("/run/oblivion-stream-provider.sock")
            control.listen(1)
            while True:
                channel, _ = control.accept()
                with channel:
                    channel.settimeout(5)
                    with channel.makefile("rb") as reader:
                        line = reader.readline(1024)
                        assert line.endswith(b"\n")
                        channel.sendall(status(line).encode() + b"\n")
    else:
        tty.setraw(0)
        for line in sys.stdin:
            print("OBLIVION_STREAM " + status(line), flush=True)


if __name__ == "__main__":
    main()
