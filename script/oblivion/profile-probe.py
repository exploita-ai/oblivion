#!/usr/bin/env python3
"""Exercise the compiled ARM Linux privacy build with synthetic data, offline."""
import base64
import csv
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OUT = Path("/out")
BINARY = Path("/work/artifacts/oblivion-build/cli-linux-arm64/bin/opencode")
MARKER = "OBLIVION_PROFILE_CANARY_59fa"
if not Path("/.dockerenv").exists() or not BINARY.is_file():
    raise SystemExit("Run inside the offline audit container with the compiled binary")
OUT.mkdir(exist_ok=True)
requests = []
checks = []


def check(label):
    checks.append(label)
    print("PASS: " + label, flush=True)


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        requests.append({"method": "GET", "path": self.path})
        self.send_response(500)
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/v1/chat/completions":
            requests.append({"method": "POST", "path": self.path})
            self.send_response(200)
            self.end_headers()
            return
        tools = [item.get("function", {}).get("name") for item in body.get("tools", [])]
        used = any(item.get("role") == "tool" for item in body.get("messages", []))
        requests.append({"method": "POST", "path": self.path, "model": body.get("model"), "tool_result": used})
        if "shell" in tools and not used:
            command = f"printf {MARKER}_DOCUMENT > document.txt; printf {MARKER}_TEMP > /tmp/profile-temp; cat context.txt"
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_privacy", "type": "function",
                     "function": {"name": "shell", "arguments": json.dumps({"command": command})}}]}
            finish = "tool_calls"
        else:
            delta = {"role": "assistant", "content": MARKER + "_REPLY"}
            finish = "stop"
        chunks = [
            {"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}]},
            {"choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}},
        ]
        payload = "".join("data: " + json.dumps({"id": "chatcmpl-privacy", "object": "chat.completion.chunk",
                  "created": 1, "model": body.get("model"), **chunk}) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload.encode())))
        self.end_headers()
        self.wfile.write(payload.encode())


fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
threading.Thread(target=fixture.serve_forever, daemon=True).start()
root = OUT / "session"
root.mkdir(exist_ok=False)
workspace = root / "workspace"
workspace.mkdir()
(workspace / "context.txt").write_text(MARKER + "_CONTEXT")
env = {"PATH": os.environ["PATH"], "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
       "XDG_DATA_HOME": str(root / "data"), "XDG_STATE_HOME": str(root / "state"),
       "XDG_CONFIG_HOME": str(root / "config"), "XDG_CACHE_HOME": str(root / "cache"),
       "ABLIT_KEY": "synthetic-key-only", "OPENCODE_PASSWORD": "synthetic-server-key",
       "OBLIVION_PROFILE": "false", "OPENCODE_PRINT_LOGS": "1", "OPENCODE_LOG_LEVEL": "DEBUG",
       "OPENCODE_DISABLE_MODELS_FETCH": "false", "OPENCODE_DISABLE_AUTOUPDATE": "false",
       "OPENCODE_DISABLE_PROJECT_CONFIG": "false", "OPENCODE_DISABLE_CLAUDE_CODE": "false",
       "OPENCODE_DISABLE_FILEWATCHER": "true", "OPENCODE_DISABLE_FFF": "true",
       "OPENCODE_MODELS_URL": f"http://127.0.0.1:{fixture.server_port}/catalog",
       "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{fixture.server_port}/telemetry",
       "OPENCODE_CONFIG_CONTENT": json.dumps({"model": "abliteration-ai/abliterated-model", "snapshots": False,
           "providers": {"abliteration-ai": {"settings": {"baseURL": f"http://127.0.0.1:{fixture.server_port}/v1"}}}})}
for name in ["HOME", "TMPDIR", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"]:
    Path(env[name]).mkdir(parents=True)
# A project-local override must not redirect the provider in this build.
(workspace / "opencode.json").write_text(json.dumps({"providers": {"abliteration-ai": {
    "settings": {"baseURL": f"http://127.0.0.1:{fixture.server_port}/untrusted-project"}}}}))


def run(name, arguments):
    with (OUT / f"{name}.stdout").open("w") as stdout, (OUT / f"{name}.stderr").open("w") as stderr:
        result = subprocess.run(["strace", "-f", "-yy", "-s", "128", "-e", "trace=%file,%network",
            "-o", str(OUT / f"{name}.strace"), str(BINARY), *arguments], cwd=workspace, env=env,
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=90)
    return result.returncode


def api(port, route, method="GET"):
    request = urllib.request.Request(f"http://127.0.0.1:{port}/api/{route}", method=method,
        headers={"Authorization": "Basic " + base64.b64encode(b"opencode:synthetic-server-key").decode()})
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


with (OUT / "capture.log").open("w") as capture_log:
    capture = subprocess.Popen(["tcpdump", "-n", "-p", "-U", "--immediate-mode", "-B", "16384",
        "-i", "any", "-s", "0", "-Z", "root", "-w", "/tmp/profile.pcap"],
        stdout=subprocess.DEVNULL, stderr=capture_log)
    try:
        deadline = time.monotonic() + 5
        while "listening on" not in (OUT / "capture.log").read_text():
            assert capture.poll() is None and time.monotonic() < deadline
            time.sleep(0.02)
        assert run("chat", ["run", "--standalone", "--auto", "--format", "json", "--file", "context.txt", MARKER]) == 0
        assert MARKER + "_REPLY" in (OUT / "chat.stdout").read_text()
        assert (workspace / "document.txt").read_text() == MARKER + "_DOCUMENT"
        assert any(item.get("tool_result") for item in requests)
        check("compiled privacy binary completes native Abliteration streaming and shell tool round trip")
        assert requests and all(item["path"] == "/v1/chat/completions" for item in requests)
        check("project provider override, catalog refresh and OTLP environment cannot redirect startup traffic")
        assert run("upgrade", ["upgrade", "--method", "curl"]) != 0
        assert "outside the session" in (OUT / "upgrade.stdout").read_text()
        check("in-session updater refuses explicit upgrades")
        with (OUT / "server.stdout").open("w") as stdout, (OUT / "server.stderr").open("w") as stderr:
            server = subprocess.Popen([str(BINARY), "serve", "--hostname", "127.0.0.1", "--port", "0"],
                cwd=workspace, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 30
                port = None
                while port is None:
                    match = re.search(r"server listening on http://127\.0\.0\.1:(\d+)", (OUT / "server.stdout").read_text())
                    if match:
                        port = int(match[1])
                        break
                    assert server.poll() is None and time.monotonic() < deadline
                    time.sleep(0.02)
                assert api(port, "info")[0] == 200
                os.kill(server.pid, signal.SIGUSR1)
                os.kill(server.pid, signal.SIGPROF)
                status, response = api(port, "debug/heap-dump", "POST")
                assert status >= 400 and "disabled in Oblivion" in json.dumps(response)
                assert api(port, "info")[0] == 200 and server.poll() is None
                check("diagnostic signals do not dump memory; HTTP heap-dump endpoint refuses the write")
            finally:
                server.terminate()
                server.wait(timeout=10)
        forbidden = [str(file.relative_to(root)) for file in root.rglob("*") if file.is_file()
                     and file.suffix in {".log", ".heapsnapshot", ".cpuprofile"}]
        assert not forbidden, forbidden
        check("no log, heap snapshot or CPU profile files remain in isolated application storage")
    finally:
        fixture.shutdown()
        time.sleep(0.2)
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=5)
assert capture.returncode == 0
assert "0 packets dropped by kernel" in (OUT / "capture.log").read_text().splitlines()
pcap = Path("/tmp/profile.pcap")
(OUT / "network.pcap").write_bytes(pcap.read_bytes())
decoded = subprocess.check_output(["tshark", "-n", "-r", str(pcap), "-T", "fields", "-e", "frame.len",
    "-e", "frame.cap_len", "-e", "tcp.dstport", "-e", "dns.qry.name"], text=True, stderr=subprocess.DEVNULL)
rows = list(csv.reader(io.StringIO(decoded), delimiter="\t"))
assert rows and all(row[0] == row[1] for row in rows)
assert not any(row[2] in {"1234", "11434", "8000"} or row[3] for row in rows)
traces = "\n".join(file.read_text() for file in OUT.glob("*.strace"))
assert not re.search(r"sin_port=htons\((1234|11434|8000|53)\)", traces)
check("packet capture and syscall trace show no local provider discovery or DNS attempts")
summary = {"scope": "compiled ARM Linux privacy binary in offline Docker on Mac ARM; synthetic provider only",
    "checks": checks, "packets": len(rows), "dropped_packets": 0, "truncated_packets": 0,
    "provider_requests": requests, "binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
    "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
    "limits": ["No real Abliteration, Tor or TUI exercised.",
        "Synthetic provider key still lives inside guest environment until broker integration.",
        "Database and shell output persistence remain session data; this is not a disk-isolation test."]}
(OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({"checks": len(checks), "packets": len(rows)}))
