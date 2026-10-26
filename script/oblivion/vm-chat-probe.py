#!/usr/bin/env python3
"""Actual compiled CLI in a session guest; loopback provider and data are synthetic."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MARKER = "OBLIVION_GUEST_CHAT_CANARY_7eaf"
phase = sys.argv[1]
assert phase in {"chat-a", "chat-b", "chat-resume"}
assert os.getuid() == 1000 and Path.cwd() == Path("/vault/workspace")
assert " / squashfs ro," in Path("/proc/mounts").read_text()
assert sorted(item.name for item in Path("/sys/class/net").iterdir()) == ["lo"]
state = Path("/vault/state/lab-chat-id")
context = Path("chat-context.txt")
document = Path("chat-document.txt")
temporaries = [Path("/tmp/chat-temp"), Path("/var/tmp/chat-temp")]
if phase == "chat-b":
    assert not state.exists() and not context.exists() and not document.exists()
    assert not any(Path("/vault/state").rglob("*.db"))
    assert not any(item.exists() for item in temporaries)
    print("OBLIVION_CHAT_EMPTY", flush=True)
    raise SystemExit(0)
if phase == "chat-resume":
    assert document.read_text() == MARKER + "_DOCUMENT"
    assert not any(item.exists() for item in temporaries)
if phase == "chat-a":
    assert not state.exists()
    context.write_text(MARKER + "_CONTEXT")
requests = []


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.path == "/v1/chat/completions"
        requests.append(body)
        used = any(item.get("role") == "tool" for item in body.get("messages", []))
        if phase == "chat-a" and not used:
            command = f"printf %s {MARKER}_DOCUMENT > chat-document.txt; printf %s {MARKER}_TEMP > /tmp/chat-temp; printf %s {MARKER}_TEMP > /var/tmp/chat-temp; cat chat-context.txt"
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_guest", "type": "function",
                "function": {"name": "shell", "arguments": json.dumps({"command": command})}}]}
            finish = "tool_calls"
        else:
            delta = {"role": "assistant", "content": MARKER + ("_RESUMED" if phase == "chat-resume" else "_REPLY")}
            finish = "stop"
        chunks = [{"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                  {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}]},
                  {"choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}}]
        payload = "".join("data: " + json.dumps({"id": "chatcmpl-guest", "object": "chat.completion.chunk",
            "created": 1, "model": body["model"], **chunk}) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload.encode())))
        self.end_headers()
        self.wfile.write(payload.encode())


provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
threading.Thread(target=provider.serve_forever, daemon=True).start()
env = {**os.environ, "ABLIT_KEY": "synthetic-guest-key", "OPENCODE_PASSWORD": "synthetic-guest-server-key",
       "OPENCODE_DISABLE_FILEWATCHER": "true", "OPENCODE_DISABLE_FFF": "true",
       "OPENCODE_CONFIG_CONTENT": json.dumps({"model": "abliteration-ai/abliterated-model", "snapshots": False,
           "providers": {"abliteration-ai": {"settings": {"baseURL": f"http://127.0.0.1:{provider.server_port}/v1"}}}})}
arguments = ["--file", str(context), MARKER + "_PROMPT"] if phase == "chat-a" else ["--session", state.read_text(), "Continue the synthetic conversation"]
try:
    result = subprocess.run(["/usr/bin/oblivion", "run", "--standalone", "--auto", "--format", "json", *arguments],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=150)
    assert result.returncode == 0, (result.returncode, result.stderr[-4000:], result.stdout[-4000:])
    output = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert requests and MARKER + "_CONTEXT" in json.dumps(requests)
    assert document.read_text() == MARKER + "_DOCUMENT"
    assert any(item.get("role") == "tool" for request in requests for item in request["messages"])
    if phase == "chat-a":
        assert MARKER + "_REPLY" in result.stdout
        assert all(item.read_text() == MARKER + "_TEMP" for item in temporaries)
        state.write_text(output[-1]["sessionID"])
    if phase == "chat-resume":
        assert MARKER + "_REPLY" in json.dumps(requests)
        assert MARKER + "_RESUMED" in result.stdout
        assert all(item["sessionID"] == state.read_text() for item in output)
        assert not any(item.exists() for item in temporaries)
    forbidden = [str(item) for item in Path("/vault").rglob("*") if item.is_file()
                 and item.suffix in {".log", ".heapsnapshot", ".cpuprofile"}]
    assert not forbidden, forbidden
    os.sync()
    print("OBLIVION_CHAT_CREATED" if phase == "chat-a" else "OBLIVION_CHAT_RESUMED", flush=True)
finally:
    provider.shutdown()
