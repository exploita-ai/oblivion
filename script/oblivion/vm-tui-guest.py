#!/usr/bin/python3
"""Interactive compiled TUI; synthetic loopback provider only, no external NIC."""
import fcntl
import json
import os
import struct
import subprocess
import termios
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MARKER = "OBLIVION_TUI_CANARY_8ac4"
assert os.getuid() == 1000 and Path.cwd() == Path("/vault/workspace")
assert sorted(item.name for item in Path("/sys/class/net").iterdir()) == ["lo"]
# Fixed-size laboratory PTY. Dynamic serial-console resizing remains a product gate.
fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 27, 100, 0, 0))


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.path == "/v1/chat/completions"
        messages = body.get("messages", [])
        users = [json.dumps(item["content"]) for item in messages if item.get("role") == "user"]
        prompt = users[-1] if users else ""
        tool = any(item.get("role") == "tool" for item in messages)
        delta = {"role": "assistant", "content": "Conversazione di prova"}
        finish = "stop"
        if body.get("tools"):
            if "OBLIVION_TUI_A_REQUEST" in prompt and not tool:
                command = f"printf %s {MARKER} > document.txt; printf %s {MARKER} > /tmp/tui-temp; printf %s {MARKER} > /var/tmp/tui-temp; cat document.txt"
                delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_tui", "type": "function",
                    "function": {"name": "shell", "arguments": json.dumps({"command": command})}}]}
                finish = "tool_calls"
            elif "OBLIVION_TUI_A_REQUEST" in prompt:
                assert tool and Path("document.txt").read_text() == MARKER
                delta["content"] = "OBLIVION_TUI_A_REPLY"
            elif "OBLIVION_TUI_RESUME" in prompt:
                assert "OBLIVION_TUI_A_REPLY" in json.dumps(messages)
                assert Path("document.txt").read_text() == MARKER
                assert not Path("/tmp/tui-temp").exists() and not Path("/var/tmp/tui-temp").exists()
                delta["content"] = "OBLIVION_TUI_A_RESUMED"
            elif "OBLIVION_TUI_B_REQUEST" in prompt:
                assert "OBLIVION_TUI_A_REQUEST" not in json.dumps(messages)
                assert not Path("document.txt").exists()
                assert not Path("/tmp/tui-temp").exists() and not Path("/var/tmp/tui-temp").exists()
                delta["content"] = "OBLIVION_TUI_B_REPLY"
            else:
                raise AssertionError("unexpected interactive prompt")
        chunks = [{"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                  {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}]},
                  {"choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}}]
        payload = "".join("data: " + json.dumps({"id": "chatcmpl-tui", "object": "chat.completion.chunk",
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
raise SystemExit(subprocess.call(["/usr/bin/oblivion", "--standalone", "--auto"], env=env))
