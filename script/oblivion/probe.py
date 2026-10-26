#!/usr/bin/env python3
"""Synthetic, offline syscall probes. Run only in the audit container.

The container has no external network and mounts the source read-only. /out is
the sole host-writable mount. Results describe exercised paths, not all paths.
"""

import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OUT = Path("/out")
if not Path("/.dockerenv").exists() or not Path("/work/packages/cli/src/index.ts").exists():
    raise SystemExit("Run in the isolated audit container; see REPRODUCE.md")
OUT.mkdir(exist_ok=True)
MARKER = "OBLIVION_AUDIT_SYNTHETIC_7c924e"
requests = []


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        tools = [item.get("function", {}).get("name") for item in body.get("tools", [])]
        used = any(item.get("role") == "tool" for item in body.get("messages", []))
        requests.append({"path": self.path, "model": body.get("model"), "stream": body.get("stream"),
                         "tools": tools, "has_tool_result": used,
                         "authorization_is_fixture": self.headers.get("Authorization") == "Bearer audit-dummy-key"})
        if "shell" in tools and not used:
            command = "python3 -c 'from pathlib import Path; " + \
                f'Path("/tmp/oblivion-outside-xdg.txt").write_text("{MARKER}_SHELL_TMP"); ' + \
                f'Path("context-edited.txt").write_text("{MARKER}_DOCUMENT"); ' + \
                'import os; print("AUDIT_CHILD_HAS_PROVIDER_KEY=" + str(os.environ.get("ABLIT_KEY") == "audit-dummy-key")); ' + \
                f'print("{MARKER}_SHELL_OUTPUT\\n" * 2500)' + "'"
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_audit_shell", "type": "function",
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
        payload = "".join("data: " + json.dumps({"id": "chatcmpl-audit", "object": "chat.completion.chunk",
                    "created": 1, "model": body.get("model"), **chunk}) + "\n\n" for chunk in chunks)
        payload += "data: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload.encode())))
        self.end_headers()
        self.wfile.write(payload.encode())


server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
threading.Thread(target=server.serve_forever, daemon=True).start()
reports = []


def run(name, arguments, memory=False, model_refresh=False):
    outside = Path("/tmp/oblivion-outside-xdg.txt")
    outside.unlink(missing_ok=True)
    root = OUT / (name + "-" + str(time.time_ns()))
    root.mkdir()
    work = root / "workspace"
    work.mkdir()
    (work / "context.txt").write_text(MARKER + "_CONTEXT")
    # The unbundled CLI spawns itself without Bun flags. Match its package's
    # JSX preload in the synthetic cwd so both client and server load sources.
    (work / "bunfig.toml").write_text('preload = ["/work/packages/cli/node_modules/@opentui/solid/scripts/preload.js"]\n')
    (work / "tsconfig.json").write_text(json.dumps({"extends": "/work/packages/cli/tsconfig.json"}))
    env = {"PATH": os.environ["PATH"], "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
           "XDG_DATA_HOME": str(root / "data"), "XDG_STATE_HOME": str(root / "state"),
           "XDG_CACHE_HOME": str(root / "cache"), "XDG_CONFIG_HOME": str(root / "config"),
           "OPENCODE_DISABLE_PROJECT_CONFIG": "true", "OPENCODE_DISABLE_CLAUDE_CODE": "true",
           "OPENCODE_DISABLE_MODELS_FETCH": "false" if model_refresh else "true", "OPENCODE_DISABLE_FFF": "true",
           "OPENCODE_DISABLE_FILEWATCHER": "true", "ABLIT_KEY": "audit-dummy-key",
           "OPENCODE_CONFIG_CONTENT": json.dumps({
               "update": "disable", "model": "abliteration-ai/abliterated-model", "snapshots": False,
               "providers": {"abliteration-ai": {"settings": {"baseURL": f"http://127.0.0.1:{server.server_port}/v1"}}},
           })}
    for key in ["HOME", "TMPDIR", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"]:
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    if memory:
        env["OPENCODE_DB"] = ":memory:"
    start = len(requests)
    command = ["strace", "-f", "-yy", "-s", "256", "-e", "trace=%file,%network,%process,write,pwrite64,ftruncate,fsync,fdatasync,mmap,msync",
               "-o", str(root / "syscalls.log"), "bun", "--preload", "/work/packages/cli/node_modules/@opentui/solid/scripts/preload.js",
               "--tsconfig-override", "/work/packages/cli/tsconfig.json", "/work/packages/cli/src/index.ts", *arguments]
    with (root / "stdout.txt").open("w") as stdout, (root / "stderr.txt").open("w") as stderr:
        child = subprocess.Popen(command, cwd=work, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            child.wait(timeout=75)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    found = []
    files = []
    for file in sorted(root.rglob("*")):
        if not file.is_file() or file.name in {"syscalls.log", "stdout.txt", "stderr.txt"}:
            continue
        content = file.read_bytes()
        item = {"path": str(file.relative_to(root)), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        files.append(item)
        if MARKER.encode() in content and item["path"] != "workspace/context.txt":
            found.append(item["path"])
    report = {"scenario": name, "artifact_directory": root.name, "exit_code": child.returncode, "timed_out": timed_out,
              "requests": requests[start:], "files": files, "canary_files": found,
              "stdout_has_reply": (MARKER + "_REPLY") in (root / "stdout.txt").read_text(),
              "outside_xdg_exists": outside.exists(),
              "outside_xdg_has_canary": outside.exists() and MARKER in outside.read_text(),
              "model_refresh_enabled": model_refresh,
              "child_inherited_provider_key": any(
                  b"AUDIT_CHILD_HAS_PROVIDER_KEY=True" in file.read_bytes()
                  for file in (root / "data/opencode/shell").rglob("*.out")
              )}
    reports.append(report)
    print(json.dumps({k: v for k, v in report.items() if k not in {"files", "requests"}}), flush=True)


run("help", ["--help"])
run("persisted-chat", ["run", "--standalone", "--auto", "--format", "json", "--file", "context.txt", MARKER + "_PROMPT"])
run("memory-db-chat", ["run", "--standalone", "--auto", "--format", "json", MARKER + "_PROMPT"], memory=True)
run("model-refresh-enabled", ["run", "--standalone", "--auto", "--format", "json", MARKER + "_PROMPT"], model_refresh=True)
server.shutdown()
(OUT / "runtime-results.json").write_text(json.dumps(reports, indent=2) + "\n")
if any(item["exit_code"] != 0 or item["timed_out"] for item in reports):
    raise SystemExit(1)
if not all(item["stdout_has_reply"] and any(r["has_tool_result"] for r in item["requests"]) for item in reports[1:]):
    raise SystemExit("Conversation/tool round trip was not observed")
for report in reports[1:]:
    if not all(request["authorization_is_fixture"] for request in report["requests"]):
        raise SystemExit("Native provider did not use the synthetic credential")
    if not report["outside_xdg_has_canary"] or not report["child_inherited_provider_key"]:
        raise SystemExit("Expected upstream shell behavior was not reproduced")
    if not any(path.startswith("data/opencode/log/") for path in report["canary_files"]):
        raise SystemExit("Expected upstream prompt logging was not reproduced")
    if not any(path.startswith("data/opencode/shell/") for path in report["canary_files"]):
        raise SystemExit("Expected upstream shell output persistence was not reproduced")
    has_database = any(file["path"].endswith("opencode-local.db") for file in report["files"])
    if has_database != (report["scenario"] != "memory-db-chat"):
        raise SystemExit("Unexpected database persistence")
