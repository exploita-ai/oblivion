#!/usr/bin/env python3
"""Run in an isolated installed session image as uid 1000, with synthetic state.

The fixture needs /vault and the three /run/oblivion-* directories, a synthetic
provider capability and a local server password. No provider request is sent.
"""
import base64
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import time
import urllib.request

assert os.getuid() == 1000
env = {
    **os.environ, "HOME": "/vault/home", "XDG_CONFIG_HOME": "/vault/config",
    "XDG_DATA_HOME": "/vault/state", "XDG_STATE_HOME": "/vault/state",
    "XDG_CACHE_HOME": "/tmp/oblivion-cache", "TERM": "xterm-256color",
    "COLORTERM": "truecolor", "OPENCODE_DISABLE_MODELS_FETCH": "1",
}
password = Path("/run/oblivion-chat/password").read_text()
headers = {"Authorization": "Basic " + base64.b64encode(("opencode:" + password).encode()).decode(),
           "Content-Type": "application/json"}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(route, body=None):
    request = urllib.request.Request("http://127.0.0.1:4096/api/" + route, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
    with opener.open(request, timeout=5) as response:
        value = json.load(response)
        return value.get("data", value)


def tmux(*args):
    return subprocess.check_output(["tmux", "-S", "/run/oblivion-terminal/tmux.sock", *args], text=True).strip()


server = subprocess.Popen(["/usr/lib/oblivion/guest/chat-server.sh"], env=env, cwd="/vault/workspace",
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
viewer = None
master = None
try:
    subprocess.run(["python3", "/usr/lib/oblivion/guest/chat-ready.py"],
                   env={**env, "OPENCODE_PASSWORD": password}, check=True, timeout=50)
    template = api("session", {"title": "Workspace template", "location": {"directory": "/vault/workspace"}})
    sessions = [{**template, "id": "ses_workspace_" + word, "title": "Workspace fixture " + word}
                for word in ("one", "two")]
    for session in sessions:
        api("experimental/session/import", {"info": session, "location": template["location"], "messages": [{
            "id": "msg_workspace_" + session["id"], "type": "user", "text": session["title"],
            "time": {"created": 1700000000000}, "files": [], "agents": [], "skills": [],
        }]})
    master, slave = pty.openpty()
    viewer = subprocess.Popen(["/usr/libexec/oblivion"], env=env, cwd="/vault/workspace",
                              stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)

    output = bytearray()

    def until(predicate):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                output.extend(os.read(master, 65536))
                del output[:-65536]
            if predicate():
                return
        raise AssertionError("Workspace did not reach the expected state")

    # The real serial viewer waits for host size before starting tmux.
    until(lambda: b"oblivion;ready" in output)
    os.write(master, b"\x1b[8;50;160t")
    until(lambda: Path("/run/oblivion-terminal/tmux.sock").exists())
    until(lambda: "Workspace fixture two" in tmux("capture-pane", "-p", "-t", "0.0"))
    first = tmux("display-message", "-p", "#{pane_id}")
    fresh = tmux("split-window", "-h", "-P", "-F", "#{pane_id}", "/usr/bin/chat")
    until(lambda: "privacy-first" in tmux("capture-pane", "-p", "-t", fresh))
    assert "Workspace fixture two" not in tmux("capture-pane", "-p", "-t", fresh)
    tmux("kill-pane", "-t", fresh)
    second = tmux("split-window", "-h", "-P", "-F", "#{pane_id}",
                  "/usr/bin/chat --session " + sessions[0]["id"])
    until(lambda: "Workspace fixture one" in tmux("capture-pane", "-p", "-t", second))
    assert "Workspace fixture two" in tmux("capture-pane", "-p", "-t", first)
    assert server.poll() is None
    print("PASS two independent chat clients share one authenticated server", flush=True)

    terminal = tmux("split-window", "-v", "-P", "-F", "#{pane_id}")
    tmux("send-keys", "-t", terminal, "printf workspace-test > /vault/workspace/panes.txt", "Enter")
    until(lambda: Path("/vault/workspace/panes.txt").exists())
    tmux("kill-pane", "-t", second)
    assert server.poll() is None
    assert len(api("session")) == 3
    assert "Workspace fixture two" in tmux("capture-pane", "-p", "-t", first)
    print("PASS closing a chat pane preserves the server, other pane and conversations", flush=True)

    # Native tmux reattachment preserves panes and shell jobs.
    original = tmux("list-panes", "-F", "#{pane_pid}")
    viewer.terminate()
    viewer.wait(timeout=5)
    os.close(master)
    master, slave = pty.openpty()
    viewer = subprocess.Popen(["/usr/libexec/oblivion"], env=env, cwd="/vault/workspace",
                              stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    output.clear()
    until(lambda: b"oblivion;ready" in output)
    os.write(master, b"\x1b[8;24;80t")
    until(lambda: tmux("display-message", "-p", "#{window_width}") == "80")
    assert tmux("list-panes", "-F", "#{pane_pid}") == original
    assert Path("/vault/workspace/panes.txt").read_text() == "workspace-test"
    print("PASS reattachment and resize preserve panes and files", flush=True)
    output.clear()
    tmux("select-pane", "-t", first)
    tmux("send-keys", "-t", first, "/exit")
    until(lambda: "Close and lock session" in tmux("capture-pane", "-p", "-t", first))
    tmux("send-keys", "-t", first, "Enter")
    until(lambda: b"\x1b]777;oblivion;close\x07" in output)
    assert server.poll() is None
    print("PASS /exit requests host confirmation without stopping the server", flush=True)
finally:
    if viewer:
        viewer.terminate()
        viewer.wait(timeout=5)
    if master is not None:
        os.close(master)
    subprocess.run(["tmux", "-S", "/run/oblivion-terminal/tmux.sock", "kill-server"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server.terminate()
    server.wait(timeout=15)
