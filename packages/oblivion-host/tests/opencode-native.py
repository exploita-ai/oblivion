"""Offline native evidence, separate from the real systemd/cgroup VM gate.

Run as UID1000 in a fresh /vault tmpfs with the pinned 2.0.1 binary. Uses the
production exec handoff, two actual TUIs and the native server/API/database.
No provider request, fake server or replacement agent participates.
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import struct
import subprocess
import termios
import threading

EXEC = "/usr/lib/oblivion/guest/opencode-exec.sh"
BINARY = "/usr/lib/oblivion/agents/bin/opencode2"
TITLE = "Oblivion native fixture · $HOME 'quotes'"
ENV = {"PATH": os.defpath, "HOME": "/vault/home", "LANG": "C.UTF-8", "TERM": "xterm-256color", "COLORTERM": "truecolor",
       "OPENCODE_DISABLE_MODELS_FETCH": "1", "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
       "OPENCODE_DISABLE_FILEWATCHER": "1", "OPENCODE_DISABLE_FFF": "1"}


def stop(process):
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def api(method, path, payload=None):
    command = [EXEC, "api", method, path]
    if payload is not None:
        command.extend(["--data", json.dumps(payload)])
    result = subprocess.run(command, env=ENV, cwd="/vault/workspace", stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    assert result.returncode == 0, "official native API command failed"
    return json.loads(result.stdout)


def start():
    process = subprocess.Popen([EXEC, "serve", "--service", "--hostname", "127.0.0.1", "--port", "0"],
                               env=ENV, cwd="/vault/workspace", stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        assert select.select([process.stdout], [], [], 20)[0], "native server readiness timeout"
        assert process.stdout.readline(4096).startswith(b"server listening on http://127.0.0.1:"), "native server did not become ready"
        return process
    except BaseException:
        stop(process)
        raise


def tui():
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))

    def controlling_terminal():
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    process = subprocess.Popen([EXEC], env=ENV, cwd="/vault/workspace", stdin=slave,
                               stdout=slave, stderr=slave, start_new_session=True, preexec_fn=controlling_terminal)
    os.close(slave)
    rendered = threading.Event()

    def drain():
        while process.poll() is None:
            if not select.select([master], [], [], 0.1)[0]:
                continue
            try:
                if not os.read(master, 65536):
                    return
                rendered.set()
            except OSError:
                return

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    try:
        assert rendered.wait(timeout=15), "official TUI did not render"
        assert process.poll() is None, "official TUI exited during startup"
        return process, master, thread
    except BaseException:
        stop(process)
        os.close(master)
        thread.join(timeout=3)
        raise


def main():
    assert os.getuid() == 1000, "requires an isolated Linux UID1000 fixture"
    assert any(row.split()[4] == "/vault" and row.partition(" - ")[2].startswith("tmpfs ")
               for row in Path("/proc/self/mountinfo").read_text().splitlines()), "requires a disposable /vault tmpfs, never a Safe volume"
    assert all(entry.name in ("home", "state", "config", "workspace") and entry.is_dir()
               and not entry.is_symlink() and not any(entry.iterdir())
               for entry in Path("/vault").iterdir()), "requires a fresh empty fixture"
    assert subprocess.run([BINARY, "--version"], env=ENV, check=True, capture_output=True, timeout=15).stdout.strip() == b"opencode v2.0.1"
    for name in ("home", "state", "config", "workspace"):
        (Path("/vault") / name).mkdir(mode=0o700, exist_ok=True)
    subprocess.run(["/bin/sh", "-eu", "-c", '. /usr/lib/oblivion/guest/safe-environment.sh; . /usr/lib/oblivion/guest/agent-profiles/common.sh; initialize_agent_config /usr/lib/oblivion/guest/agent-profiles/opencode2.json "$XDG_CONFIG_HOME/opencode/opencode.json"'], env=ENV, check=True, timeout=10)
    server = None
    clients = []
    try:
        server = start()
        created = api("POST", "/api/session", {"title": TITLE, "location": {"directory": "/vault/workspace"}})
        identity = created["data"]["id"]
        clients.append(tui())
        clients.append(tui())
        stop(clients[0][0])
        assert clients[1][0].poll() is None, "closing the first TUI stopped the second"
        assert server.poll() is None, "closing the first TUI stopped the independently owned native server"
        assert api("GET", f"/api/session/{identity}")["data"]["title"] == TITLE
        stop(clients[1][0])
        stop(server)
        server = start()
        resumed = api("GET", f"/api/session/{identity}")["data"]
        assert resumed["id"] == identity and resumed["title"] == TITLE
        with sqlite3.connect("file:/vault/state/opencode/opencode.db?mode=ro", uri=True) as database:
            assert database.execute("SELECT title FROM session_v2 WHERE id=?", (identity,)).fetchone() == (TITLE,)
        print("PASS: pinned OpenCode2, two actual TUIs, first-close continuity and native session metadata after server restart.")
        print("OPEN GATES: real systemd scope/cgroup shutdown, provider/tool conversation history, Safe reboot and encrypted media.")
    finally:
        for process, master, thread in clients:
            stop(process)
            os.close(master)
            thread.join(timeout=3)
        if server is not None:
            stop(server)


if __name__ == "__main__":
    os.umask(0o077)
    main()
