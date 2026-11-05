"""One native CLI per hotplug port, with independent PTY or stdin/out/err pipes.

The host sends u32be JSON length followed by a tagged agent or workspace request. Terminal
is null for pipes or {rows, cols} for a PTY. Frames are u8 kind + u32be length
+ payload. Kinds: stdin=0, stdout=1, stderr=2, resize=3 (u16be rows, cols),
exit=4 (i32be status), stdin EOF=5, signal=6 (i32be Linux signal number).
"""
from contextlib import contextmanager
import errno
import fcntl
import json
import os
import pty
import re
import select
import selectors
import signal
import struct
import subprocess
import sys
import termios
import time

LIMIT = 65536
BUFFER = 1024 * 1024
SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH}


def request(fd):
    deadline = time.monotonic() + 30

    def receive(size):
        data = bytearray()
        while len(data) < size:
            timeout = deadline - time.monotonic()
            if timeout <= 0 or not select.select([fd], [], [], timeout)[0]:
                raise ValueError("agent_request_timeout")
            chunk = os.read(fd, size - len(data))
            if not chunk:
                raise EOFError()
            data.extend(chunk)
        return data

    size, = struct.unpack(">I", receive(4))
    if not 0 < size <= LIMIT:
        raise ValueError("invalid_agent_request")
    value = json.loads(receive(size))
    if not isinstance(value, dict):
        raise ValueError("invalid_agent_request")
    if value.get("kind") == "workspace":
        if set(value) != {"kind", "terminal"} or not isinstance(value["terminal"], dict):
            raise ValueError("invalid_workspace_request")
        terminal = value["terminal"]
        if set(terminal) != {"rows", "cols"} or any(type(terminal[key]) is not int or not 1 <= terminal[key] <= 1000 for key in ("rows", "cols")):
            raise ValueError("invalid_workspace_request")
        return value
    if set(value) != {"kind", "agent", "argv", "terminal", "managed"} or value["kind"] != "agent":
        raise ValueError("invalid_agent_request")
    if value["agent"] not in ("codex", "claude", "opencode2"):
        raise ValueError("invalid_agent_request")
    if not isinstance(value["argv"], list) or len(value["argv"]) > 1024:
        raise ValueError("invalid_agent_request")
    if any(not isinstance(arg, str) or "\0" in arg for arg in value["argv"]):
        raise ValueError("invalid_agent_request")
    if value["terminal"] is not None:
        terminal = value["terminal"]
        if not isinstance(terminal, dict) or set(terminal) != {"rows", "cols"}:
            raise ValueError("invalid_agent_request")
        if any(type(terminal[key]) is not int or not 1 <= terminal[key] <= 1000 for key in ("rows", "cols")):
            raise ValueError("invalid_agent_request")
    managed = value["managed"]
    if managed is not None:
        if not isinstance(managed, dict) or value["terminal"] is not None or value["argv"]:
            raise ValueError("invalid_managed_job")
        if managed.get("operation") == "start" and set(managed) == {"operation", "job_id", "request_id", "task"}:
            if not isinstance(managed["request_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", managed["request_id"]) or not isinstance(managed["task"], str) or not managed["task"].strip() or len(managed["task"].encode()) > 16384 or "\0" in managed["task"]:
                raise ValueError("invalid_managed_job")
        elif managed != {"operation": "inspect", "job_id": managed.get("job_id")}:
            raise ValueError("invalid_managed_job")
        if not isinstance(managed["job_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", managed["job_id"]):
            raise ValueError("invalid_managed_job")
    return value


def frame(kind, payload):
    return bytes([kind]) + struct.pack(">I", len(payload)) + payload
def stop_channel(_number, _frame):
    # Device removal stops this service with TERM. A scoped client is outside
    # its cgroup, so run's owned-process cleanup must receive the revocation.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    raise ConnectionAbortedError("agent_connection_closed")


@contextmanager
def owned_process(command, **options):
    process = None
    try:
        process = subprocess.Popen(command, **options)
        yield process
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def run(fd, value):
    terminal = value["terminal"]
    master = slave = None
    if terminal:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ,
                    struct.pack("HHHH", terminal["rows"], terminal["cols"], 0, 0))

    def child():
        if os.getuid() == 0:
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
        if terminal:
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
    if terminal:
        env.update(TERM="xterm-256color", COLORTERM="truecolor")
    managed = value.get("managed")
    command = (["/usr/lib/oblivion/guest/shell-workspace.sh"] if value["kind"] == "workspace"
               else ["/usr/lib/oblivion/guest/agent.sh", value["agent"], *value["argv"]])
    if managed is not None:
        command = ["/usr/bin/python3", "-B", "/usr/lib/oblivion/guest/managed-job.py", managed["operation"], managed["job_id"]]
        if managed["operation"] == "start":
            command.extend([value["agent"], managed["request_id"]])
    with owned_process(
        command,
        stdin=slave if terminal else subprocess.PIPE,
        stdout=slave if terminal else subprocess.PIPE,
        stderr=slave if terminal else subprocess.PIPE,
        cwd="/vault/workspace", env=env, start_new_session=True, preexec_fn=child,
    ) as process:
        if slave is not None:
            os.close(slave)
        source = {master: 1} if terminal else {process.stdout.fileno(): 1, process.stderr.fileno(): 2}
        stdin = master if terminal else process.stdin.fileno()
        incoming = bytearray()
        outbound = bytearray()
        pending_stdin = bytearray(managed["task"].encode() if managed is not None and managed["operation"] == "start" else b"")
        stdin_eof = managed is not None
        registered = {}
        exit_queued = False
        os.set_blocking(fd, False)
        for descriptor in {stdin, *source}:
            os.set_blocking(descriptor, False)

        try:
            with selectors.DefaultSelector() as selector:
                while True:
                    desired = {}
                    if len(pending_stdin) < BUFFER:
                        desired[fd] = selectors.EVENT_READ
                    if outbound:
                        desired[fd] = desired.get(fd, 0) | selectors.EVENT_WRITE
                    if len(outbound) < BUFFER:
                        for descriptor in source:
                            desired[descriptor] = selectors.EVENT_READ
                    if pending_stdin:
                        desired[stdin] = desired.get(stdin, 0) | selectors.EVENT_WRITE
                    for descriptor in set(registered) - set(desired):
                        selector.unregister(descriptor)
                    for descriptor, events in desired.items():
                        if descriptor not in registered:
                            selector.register(descriptor, events)
                        elif registered[descriptor] != events:
                            selector.modify(descriptor, events)
                    registered = desired
                    for key, events in selector.select(0.1):
                        descriptor = key.fd
                        if events & selectors.EVENT_WRITE:
                            buffer = outbound if descriptor == fd else pending_stdin
                            try:
                                count = os.write(descriptor, buffer[:LIMIT])
                                del buffer[:count]
                            except BlockingIOError:
                                pass
                            except BrokenPipeError:
                                if descriptor == fd:
                                    return
                                pending_stdin.clear()
                                stdin_eof = True
                        if not events & selectors.EVENT_READ:
                            continue
                        try:
                            data = os.read(descriptor, LIMIT)
                        except BlockingIOError:
                            continue
                        except OSError as error:
                            if descriptor != master or error.errno != errno.EIO:
                                raise
                            data = b""
                        if descriptor != fd:
                            if data:
                                outbound.extend(frame(source[descriptor], data))
                            else:
                                del source[descriptor]
                            continue
                        if not data:
                            return
                        incoming.extend(data)
                        while len(incoming) >= 5:
                            kind = incoming[0]
                            length, = struct.unpack(">I", incoming[1:5])
                            if length > LIMIT:
                                raise ValueError("invalid_agent_frame")
                            if len(incoming) < 5 + length:
                                break
                            payload = incoming[5:5 + length]
                            del incoming[:5 + length]
                            if kind == 0 and not stdin_eof:
                                pending_stdin.extend(payload)
                            elif kind == 3 and length == 4 and terminal:
                                rows, cols = struct.unpack(">HH", payload)
                                if not 1 <= rows <= 1000 or not 1 <= cols <= 1000:
                                    raise ValueError("invalid_agent_resize")
                                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                            elif kind == 5 and length == 0:
                                stdin_eof = True
                                if terminal:
                                    pending_stdin.extend(b"\x04")
                            elif kind == 6 and length == 4:
                                number, = struct.unpack(">i", payload)
                                if number not in SIGNALS:
                                    raise ValueError("invalid_agent_signal")
                                try:
                                    os.killpg(process.pid, number)
                                except ProcessLookupError:
                                    pass
                            else:
                                raise ValueError("invalid_agent_frame")
                    if stdin_eof and not pending_stdin and not terminal and not process.stdin.closed:
                        process.stdin.close()
                    if not exit_queued and process.poll() is not None and not source:
                        status = process.returncode
                        if status < 0:
                            status = 128 - status
                        outbound.extend(frame(4, struct.pack(">i", status)))
                        exit_queued = True
                    if exit_queued and not outbound:
                        return
        finally:
            if master is not None:
                os.close(master)


def main():
    if os.geteuid() not in (0, 1000) or len(sys.argv) != 2:
        raise ValueError("invalid_agent_service")
    path = sys.argv[1]
    if not re.fullmatch(r"/dev/vport[0-9]+p[0-9]+", path):
        raise ValueError("invalid_agent_port")
    name = os.path.basename(os.path.realpath(path))
    label = open(f"/sys/class/virtio-ports/{name}/name", encoding="ascii").read().strip()
    if not re.fullmatch(r"oblivion\.agent\.[0-9a-f]{32}", label):
        raise ValueError("invalid_agent_port")
    signal.signal(signal.SIGTERM, stop_channel)
    signal.signal(signal.SIGHUP, stop_channel)
    with open(path, "r+b", buffering=0) as stream:
        fd = stream.fileno()
        try:
            stream.write(b"ready\n")
            run(fd, request(fd))
        except (ValueError, EOFError, OSError, json.JSONDecodeError):
            # Request data, arguments and subprocess exceptions can contain
            # secrets. Only fixed protocol feedback crosses this boundary.
            try:
                os.write(fd, frame(2, b"The agent connection could not be completed.\n") + frame(4, struct.pack(">i", 125)))
            except OSError:
                pass


if __name__ == "__main__":
    main()
