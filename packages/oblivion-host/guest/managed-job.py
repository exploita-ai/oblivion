"""One fixed official headless client; task, output and manifest stay in its Safe."""

import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import threading

TASK_LIMIT = 16384
OUTPUT_LIMIT = 4 * 1024 * 1024
RECORD_LIMIT = 16
CANCELLED = threading.Event()
VERSIONS = {"codex": "0.159.2", "claude": "2.1.302", "opencode2": "2.0.1"}
HEADLESS = {
    "codex": ["exec", "--json", "--skip-git-repo-check", "--color", "never", "-"],
    "claude": ["--print", "--output-format", "stream-json", "--verbose", "--permission-prompts", "none"],
    "opencode2": ["run", "--standalone", "--format", "json"],
}
STATES = {"queued", "running", "completed", "failed", "cancelled"}
REASONS = {"needs-auth", "needs-input", "timeout", "output-limit", "interrupted", "agent-exit", "startup-failed", "cleanup-required"}


class Rejected(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def info(value):
    if not isinstance(value, dict) or set(value) != {"job_id", "request_id", "agent", "state", "native_chat_id", "reason"}:
        raise Rejected("recovery-required")
    native = value["native_chat_id"]
    if not identifier(value["job_id"]) or not identifier(value["request_id"]) or value["agent"] not in VERSIONS or value["state"] not in STATES:
        raise Rejected("recovery-required")
    if native is not None and (not isinstance(native, str) or not 0 < len(native.encode()) <= 256 or any(not char.isprintable() for char in native)):
        raise Rejected("recovery-required")
    if (value["state"] == "failed") != (value["reason"] is not None) or value["reason"] is not None and value["reason"] not in REASONS:
        raise Rejected("recovery-required")
    return value


def emit(value):
    print(json.dumps(value, separators=(",", ":"), ensure_ascii=True), flush=True)


def root(vault):
    home = os.open(vault / "home", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.mkdir(".oblivion-jobs", mode=0o700, dir_fd=home)
        except FileExistsError:
            pass
        descriptor = os.open(".oblivion-jobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
        owner = os.fstat(descriptor)
        if owner.st_uid != os.geteuid() or owner.st_mode & 0o077:
            os.close(descriptor)
            raise Rejected("storage-failed")
        return descriptor
    finally:
        os.close(home)


def read(target):
    descriptor = os.open("status.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=target)
    with os.fdopen(descriptor, "rb") as source:
        owner = os.fstat(source.fileno())
        if not stat.S_ISREG(owner.st_mode) or owner.st_nlink != 1 or owner.st_uid != os.geteuid() or owner.st_mode & 0o077 or not 0 < owner.st_size <= 4096:
            raise Rejected("recovery-required")
        record = json.loads(source.read(4097))
    if not isinstance(record, dict) or set(record) != {"version", "info", "output_bytes"} or type(record["version"]) is not int or record["version"] != 1 or type(record["output_bytes"]) is not int or not 0 <= record["output_bytes"] <= OUTPUT_LIMIT:
        raise Rejected("recovery-required")
    info(record["info"])
    return record


def write(target, record):
    info(record["info"])
    name = ".pending-status"
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write((json.dumps(record, separators=(",", ":")) + "\n").encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, "status.json", src_dir_fd=target, dst_dir_fd=target)
        os.fsync(target)
    finally:
        try:
            os.unlink(name, dir_fd=target)
        except FileNotFoundError:
            pass


def lease(directory):
    descriptor = os.open("active.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    owner = os.fstat(descriptor)
    if not stat.S_ISREG(owner.st_mode) or owner.st_nlink != 1 or owner.st_uid != os.geteuid() or owner.st_mode & 0o077:
        os.close(descriptor)
        raise Rejected("storage-failed")
    return descriptor


def inspect(directory, job_id):
    try:
        target = os.open(job_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        raise Rejected("not-found") from None
    try:
        record = read(target)
        if record["info"]["job_id"] != job_id:
            raise Rejected("recovery-required")
        if record["info"]["state"] in ("queued", "running"):
            active = lease(directory)
            try:
                try:
                    fcntl.flock(active, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    alive = False
                except BlockingIOError:
                    alive = os.pread(active, 33, 0) == job_id.encode()
                if not alive:
                    record["info"].update(state="failed", reason="interrupted")
                    write(target, record)
            finally:
                os.close(active)
        return record["info"]
    finally:
        os.close(target)


class Events:
    def __init__(self, agent):
        self.agent = agent
        self.native = None
        self.reason = None
        self.failed = False
        self.completed = False
        self.buffer = bytearray()
        self.skipping = False
        self.stderr = bytearray()

    def feed(self, kind, data):
        if kind == "stderr":
            self.stderr.extend(data)
            if len(self.stderr) > 16384:
                del self.stderr[:-16384]
            lowered = bytes(self.stderr).lower()
            if any(value in lowered for value in (b"not logged in", b"please run /login", b"authentication required", b"invalid api key", b"missing api key")):
                self.reason = "needs-auth"
            if b"permission requested:" in lowered or b"cannot ask the user" in lowered:
                self.reason = "needs-input"
            return
        for line in data.splitlines(keepends=True):
            if not self.skipping:
                self.buffer.extend(line)
                if len(self.buffer) > 65536:
                    self.buffer.clear()
                    self.skipping = True
            if line.endswith(b"\n"):
                if not self.skipping:
                    try:
                        self.event(json.loads(self.buffer))
                    except (ValueError, TypeError):
                        pass
                self.buffer.clear()
                self.skipping = False

    def event(self, event):
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        error = None
        if self.agent == "codex":
            if kind == "thread.started":
                self.native_id(event.get("thread_id"))
            if kind == "turn.completed":
                self.completed = True
                self.failed = False
            if kind in ("error", "turn.failed"):
                error = event.get("error", event)
        if self.agent == "claude":
            if kind in ("system", "result"):
                self.native_id(event.get("session_id"))
            if kind == "result" and event.get("subtype") == "success" and not event.get("is_error"):
                self.completed = True
            if kind == "result" and event.get("permission_denials"):
                self.reason = "needs-input"
            if kind == "result" and event.get("is_error"):
                error = event
        if self.agent == "opencode2":
            self.native_id(event.get("sessionID"))
            if kind == "step_finish":
                self.completed = True
            if kind == "error":
                error = event.get("error", {})
            part = event.get("part")
            if kind == "tool_use" and isinstance(part, dict):
                state = part.get("state")
                if isinstance(state, dict) and state.get("status") == "error":
                    failure = state.get("error", "")
                    if isinstance(failure, str) and any(value in failure.lower() for value in ("permission", "cannot ask", "question was cancelled")):
                        self.reason = "needs-input"
        if error is not None:
            self.failed = True
            text = json.dumps(error, ensure_ascii=True).lower()
            if any(value in text for value in ("invalid_api_key", "authentication", "unauthorized", "missing api key", "not logged in", '"status": 401', '"statuscode": 401')):
                self.reason = "needs-auth"
            elif any(value in text for value in ("approval", "permission prompt", "user input", "question was cancelled")):
                self.reason = "needs-input"

    def native_id(self, value):
        if not isinstance(value, str) or not value or len(value.encode()) > 256 or not all(char.isprintable() for char in value):
            return
        if self.agent in ("codex", "claude") and not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", value):
            return
        if self.agent == "opencode2" and not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,128}", value):
            return
        if self.native is None:
            self.native = value


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=2)
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # A successful leader exit does not prove that its descendants stopped.
    # The service cgroup also owns them and is removed with the hotplug port.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def execute(directory, job_id, agent, request_id, task, *, vault, deadline_seconds=1800):
    try:
        return inspect(directory, job_id)
    except Rejected as error:
        if error.code != "not-found":
            raise
    active = lease(directory)
    target = None
    try:
        try:
            fcntl.flock(active, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected("busy") from None
        records = 0
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= 64:
                    raise Rejected("quota")
                records += int(identifier(entry.name))
                if records >= RECORD_LIMIT:
                    raise Rejected("quota")
        os.pwrite(active, job_id.encode(), 0)
        os.ftruncate(active, 32)
        try:
            os.mkdir(job_id, mode=0o700, dir_fd=directory)
        except FileExistsError:
            return inspect(directory, job_id)
        target = os.open(job_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        task_fd = os.open("task.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
        with os.fdopen(task_fd, "wb") as output:
            output.write(task)
            output.flush()
            os.fsync(output.fileno())
        record = {"version": 1, "info": {"job_id": job_id, "request_id": request_id, "agent": agent,
                  "state": "queued", "native_chat_id": None, "reason": None}, "output_bytes": 0}
        write(target, record)
        emit({"kind": "status", "info": record["info"]})
        try:
            run(target, record, vault=vault, deadline_seconds=deadline_seconds)
        except Rejected as error:
            record["info"].update(state="failed", reason="cleanup-required" if error.code == "recovery-required" else "startup-failed")
            write(target, record)
        except subprocess.TimeoutExpired:
            record["info"].update(state="failed", reason="timeout")
            write(target, record)
        except (OSError, ValueError, subprocess.SubprocessError):
            record["info"].update(state="failed", reason="startup-failed")
            write(target, record)
        return record["info"]
    finally:
        if target is not None:
            os.close(target)
        os.close(active)


def run(target, record, *, vault, deadline_seconds):
    agent = record["info"]["agent"]
    environment = os.environ.copy()
    environment.update(HOME=str(vault / "home"), OTEL_SDK_DISABLED="true", DISABLE_TELEMETRY="1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
    stdout = os.open("stdout.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
    stderr = os.open("stderr.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
    process = None
    try:
        version = subprocess.run(["/usr/lib/oblivion/agents/bin/" + agent, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, timeout=15)
        if CANCELLED.is_set():
            record["info"].update(state="cancelled", reason=None)
            return
        if version.returncode != 0 or not re.search(r"(?<![0-9.])" + re.escape(VERSIONS[agent]) + r"(?![0-9.])", version.stdout[:256].decode("ascii", "ignore")):
            raise ValueError("unsupported_native_agent")
        source = os.open("task.txt", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=target)
        try:
            process = subprocess.Popen(["/usr/lib/oblivion/guest/agent.sh", agent, *HEADLESS[agent]],
                cwd=vault / "workspace", env=environment, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        finally:
            os.close(source)
        supervise(process, target, record, stdout, stderr, deadline_seconds=deadline_seconds)
    finally:
        if process is not None:
            try:
                stop(process)
            except (OSError, subprocess.SubprocessError):
                raise Rejected("recovery-required") from None
        os.fsync(stdout)
        os.fsync(stderr)
        os.close(stdout)
        os.close(stderr)
        write(target, record)


def supervise(process, target, record, stdout, stderr, *, deadline_seconds):
    events = Events(record["info"]["agent"])
    reason = None
    record["info"]["state"] = "running"
    write(target, record)
    emit({"kind": "status", "info": record["info"]})
    deadline = time.monotonic() + deadline_seconds
    with selectors.DefaultSelector() as selector:
        for source, destination, kind in ((process.stdout, stdout, "stdout"), (process.stderr, stderr, "stderr")):
            os.set_blocking(source.fileno(), False)
            selector.register(source, selectors.EVENT_READ, (destination, kind))
        while selector.get_map() or process.poll() is None:
            if CANCELLED.is_set():
                stop(process)
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                stop(process)
                break
            for key, _ in selector.select(0.1):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                remaining = OUTPUT_LIMIT - record["output_bytes"]
                if len(data) > remaining:
                    reason = "output-limit"
                    data = data[:remaining]
                if data:
                    view = memoryview(data)
                    while view:
                        count = os.write(key.data[0], view)
                        view = view[count:]
                    record["output_bytes"] += len(data)
                    events.feed(key.data[1], data)
                    if events.native and record["info"]["native_chat_id"] is None:
                        record["info"]["native_chat_id"] = events.native
                        write(target, record)
                        emit({"kind": "status", "info": record["info"]})
                if reason or events.reason:
                    reason = reason or events.reason
                    stop(process)
                    break
            if reason:
                break
    process.wait(timeout=4)
    if CANCELLED.is_set():
        record["info"].update(state="cancelled", reason=None)
    elif reason or events.reason or events.failed or process.returncode != 0 or not events.completed or events.native is None:
        record["info"].update(state="failed", reason=reason or events.reason or "agent-exit")
    else:
        record["info"].update(state="completed", reason=None)


def main():
    os.umask(0o077)
    if len(sys.argv) not in (3, 5) or sys.argv[1] not in ("start", "inspect") or not identifier(sys.argv[2]):
        raise ValueError("invalid_managed_job")
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, lambda _number, _frame: CANCELLED.set())
    directory = root(Path("/vault"))
    try:
        if sys.argv[1] == "inspect" and len(sys.argv) == 3:
            result = inspect(directory, sys.argv[2])
        elif sys.argv[1] == "start" and len(sys.argv) == 5 and sys.argv[3] in VERSIONS and identifier(sys.argv[4]):
            task = sys.stdin.buffer.read(TASK_LIMIT + 1)
            if not 0 < len(task) <= TASK_LIMIT or not task.decode().strip() or b"\0" in task:
                raise ValueError("invalid_managed_task")
            result = execute(directory, sys.argv[2], sys.argv[3], sys.argv[4], task, vault=Path("/vault"))
        else:
            raise ValueError("invalid_managed_job")
        emit({"kind": "status", "info": result})
        return 0 if result["state"] in ("completed", "queued", "running") else 1
    except Rejected as error:
        emit({"kind": "rejected", "error": error.code})
        return 1
    except Exception:
        emit({"kind": "rejected", "error": "storage-failed"})
        return 1
    finally:
        os.close(directory)


if __name__ == "__main__":
    raise SystemExit(main())
