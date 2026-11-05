#!/usr/bin/env python3
"""Exercise the production bridge with a real controlling PTY and native pipes.

Run from packages/oblivion-host: python3 tests/native-overlay.py
The guest wire and manager process use synthetic data; no VM or user profile opens.
"""

from pathlib import Path
import tempfile, os, sys, socket, subprocess, pty, fcntl, termios, struct, select, time, json, shutil, signal, threading

package = Path(__file__).resolve().parents[1]
built = subprocess.run(
    ["cargo", "build", "--lib", "--message-format=json"],
    cwd=package,
    check=True,
    capture_output=True,
    text=True,
)
libraries = {}
for line in built.stdout.splitlines():
    value = json.loads(line)
    if value.get("reason") != "compiler-artifact" or value["target"]["name"] not in (
        "oblivion_host",
        "oblivion_cli",
        "libc",
    ):
        continue
    for filename in value["filenames"]:
        if filename.endswith(".rlib"):
            libraries[value["target"]["name"]] = Path(filename)
root = Path(tempfile.mkdtemp(prefix="oblivion-overlay-", dir="/tmp"))
(root / "harness.rs").write_text(
    r"""
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};
static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn signal(value: i32) {
    SIGNAL.store(value, Ordering::Relaxed);
}
fn size() -> oblivion_host::agent::Size {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut size) };
    oblivion_host::agent::Size {
        rows: size.ws_row.clamp(1, 1000),
        cols: size.ws_col.clamp(1, 1000),
    }
}
#[path = "{module}"]
mod native_overlay;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut stream = UnixStream::connect(&args[1]).unwrap();
    let interactive = args[2] == "tty";
    let mut saved = unsafe { std::mem::zeroed() };
    if interactive {
        unsafe {
            libc::tcgetattr(0, &mut saved);
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(0, libc::TCSANOW, &raw);
            libc::signal(libc::SIGWINCH, signal as *const () as libc::sighandler_t);
        }
    }
    let result = native_overlay::bridge(
        &mut stream,
        interactive,
        "12345678123442348234123456789abc",
        saved,
        if interactive { Some(oblivion_host::activity::Reporter::current_safe("12345678123442348234123456789abc").unwrap()) } else { None },
    );
    if interactive {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &saved);
        }
    }
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(70)
        }
    }
}
""".replace("{module}", str(package / "src/native_overlay.rs"))
)
command = [
    "rustc",
    "--edition=2024",
    str(root / "harness.rs"),
    "-L",
    "dependency=" + str(libraries["libc"].parent),
    "-o",
    str(root / "harness"),
]
for name, filename in libraries.items():
    command += ["--extern", name + "=" + str(filename)]
subprocess.run(command, check=True)
(root / "oblivion-manager").write_text(
    "#!"
    + sys.executable
    + "\n"
    + r"""
import os, sys, tty, termios, json
saved = termios.tcgetattr(0)
tty.setraw(0, when=termios.TCSANOW)
with open(os.environ["OVERLAY_TRACE"], "a") as trace:
    trace.write(json.dumps({"argv": sys.argv[1:], "group": os.getpgrp(), "foreground": os.tcgetpgrp(0)}) + "\n")
os.write(1, b"HOST_OVERLAY_READY")
try:
    while os.read(0, 1) != b"x":
        pass
finally:
    termios.tcsetattr(0, termios.TCSANOW, saved)
"""
)
os.chmod(root / "oblivion-manager", 0o700)
run = Path(tempfile.mkdtemp(prefix="obf-", dir="/tmp"))
listener = socket.socket(socket.AF_UNIX)
listener.bind(str(run / "s"))
listener.listen()
listener.settimeout(8)
control_listener = socket.socket(socket.AF_UNIX)
control_listener.bind(str(run / "control"))
os.chmod(run / "control", 0o600)
control_listener.listen()
control_listener.settimeout(0.1)
control_stop = threading.Event()
activity_received = threading.Event()
activity_reports = []


def frame(s, k, b):
    s.sendall(bytes([k]) + struct.pack(">I", len(b)) + b)


def exact(s, n):
    out = b""
    while len(out) < n:
        part = s.recv(n - len(out))
        if not part:
            raise EOFError()
        out += part
    return out


def receive(s):
    h = exact(s, 5)
    return h[0], exact(s, struct.unpack(">I", h[1:])[0])


def waittty(fd, needle, timeout=8):
    out = b""
    until = time.monotonic() + timeout
    while needle not in out:
        remaining = until - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise AssertionError(("missing tty marker", needle, out[-180:]))
        chunk = os.read(fd, 262144)
        if not chunk:
            raise AssertionError(("tty closed before marker", needle, out[-180:]))
        out += chunk
    return out


def drain(fd):
    out = b""
    while select.select([fd], [], [], 0)[0]:
        chunk = os.read(fd, 262144)
        if not chunk:
            break
        out += chunk
    return out


def controlling():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def controller():
    while not control_stop.is_set():
        try:
            request, _ = control_listener.accept()
        except socket.timeout:
            continue
        with request:
            size = struct.unpack(">I", exact(request, 4))[0]
            header = json.loads(exact(request, size))
            body = exact(request, header["secret_len"])
            assert header["version"] == 1
            if header["operation"] == "status":
                output = json.dumps({"idle_lock": {
                    "preferences": {"version": 1, "safe_minutes": 15, "host_minutes": 30},
                    "host": {"nonce": "a" * 32, "remaining_seconds": 1800, "closing": False},
                    "safes": [{"opening": {"slot": 0, "safe_id": "12345678123442348234123456789abc", "nonce": "b" * 32}, "remaining_seconds": 900, "closing": False}],
                    "last_error": None, "storage": "saved-encrypted", "writable": True,
                }})
            else:
                assert header["operation"] == "activity"
                activity_reports.append(json.loads(body))
                output = ""
            data = json.dumps({"ok": True, "output": output, "error": None}).encode()
            request.sendall(struct.pack(">I", len(data)) + data)
            if header["operation"] == "activity":
                activity_received.set()


control_thread = threading.Thread(target=controller, daemon=True)
control_thread.start()


master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
env = os.environ.copy()
env["OVERLAY_TRACE"] = str(run / "trace")
env["OBLIVION_CONTROL_SOCKET"] = str(run / "control")
# The production overlay requires the launcher's current typed runtime profile
# and a private generation. This fixture publishes metadata only: no image,
# helper, guest filesystem or VM is created or booted.
runtime = run / "runtime"
runtime.mkdir(mode=0o700)
backend = "apple-vz" if sys.platform == "darwin" else "qemu-kvm"
runtime_id = "1" * 32
settings = {
    "version": 1, "backend": backend,
    "bundle": {"bundle_id": "a" * 64, "source_sha256": "b" * 64,
               "boot": [{"path": "runtime/" + name, "sha256": "c" * 64,
                         "bytes": 1, "executable": False}
                        for name in ("controller.iso", "kernel", "initrd")]},
    "runtimeId": runtime_id, "kernel": str(runtime / "kernel"),
    "initrd": str(runtime / "initrd"),
    "commandLine": f"console=hvc0 oblivion.runtime=1 oblivion.runtime-backend={backend} oblivion.runtime-id={runtime_id}",
    "disks": [{"path": str(runtime / "controller.iso"), "readOnly": True},
              {"path": str(runtime / "storage.raw"), "readOnly": False}],
    "cpuCount": 4, "memoryMiB": 6144, "controlSocket": str(run / "control"),
    "controlPort": 4050, "network": True, "serialStdio": False,
}
if backend == "qemu-kvm":
    settings["guestCID"] = 45032
(runtime / "runtime.json").write_text(json.dumps(settings))
os.chmod(runtime / "runtime.json", 0o600)
lifecycle = run / "control.lifecycle"
lifecycle.mkdir(mode=0o700)
(lifecycle / ("2" * 32)).mkdir(mode=0o700)
(lifecycle / "generation.json").write_text(json.dumps({
    "version": 1, "id": "2" * 32, "runtime_id": runtime_id,
    "supervisor": None, "phase": "starting", "resident": False,
}))
os.chmod(lifecycle / "generation.json", 0o600)
env["OBLIVION_RUNTIME_DIRECTORY"] = str(runtime)
env["OBLIVION_RUNTIME_MODE"] = "desktop"
env.pop("OBLIVION_MANAGER_OWNER", None)
process = subprocess.Popen(
    [str(root / "harness"), str(run / "s"), "tty"],
    stdin=slave,
    stdout=slave,
    stderr=slave,
    env=env,
    preexec_fn=controlling,
)
os.close(slave)
peer, _ = listener.accept()
peer.settimeout(8)
try:
    frame(peer, 1, b"\x1b[?1049h\x1b[2J\x1b[HAGENT_VISIBLE")
    waittty(master, b"AGENT_VISIBLE")
    assert activity_reports == []
    os.write(master, b"\x1b[20~")
    opened = waittty(master, b"HOST_OVERLAY_READY")
    assert b"\x1b[?2004h" in opened, "paste must be framed before the overlay takes input"
    assert activity_received.wait(2), "human overlay key did not report activity"
    assert activity_reports[0] == {"host": "a" * 32, "safe": {"slot": 0, "safe_id": "12345678123442348234123456789abc", "nonce": "b" * 32}}
    # More than the socket buffers: completion requires the bridge to drain it.
    for _ in range(48):
        frame(peer, 1, b"HIDDEN_AGENT_OUTPUT " * 2500)
    frame(peer, 1, b"\x1b[2J\x1b[HAGENT_CONTINUED_OFFSCREEN\x1b[6n")
    kind, replies = receive(peer)
    assert kind == 0 and replies.startswith(b"\x1b[") and replies.endswith(b"R"), (
        kind,
        replies,
    )
    assert b"HIDDEN_AGENT_OUTPUT" not in drain(master)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    kind, payload = receive(peer)
    assert kind == 3 and payload == struct.pack(">HH", 30, 100), (kind, payload)
    os.write(master, b"xOVERLAY_QUEUED_INPUT")
    returned = waittty(master, b"AGENT_CONTINUED_OFFSCREEN")
    assert returned.count(b"AGENT_CONTINUED_OFFSCREEN") == 1
    kind, payload = receive(peer)
    assert kind == 6 and struct.unpack(">i", payload)[0] == 28, (kind, payload)
    os.write(master, b"z")
    assert receive(peer) == (0, b"z")
    # Coalesced input following F7 belongs to the overlay, never the agent.
    os.write(master, b"\x1b[18~x")
    waittty(master, b"HOST_OVERLAY_READY")
    kind, payload = receive(peer)
    assert kind == 6, (kind, payload)
    traces = [json.loads(line) for line in (run / "trace").read_text().splitlines()]
    assert len(traces) == 2
    assert all(x["group"] == x["foreground"] for x in traces)
    assert traces[0]["argv"][0:2] == ["--native-overlay", "network"]
    assert traces[1]["argv"][0:2] == ["--native-overlay", "files"]
    os.write(master, b"\x1b[20~")
    waittty(master, b"HOST_OVERLAY_READY")
    crashed = json.loads((run / "trace").read_text().splitlines()[-1])["group"]
    os.kill(crashed, signal.SIGKILL)
    waittty(master, b"AGENT_CONTINUED_OFFSCREEN")
    kind, payload = receive(peer)
    assert kind == 6
    # Failed exec must give the existing native process its terminal back.
    (root / "oblivion-manager").rename(root / "manager-unavailable")
    os.write(master, b"\x1b[20~")
    waittty(master, b"overlay could not open")
    os.write(master, b"k")
    assert receive(peer) == (0, b"k")
    (root / "manager-unavailable").rename(root / "oblivion-manager")
    os.write(master, b"\x1b[20~")
    waittty(master, b"HOST_OVERLAY_READY")
    frame(peer, 1, b"\x1b[?1049l")
    frame(peer, 4, struct.pack(">i", 7))
    assert process.wait(timeout=8) == 7
    print(
        "PTY ownership / scoped human activity / output drain / replies / resize / repaint / queued keys / crashed child / failed exec / native exit: PASS"
    )
finally:
    if (root / "manager-unavailable").exists():
        (root / "manager-unavailable").rename(root / "oblivion-manager")
    if process.poll() is None:
        process.kill()
        process.wait()
    peer.close()
    os.close(master)
process = subprocess.Popen(
    [str(root / "harness"), str(run / "s"), "pipe"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
peer, _ = listener.accept()
peer.settimeout(8)
try:
    raw = b"\x1b[18~\x00\xff\x1b[20~"
    process.stdin.write(raw)
    process.stdin.close()
    got = b""
    while True:
        kind, payload = receive(peer)
        if kind == 5:
            break
        assert kind == 0
        got += payload
    assert got == raw
    stdout = b"\x00\xff\x1b]52;c;fixture\x07"
    stderr = b"error\x00\xfe"
    frame(peer, 1, stdout)
    frame(peer, 2, stderr)
    frame(peer, 4, struct.pack(">i", 9))
    assert process.wait(timeout=8) == 9
    assert process.stdout.read() == stdout
    assert process.stderr.read() == stderr
    assert all(set(report) == {"host", "safe"} and set(report["safe"]) == {"slot", "safe_id", "nonce"} for report in activity_reports)
    assert b"HIDDEN_AGENT_OUTPUT" not in json.dumps(activity_reports).encode()
    print("Non-interactive binary stdin/stdout/stderr and exit status: PASS")
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
    peer.close()
    listener.close()
    control_stop.set()
    control_thread.join(timeout=1)
    control_listener.close()
    shutil.rmtree(run)
    shutil.rmtree(root)
