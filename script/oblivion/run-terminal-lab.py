#!/usr/bin/env python3
"""Boot actual offline session services and exercise the terminal through hvc1.

Synthetic ext4 fixture only: this checks guest deployment, not the outer LUKS
controller, physical power loss or forensic retention. No network or user data.
"""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--accelerator", choices=["hvf", "kvm", "tcg"], default="hvf")
parser.add_argument("--exports", action="store_true", help="Also qualify the deployed chat export service; requires an opencode-guest image")
parser.add_argument("--tools", action="store_true", help="Also qualify the production session tools; requires a session-tools or opencode-guest image")
parser.add_argument("--bridge", type=Path, default=Path(__file__).resolve().parents[2] / "packages/oblivion-host/target/debug/examples/viewport-probe")
args = parser.parse_args()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
image = args.image.resolve(strict=True)
bridge = args.bridge.resolve(strict=True)
output = args.output.resolve()
assert all("," not in str(path) for path in [image, output])
output.mkdir(parents=True, exist_ok=False)
for line in (image / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split()
    assert Path(name).name == name
    with (image / name).open("rb") as file:
        assert hashlib.file_digest(file, "sha256").hexdigest() == digest
shutil.copyfile(image / "vault.raw", output / "vault.raw")
architecture = "aarch64" if platform.machine() in ["arm64", "aarch64"] else "x86_64"
if args.accelerator == "hvf":
    assert platform.system() == "Darwin" and architecture == "aarch64"
if args.accelerator == "kvm":
    assert platform.system() == "Linux" and os.access("/dev/kvm", os.R_OK | os.W_OK)
cpu = "host" if args.accelerator != "tcg" else "cortex-a72" if architecture == "aarch64" else "max"
machine = "virt" if architecture == "aarch64" else "q35"
uart = "ttyAMA0" if architecture == "aarch64" else "ttyS0"
checks = []


def marker(value):
    # The expected marker never appears literally in echoed input.
    return "printf '" + "".join(f"\\{byte:03o}" for byte in (value + "\n").encode()) + "'"


def boot(index, verify):
    terminal = channels / "terminal.sock"
    qmp = channels / "qmp.sock"
    terminal.unlink(missing_ok=True)
    qmp.unlink(missing_ok=True)
    properties = ",dump-guest-core=off" if platform.system() == "Linux" else ""
    command = [f"qemu-system-{architecture}", "-machine", f"{machine},mem-merge=off{properties}", "-accel", args.accelerator,
               "-cpu", cpu, "-m", "1536" if args.exports else "768", "-smp", "2", "-nodefaults", "-no-reboot", "-display", "none", "-nic", "none",
               "-serial", f"file:{output}/kernel-{index}.log", "-qmp", f"unix:{qmp},server=on,wait=off",
               "-kernel", str(image / "kernel"), "-initrd", str(image / "initrd"),
               "-append", f"root=/dev/vda ro rootfstype=squashfs console={uart} systemd.getty_auto=no oblivion.documents=1 quiet loglevel=0",
               "-drive", f"file={image}/root.squashfs,format=raw,if=virtio,readonly=on",
               "-drive", f"file={output}/vault.raw,format=raw,if=virtio,cache=none",
               "-device", "virtio-serial-pci,id=serial", "-chardev", "null,id=unused", "-device", "virtconsole,chardev=unused,bus=serial.0",
               "-chardev", f"socket,id=terminal,path={terminal},server=on,wait=off", "-device", "virtconsole,chardev=terminal,bus=serial.0",
               "-chardev", "null,id=ready", "-device", "virtserialport,chardev=ready,name=oblivion.documents,bus=serial.0",
               "-device", "virtio-rng-pci"]
    with (output / f"qemu-{index}.log").open("wb") as log, subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log) as process:
        try:
            deadline = time.monotonic() + 90
            while not terminal.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert process.poll() is None and terminal.exists(), f"QEMU startup failed; inspect qemu-{index}.log"
            with subprocess.Popen([str(bridge), str(terminal)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log) as viewport, subprocess.Popen([str(bridge), "--screen"], stdin=viewport.stdout, stdout=subprocess.PIPE, stderr=log, bufsize=0) as screen, contextlib.ExitStack() as cleanup:
                cleanup.callback(viewport.stdin.close)
                captured = bytearray()
                current = ""

                def send(value):
                    viewport.stdin.write(json.dumps(value).encode() + b"\n")
                    viewport.stdin.flush()

                def input(data):
                    send({"type": "input", "data": list(data)})

                def resize(rows, cols):
                    send({"type": "resize", "cols": cols, "rows": rows})

                def expect(value):
                    nonlocal current
                    until = time.monotonic() + 60
                    while value not in current and time.monotonic() < until and process.poll() is None:
                        if not select.select([screen.stdout], [], [], 1)[0]:
                            continue
                        data = screen.stdout.readline()
                        if not data:
                            break
                        event = json.loads(data)
                        if event["type"] == "snapshot":
                            current = event["text"]
                            captured.extend(current.encode() + b"\n\n")
                        else:
                            assert event == {"type": "startup", "status": "started"}, "untrusted host event"
                        assert len(captured) <= 4 * 1024 * 1024, "terminal output limit"
                    (output / f"terminal-{index}.log").write_bytes(captured)
                    assert value in current, f"Missing {value}; inspect terminal/kernel logs"

                def run(command, expected):
                    input((command + " && " + marker(expected) + "\n").encode())
                    expect(expected)

                def rpc(value, number):
                    path = channels / f"export-{number}.sock"
                    with socket.socket(socket.AF_UNIX) as monitor:
                        monitor.connect(str(qmp)); monitor.settimeout(10)
                        reader = monitor.makefile("rb")
                        json.loads(reader.readline())

                        def execute(operation, arguments=None, retry=False):
                            monitor.sendall(json.dumps({"execute": operation, **({"arguments": arguments} if arguments else {})}).encode() + b"\n")
                            while True:
                                response = json.loads(reader.readline())
                                if "error" in response and retry:
                                    return False
                                assert "error" not in response, response
                                if "return" in response:
                                    return True

                        execute("qmp_capabilities")
                        execute("chardev-add", {"id": f"export{number}", "backend": {"type": "socket", "data": {
                            "addr": {"type": "unix", "data": {"path": str(path)}}, "server": True, "wait": False}}})
                        with socket.socket(socket.AF_UNIX) as channel:
                            channel.settimeout(95); channel.connect(str(path))
                            execute("device_add", {"driver": "virtserialport", "id": f"export{number}", "chardev": f"export{number}",
                                "bus": "serial.0", "name": "oblivion.archive." + f"{number:032x}"})

                            def read(size):
                                data = b""
                                while len(data) < size:
                                    part = channel.recv(size - len(data))
                                    assert part, "export channel closed"
                                    data += part
                                return data

                            assert read(6) == b"ready\n"
                            payload = json.dumps(value).encode()
                            channel.sendall(b"G" + len(payload).to_bytes(4, "big") + payload)
                            size = int.from_bytes(read(4), "big")
                            assert 0 < size <= 64 * 1024
                            result = json.loads(read(size))
                        execute("device_del", {"id": f"export{number}"})
                        # Match the production controller's detach barrier. QMP
                        # acknowledges device_del before the guest removes it.
                        until = time.monotonic() + 10
                        while not execute("chardev-remove", {"id": f"export{number}"}, retry=True):
                            assert time.monotonic() < until, "export device did not detach"
                            time.sleep(0.02)
                    assert result["result"] != "unavailable", result
                    return result

                resize(24, 80)
                expect("TERMINAL")
                run('test "$(id -u)" = 1000 && test "$(ls /sys/class/net | wc -l)" = 1 && test ! -e /run/oblivion-api/token && test -z "${HTTP_PROXY-}"', "OFFLINE_NONROOT_NO_KEY")
                if not verify:
                    run("printf terminal-persistence > /vault/workspace/terminal-check.txt", "FIRST_FILE_WRITTEN")
                    input(b"\x02c")
                    run('test "$(tmux -S /run/oblivion-terminal/tmux.sock list-windows | wc -l)" = 2', "SECOND_WINDOW_RUNNING")
                    input(b"\x02p")
                    expect("top -")
                    input(b"\x02c")
                    run('tmux -S /run/oblivion-terminal/tmux.sock kill-window -t Processes', "PROCESS_VIEW_CLOSED")
                    resize(30, 120)
                    run('test "$(stty size)" = "29 120"', "RESIZE_OK")
                    input(("sh -c \"" + marker("FOREGROUND_RUNNING") + "; exec sleep 30\"\n").encode())
                    expect("FOREGROUND_RUNNING")
                    input(b"\x03")
                    run("true", "INTERRUPT_WITHOUT_LOCK")
                    checks.extend(["offline nonroot terminal without key/NIC", "two real shell windows and process view", "resize and Ctrl+C", "workspace file written"])
                    if args.tools:
                        run("oblivion-tools --json | python3 -c 'import json,sys; m=json.load(sys.stdin); assert all(m[\"commands\"].values()) and m[\"components\"][\"node\"][\"version\"]'", "INSTALLED_TOOLS_MANIFEST_VALID")
                        run("curl --version >/dev/null && jq --version >/dev/null && pdftotext -v >/dev/null 2>&1", "BASE_TOOLS_AVAILABLE_OFFLINE")
                        run("node -e \"require('node:fs').writeFileSync('/vault/workspace/node-check.txt','node persisted')\"", "NODE_WORKSPACE_WRITE")
                        run("python3 -m venv /vault/workspace/.tool-venv && /vault/workspace/.tool-venv/bin/python -m pip --version >/dev/null", "PYTHON_VENV_OFFLINE")
                        run('test "$(npm config get cache)" = /tmp/oblivion-cache/npm && test "$(npm config get logs-max)" = 0 && test "$NODE_USE_ENV_PROXY" = 1 && test "$HISTFILE" = /dev/null', "TOOL_PRIVACY_DEFAULTS")
                        checks.append("production tool manifest, curl/jq/PDF, Node and Python venv work unprivileged with no NIC")
                    if args.exports:
                        seed = '''import importlib.util, tempfile
from pathlib import Path
p = Path("/usr/lib/oblivion/guest/chat-database.py")
s = importlib.util.spec_from_file_location("chat", p)
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
data = Path("/vault/state/opencode"); data.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=data) as d:
    with m.server("/usr/bin/oblivion", data / "oblivion.db", Path(d)) as call:
        chat = call("/api/session", {"title": "Guest export fixture", "location": {"directory": "/vault/workspace"}})
        call("/api/experimental/session/import", {"info": {**chat, "id": "ses_guest_export"}, "messages": [{"id": "msg_guest_export", "type": "user", "text": "GUEST_TRANSCRIPT_CONTENT", "time": {"created": 1700000000000}, "files": [], "agents": [], "skills": []}], "location": chat["location"]})
'''
                        run("python3 -c " + shlex.quote("exec(__import__('base64').b64decode('" + base64.b64encode(seed.encode()).decode() + "'))"), "CHAT_FIXTURE_READY")
                        listed = rpc({"action": "list", "cursor": None}, 1)
                        assert any(entry["id"] == "ses_guest_export" for entry in listed["entries"])
                        for number, format in enumerate(["json", "markdown"], 2):
                            result = rpc({"action": "export", "id": "ses_guest_export", "format": format}, number)
                            assert result["result"] == "exported" and result["bytes"] > 0
                            assert result["path"].startswith("workspace/chat-exports/")
                            run("grep -q GUEST_TRANSCRIPT_CONTENT " + shlex.quote("/vault/" + result["path"]), "EXPORTED_FILE_" + format.upper())
                        run('test -z "$(find /vault/state/opencode -maxdepth 1 -name ".chat-export-*")"', "EXPORT_STAGING_CLEANED")
                        report = {"version": 1, "controller_version": "0.1.0", "architecture": architecture, "cpu_cores": 2,
                            "memory_mib": 1536, "ephemeral": False, "general_open": True, "session": "documents", "transport": "offline",
                            "direct_access_blocked": True, "observation_age_ms": 0, "tor_bootstrap": None, "laboratory": True}
                        result = rpc({"action": "diagnostics", "report": report}, 4)
                        assert result["result"] == "exported" and result["path"].startswith("workspace/diagnostics/")
                        run("grep -q controller_version " + shlex.quote("/vault/" + result["path"]), "DIAGNOSTIC_REPORT_CONFIRMED")
                        for number in range(5, 11):
                            assert rpc({"action": "list", "cursor": None}, number)["result"] == "chats"
                        checks.append("ten sequential maintenance operations safely reuse guest virtio port slots")
                        run("mkdir /vault/state/opencode/.chat-export-vport0p9-interrupted && printf private > /vault/state/opencode/.chat-export-vport0p9-interrupted/snapshot.db && printf partial > /vault/workspace/chat-exports/.pending-vport0p9-interrupted.json", "CRASH_CLEANUP_FIXTURE_SEEDED")
                        checks.append("deployed network-isolated chat export service lists and exports JSON/Markdown inside the guest")
                        checks.append("deployed diagnostic writer produces an allowlisted report without provider access")
                else:
                    run('test "$(cat /vault/workspace/terminal-check.txt)" = terminal-persistence', "WORKSPACE_SURVIVED_REBOOT")
                    checks.append("workspace file survived clean guest reboot")
                    if args.tools:
                        run('test "$(cat /vault/workspace/node-check.txt)" = "node persisted" && /vault/workspace/.tool-venv/bin/python -m pip --version >/dev/null && test "$(npm config get logs-max)" = 0', "TOOL_WORKSPACE_PERSISTED")
                        checks.append("Node-created document and Python environment survive reboot; volatile npm defaults are reapplied")
                    if args.exports:
                        run('test -z "$(find /vault/state/opencode -maxdepth 1 -name ".chat-export-*")" && test -z "$(find /vault/workspace/chat-exports -maxdepth 1 -name ".pending-*")" && test "$(find /vault/workspace/chat-exports -name "*.json" | wc -l)" = 1', "BOOT_CLEANUP_PRESERVED_EXPORTS")
                        checks.append("session boot removes unfinished export staging and preserves completed transcripts")
                run("sync", "READY_FOR_SHUTDOWN")
                viewport.stdin.close()
                viewport.wait(timeout=5)
                assert viewport.returncode == 0
                viewport.stdout.close()
                screen.wait(timeout=5)
                assert screen.returncode == 0
            with socket.socket(socket.AF_UNIX) as monitor:
                monitor.connect(str(qmp)); monitor.settimeout(5)
                reader = monitor.makefile("rb")
                json.loads(reader.readline())
                for operation in ["qmp_capabilities", "system_powerdown"]:
                    monitor.sendall(json.dumps({"execute": operation}).encode() + b"\n")
                    while "return" not in json.loads(reader.readline()):
                        pass
            process.wait(timeout=30)
            assert process.returncode == 0
        finally:
            if process.poll() is None:
                process.kill(); process.wait()


with tempfile.TemporaryDirectory(prefix="oblivion-terminal-", dir="/tmp") as directory:
    channels = Path(directory)
    boot(1, False)
    boot(2, True)
report = {"passed": True, "scope": __doc__.strip(), "architecture": architecture, "accelerator": args.accelerator,
          "image_manifest": (image / "SHA256SUMS").read_text(), "checks": checks}
(output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
