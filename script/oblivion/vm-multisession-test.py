#!/usr/bin/env python3
"""Concurrent real LUKS/QEMU/systemd pairs; synthetic keys, no external network."""
import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path

CONFIG = "/run/oblivion-multisession-test.json"
BIN = "/usr/bin/oblivion-storage-lab"
GENERAL = b"synthetic-multi-general-password"
PASSWORD = b"synthetic-multi-session-password"
KEY_A = "OBLIVION_API_KEY_CANARY_5c91"  # gitleaks:allow synthetic canary, accepted only by the offline test provider
KEY_B = "OBLIVION_API_NEXT_CANARY_86ab"
ROOT = Path("/usr/lib/oblivion/vm")


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=150, **kwargs)
    assert result.returncode == 0, (args, result.stderr.decode())
    return result.stdout.decode().strip()


def command(operation, *args, slot=0, value=None, secret=b"", failure=None, expected=None, config=CONFIG):
    extra = ["--expected-session", expected] if expected else []
    result = subprocess.run([BIN, "--config", config, "--slot", str(slot), *extra, operation, *args],
        input=json.dumps(value).encode() if value is not None else secret, capture_output=True, timeout=150)
    if failure:
        assert result.returncode != 0 and result.stderr.decode().strip() == failure, (operation, result.stderr)
        return
    assert result.returncode == 0, (operation, slot, result.stderr.decode(), run("journalctl", "-n", "20", "--no-pager"))
    return result.stdout.decode().strip()


def status(slot=0):
    return json.loads(command("status", slot=slot))


def check(label):
    print("PASS: " + label, flush=True)


def prop(unit, name):
    return run("systemctl", "show", unit, "--property=" + name, "--value")


def console(slot):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(120)
    stream.connect(f"/run/oblivion-session-s{slot}/console.sock")
    stream.sendall(b"ready\n")
    wait_for(stream, "OBLIVION_GUEST_READY")
    return stream


def wait_for(stream, marker):
    data = b""
    end = time.monotonic() + 120
    while marker.encode() not in data:
        assert time.monotonic() < end, (marker, data[-1500:])
        chunk = stream.recv(65536)
        assert chunk, (marker, data[-1500:])
        data = (data + chunk)[-65536:]


def send(stream, operation, marker):
    stream.sendall(operation.encode() + b"\n")
    wait_for(stream, marker)


def pid(slot, role="session"):
    return int(prop(f"oblivion-{role}-s{slot}.service", "MainPID"))


def scoped_open(identifier, slot):
    command("enter-documents", identifier, slot=slot, secret=PASSWORD)
    assert status(slot)["active_session"] == identifier
    return console(slot)


def start(slot):
    end = time.monotonic() + 150
    while True:
        result = subprocess.run([BIN, "--config", CONFIG, "--slot", str(slot), "start-chat"], capture_output=True, timeout=120)
        if result.returncode == 0:
            break
        assert result.stderr.decode().strip() == "gateway_not_ready" and time.monotonic() < end, result.stderr
        time.sleep(.5)
    command("chat-ready", slot=slot)
    return console(slot)


def main():
    print("OBLIVION_MULTISESSION_FIXTURE_SHA256 " + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), flush=True)
    os.umask(0o077)
    print(run("unshare", "--net", "python3", "/run/test-host-firewall.py", "/run/host-firewall.nft"), flush=True)
    run("mkfs.ext4", "-q", "-m", "0", "/dev/vdb")
    run("mount", "/dev/vdb", "/data")
    config = {"general_image": "/data/general.luks", "general_mib": 1024, "session_mib": 128,
        "pbkdf_memory_kib": 65536, "manager_uid": 1000,
        "vm": {"root": str(ROOT / "qemu-root"), "kernel": str(ROOT / "kernel"), "initrd": str(ROOT / "initrd"),
            "filesystem": str(ROOT / "guest.squashfs"), "memory_mib": 512, "cpus": 1, "accelerator": "tcg"}}
    config["gateway"] = {**config["vm"], "filesystem": str(ROOT / "multisession-gateway.squashfs"), "memory_mib": 256}
    config["vm"]["initrd"] = str(ROOT / "session-initrd")
    Path(CONFIG).write_text(json.dumps(config))
    # Owner units must run the laboratory binary; production rejects TCG.
    for name in ["oblivion-gateway-host.service", "oblivion-gateway-host@.service"]:
        path = Path("/run/systemd/system") / (name + ".d")
        path.mkdir(parents=True, exist_ok=True)
        slot = " --slot %i" if "@" in name else ""
        (path / "fixture.conf").write_text(f"[Service]\nExecStart=\nExecStart={BIN} --config {CONFIG}{slot} gateway-host-run\nStandardError=append:/run/oblivion/gateway-error-%i.log\n")
    run("systemctl", "daemon-reload")
    command("init-general", secret=GENERAL)
    command("unlock", secret=GENERAL)
    for name, key in [("First", KEY_A), ("Second", KEY_B)]:
        command("api-keys", value={"action": "add", "provider": "abliteration-ai", "name": name, "key": key})
    keys = {key["name"]: key["id"] for key in status()["api_keys"]["entries"]}
    ids = [command("create", secret=PASSWORD) for _ in range(3)]
    a = scoped_open(ids[0], 1)
    check("first offline session ready")
    send(a, "write-a", "OBLIVION_A_WRITTEN")
    b = scoped_open(ids[1], 2)
    send(b, "check-b", "OBLIVION_B_ISOLATED")
    c = scoped_open(ids[2], 3)
    send(c, "probe", "OBLIVION_GUEST_CONFINED")
    assert {entry["id"] for entry in status()["open_sessions"]} == set(ids)
    command("enter-documents", ids[0], slot=4, secret=PASSWORD, failure="session_already_open")
    check("three simultaneous isolated volumes/VMs; duplicate opening rejected")
    for slot in [1, 2, 3]:
        data = Path(f"/proc/{pid(slot)}/status").read_text()
        uid = 16000 + slot * 16
        assert f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in data
        assert not Path(f"/proc/{pid(slot)}/root/run/oblivion/general").exists()
        assert not any(Path(f"/proc/{pid(slot)}/root/dev").glob("oblivion-session-s*"))
    command("close", slot=3)
    c.close()
    command("api-keys", slot=2, value={"action": "select", "id": keys["Second"]})
    command("api-keys", value={"action": "default", "id": keys["Second"]})
    assert status(1)["api_keys"]["selected"] == keys["First"]
    check("per-opening credentials remain pinned across global default changes")
    a.close(); b.close()
    a = start(1); b = start(2)
    send(a, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    send(b, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    send(a, "model-initial", "OBLIVION_MODEL_KEY_VERIFIED")
    send(b, "model-alternate", "OBLIVION_MODEL_KEY_VERIFIED")
    check("each model API request uses only the credential pinned to its session")
    before = {slot: (pid(slot), pid(slot, "gateway-vm")) for slot in [1, 2]}
    assert all(value > 0 for pair in before.values() for value in pair)
    for slot in [1, 2]:
        assert status(slot)["gateway_state"] == "active"
        guest_uid = 16000 + slot * 16
        other = 2 if slot == 1 else 1
        for path in [f"/run/oblivion-session-s{other}/console.sock", f"/run/oblivion-gateway-vm-s{other}/inside.sock"]:
            attempt = subprocess.run(["python3", "-c", "import socket,sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])", path], user=guest_uid, group=guest_uid, extra_groups=[], capture_output=True)
            assert attempt.returncode != 0
    check("two dedicated gateway VMs with disjoint identities and private wires")
    oversized = CONFIG + ".oversized"
    Path(oversized).write_text(json.dumps({**config, "vm": {**config["vm"], "memory_mib": 32768}}))
    command("enter-documents", ids[2], slot=3, secret=PASSWORD, config=oversized, failure="insufficient_session_memory")
    Path(oversized).unlink()
    assert not Path("/dev/mapper/oblivion-session-s3").exists()
    assert all((pid(slot), pid(slot, "gateway-vm")) == before[slot] for slot in [1, 2])
    check("insufficient RAM rejects a new opening without touching active sessions")
    command("stop-chat", slot=1)
    a.close()
    a = console(1)
    send(a, "probe", "OBLIVION_GUEST_CONFINED")
    assert status(1)["session_mode"] == "documents"
    assert (pid(2), pid(2, "gateway-vm")) == before[2]
    send(b, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    a.close()
    a = start(1)
    send(a, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    check("stopping/restarting one workspace leaves the other pair running")
    command("api-keys", value={"action": "replace", "id": keys["First"], "key": KEY_B}, failure="api_key_in_use")
    command("settings", slot=1, value={"action": "access", "mode": "offline", "save": True})
    assert status(1)["settings"]["current"]["web_access"] == "offline"
    assert status(2)["settings"]["current"]["web_access"] == "open"
    assert (pid(2), pid(2, "gateway-vm")) == before[2]
    send(a, "network-blocked", "OBLIVION_NETWORK_VERIFIED")
    send(b, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    command("network-policy", slot=1, value={"action": "put", "rule": {"destination": "example.org", "port": 443, "action": "deny"}, "save": True})
    assert status(2)["network_policy"]["policy"]["rules"] == []
    command("settings", slot=1, value={"action": "access", "mode": "strict", "save": True})
    send(a, "network-blocked", "OBLIVION_NETWORK_VERIFIED")
    allow = {"destination": "api.abliteration.ai", "port": 80, "action": "allow"}
    command("network-policy", slot=1, value={"action": "put", "rule": allow, "save": True})
    send(a, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    command("network-policy", slot=1, value={"action": "remove", "rule": allow, "save": True})
    send(a, "network-blocked", "OBLIVION_NETWORK_VERIFIED")
    send(b, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    assert status(2)["settings"]["current"]["web_access"] == "open"
    assert status(2)["network_policy"]["policy"]["rules"] == []
    command("settings", slot=1, value={"action": "access", "mode": "offline", "save": True})
    check("access/rules changes affect only the addressed session; active keys cannot be replaced")
    run("systemctl", "kill", "--signal=KILL", "oblivion-gateway-host@1.service")
    send(b, "network-ok", "OBLIVION_NETWORK_VERIFIED")
    assert (pid(2), pid(2, "gateway-vm")) == before[2]
    check("gateway owner failure in one slot does not interrupt the other session’s traffic")
    command("close", slot=1)
    a.close()
    assert (pid(2), pid(2, "gateway-vm")) == before[2]
    assert not Path("/dev/mapper/oblivion-session-s1").exists()
    # Reuse the slot and reject a delayed callback from its old session.
    c = scoped_open(ids[2], 1)
    command("close", slot=1, expected=ids[0], failure="session_changed")
    assert status(1)["active_session"] == ids[2]
    command("close", slot=1)
    c.close()
    a = scoped_open(ids[0], 1)
    send(a, "check-a", "OBLIVION_A_RESTORED")
    assert status(1)["settings"]["current"]["web_access"] == "offline"
    assert len(status(1)["network_policy"]["policy"]["rules"]) == 1
    assert status(1)["api_keys"]["selected"] == keys["Second"]
    command("api-keys", value={"action": "remove", "id": keys["First"]})
    check("close/reopen restores data and policy without restarting the other pair")
    command("lock", slot=2)
    a.close(); b.close()
    assert not status()["general_open"] and not status()["open_sessions"]
    for slot in [1, 2, 3]:
        assert not Path(f"/dev/mapper/oblivion-session-s{slot}").exists()
    check("global lock stops every pair and closes the general archive")
    with Path("/data/general.luks").open("rb") as file:
        saved = hashlib.file_digest(file, "sha256").hexdigest()
    command("unlock-ephemeral", secret=GENERAL)
    for slot in [1, 2]:
        command("enter-documents-ephemeral", slot=slot)
    a = console(1); b = console(2)
    send(a, "write-a", "OBLIVION_A_WRITTEN")
    send(b, "check-b", "OBLIVION_B_ISOLATED")
    command("settings", slot=1, value={"action": "access", "mode": "strict", "save": False})
    assert status(2)["settings"]["current"]["web_access"] == "open"
    command("close", slot=1)
    a.close()
    assert status(2)["session_mode"] == "documents"
    command("enter-documents-ephemeral", slot=1)
    a = console(1)
    send(a, "check-b", "OBLIVION_B_ISOLATED")
    assert status(1)["settings"]["current"]["web_access"] == "open"
    command("lock")
    a.close(); b.close()
    assert not status()["open_sessions"] and not status()["general_open"]
    with Path("/data/general.luks").open("rb") as file:
        assert hashlib.file_digest(file, "sha256").hexdigest() == saved
    check("concurrent ephemeral sessions are isolated, discarded on close, and leave the encrypted archive unchanged")
    print("OBLIVION_MULTISESSION_TESTS_PASSED", flush=True)


try:
    main()
except BaseException:
    for error in Path("/run/oblivion").glob("gateway-error-*.log"):
        print("OWNER ERROR: " + error.read_text(), flush=True)
    print(run("journalctl", "--no-pager", "-n", "80"), flush=True)
    raise
