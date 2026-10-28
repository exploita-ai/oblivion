#!/usr/bin/python3 -B
"""Root diagnostics only in the disposable onion-control laboratory image."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tty


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=30).decode().strip()


def unit(name):
    values = dict(line.split("=", 1) for line in run("systemctl", "show", name,
        "--property=ActiveState,MainPID,Result,ExecMainStatus").splitlines())
    return {"active": values["ActiveState"], "pid": int(values["MainPID"]), "result": values["Result"], "exit_status": int(values["ExecMainStatus"])}


def inspect():
    owner = unit("oblivion-onion-gateway.service")
    tor = unit("oblivion-tor.service")
    assert run("systemctl", "show", "oblivion-tor.service", "--property=BindsTo", "--value") == "oblivion-onion-network.service"
    policy = run("nft", "--stateless", "--numeric", "list", "ruleset")
    rules = json.loads(run("nft", "--stateless", "--numeric", "--json", "list", "ruleset"))
    selectors = {entry["set"]["name"]: entry["set"].get("elem", []) for entry in rules["nftables"]
                 if "set" in entry and entry["set"]["name"] in ("tor_owners", "file_ports")}
    for process, uid, capabilities in ((owner, 0, "0000000000001003"), (tor, 1200, "0000000000000000")):
        if not process["pid"]:
            continue
        try:
            status = Path(f'/proc/{process["pid"]}/status').read_text()
        except FileNotFoundError:
            # PID 1 may still report MainPID during the exit/reap transition.
            # The runner waits for the final inactive/failed state and PID 0.
            continue
        assert f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in status
        assert "NoNewPrivs:\t1" in status
        assert f"CapEff:\t{capabilities}" in status
    assert Path("/proc/swaps").read_text().count("\n") == 1
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "0"
    assert Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() == "1"
    assert not any(Path("/usr/bin", name).exists() for name in ("oblivion-api", "oblivion-egress", "oblivion-tools", "oblivion-gateway-control"))
    assert not any(Path("/var/lib/tor").rglob("hs_ed25519*"))
    return {"owner": owner, "tor": tor, "selectors": selectors,
            "controller_sha256": hashlib.sha256(Path("/usr/bin/oblivion-onion-gateway").read_bytes()).hexdigest(),
            "policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
            "interfaces": sorted(path.name for path in Path("/sys/class/net").iterdir())}


def reply(value):
    print("OBLIVION_ONION_LAB " + json.dumps(value, separators=(",", ":")), flush=True)


tty.setraw(sys.stdin.fileno())
reply({"ready": True})
try:
    for line in sys.stdin:
        command = json.loads(line)
        if command == {"operation": "info"}:
            reply({"ok": True, **inspect()})
        elif command == {"operation": "kill-owner"}:
            owner = unit("oblivion-onion-gateway.service")
            assert owner["pid"] > 1
            os.kill(owner["pid"], signal.SIGKILL)
            reply({"ok": True})
        elif command == {"operation": "tamper"}:
            run("nft", "flush", "chain", "inet", "oblivion", "output")
            reply({"ok": True})
        elif command == {"operation": "shutdown"}:
            reply({"ok": True})
            break
        else:
            raise ValueError("Invalid laboratory command")
except Exception:
    reply({"ok": False, "error": "fixture_failed"})
    raise
