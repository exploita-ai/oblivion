#!/usr/bin/python3
"""Run as root with unshare --net in the debug image; no host interfaces change."""
import json
import os
import subprocess

assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net"), "Use unshare --net"


def run(*args):
    return subprocess.check_output(args, text=True)


def networks():
    run("/usr/lib/oblivion/hardware/ssh_control.py", "refresh")
    table = json.loads(run("nft", "-j", "list", "table", "inet", "oblivion_hardware"))
    rules = [entry["rule"] for entry in table["nftables"] if "rule" in entry]
    assert any({"drop": None} in rule["expr"] for rule in rules), "SSH deny rule must remain"
    return next(entry["set"].get("elem", []) for entry in table["nftables"] if "set" in entry)


assert not networks(), "No address must deny all SSH without failing refresh"
run("ip", "link", "add", "debug-test", "type", "dummy")
run("ip", "link", "set", "debug-test", "up")
run("ip", "address", "add", "192.168.50.2/24", "dev", "debug-test")
assert networks(), "Private subnet must become available"
run("ip", "address", "flush", "dev", "debug-test")
assert not networks(), "Losing DHCP must remove the old allow rule"
run("ip", "address", "add", "192.168.51.2/24", "dev", "debug-test")
assert networks() == [{"prefix": {"addr": "192.168.51.0", "len": 24}}]
run("ip", "address", "flush", "dev", "debug-test")
run("ip", "address", "add", "203.0.113.2/24", "dev", "debug-test")
assert not networks(), "Public subnets must not enable diagnostics"
print("PASS: empty network, private subnet, DHCP loss, new subnet, public subnet")
