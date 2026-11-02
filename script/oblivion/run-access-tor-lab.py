#!/usr/bin/env python3
"""Exercise global access with production Tor control; no reachable outside network."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import secrets
import shutil
import tempfile
import time

spec = importlib.util.spec_from_file_location("network_lab", Path(__file__).with_name("run-network-lab.py"))
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
network.validate_accelerator("hvf")
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
image = args.image.resolve()
output = args.output.resolve()
network.verify_image(image)
output.mkdir(parents=True, exist_ok=False)
shutil.copyfile(image / "initrd", output / "lab-initrd")
fixture = hashlib.sha256(Path(__file__).with_name("vm-network-fixture.py").read_bytes()).hexdigest()
checks = []
with tempfile.TemporaryDirectory(prefix="oblivion-access-tor-", dir="/tmp") as temporary:
    wire = Path(temporary) / "inside.sock"
    gateway = network.VM("gateway", image, output, wire, False)
    control = None
    try:
        deadline = time.monotonic() + 15
        while not (wire.parent / "control.sock").exists():
            assert gateway.process.poll() is None and time.monotonic() < deadline
            time.sleep(0.02)
        control = network.Control(wire.parent / "control.sock")
        gateway.ready(fixture)
        assert control.receive() == {"ready": True, "version": 1}
        assert control.call("configure", provider="abliteration-ai", api_key="synthetic-tor-policy-key", transport={"mode": "tor"})["configured"]
        control.call("tor-initialize", state=None)
        assert gateway.call("tor-network-state") == {"disabled": True}
        token = secrets.token_hex(32)
        policy = {"session": "a" * 32, "policy": {"version": 1, "rules": []}, "access": "open"}
        assert control.call("grant", token=token, tools=policy)["active"]
        # The host normally waits for bootstrap before granting. Here Tor starts
        # disabled and QEMU's restricted uplink prevents all real relay access.
        for mode in ["offline", "strict", "offline", "open", "offline"]:
            policy["access"] = mode
            assert control.call("policy", tools=policy)["active"]
            assert gateway.call("tor-network-state") == {"disabled": mode == "offline"}
            rules = [entry["rule"] for entry in gateway.call("rules")["nftables"] if "rule" in entry]
            for chain, interface in [("input", "iifname"), ("output", "oifname")]:
                first = next(rule for rule in rules if rule["chain"] == chain)["expr"]
                if mode == "offline":
                    assert first[0]["match"] == {"op": "==", "left": {"meta": {"key": interface}}, "right": "outside0"}
                    assert first[1] == {"drop": None}
                else:
                    assert first[0].get("match", {}).get("right") != "outside0"
            checks.append(f"{mode}: Tor DisableNetwork and first firewall rules match global policy")
            print("PASS:", checks[-1], flush=True)
        request = b'{"operation":"observe"}'
        control.socket.sendall(len(request).to_bytes(4, "big") + request)
        observed = control.receive()
        assert observed["isolated"] and not observed["ready"]
        checks.append("Offline observation never reports a ready Tor route")
        control.call("shutdown")
        gateway.call("supervisor-stopped")
        assert token.encode() not in (output / "gateway.log").read_bytes()
    finally:
        if control: control.close()
        gateway.stop()
(output / "summary.json").write_text(json.dumps({"passed": True, "scope": __doc__, "checks": checks,
    "image_manifest": (image / "SHA256SUMS").read_text(), "real_tor_bootstrap": False}, indent=2) + "\n")
print(json.dumps({"passed": True, "checks": len(checks)}))
