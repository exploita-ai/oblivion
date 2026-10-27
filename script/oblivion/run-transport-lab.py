#!/usr/bin/env python3
"""External SOCKS path through two Debian VMs; only a native loopback fixture."""
import argparse
import hashlib
import importlib.util
import json
import platform
import resource
import secrets
import select
import shutil
import socket
import tempfile
import time
from pathlib import Path
from packet_capture import capture
from transport_fixture import KEY, PASSWORD, USERNAME, Proxy

spec = importlib.util.spec_from_file_location("network_lab", Path(__file__).with_name("run-network-lab.py"))
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--accelerator", choices=["hvf", "tcg"], default="hvf", help="Explicit lab backend: Mac HVF or Linux software emulation; never falls back")
    parser.add_argument("--authentication", choices=["required", "none"], default="required")
    parser.add_argument("--tools", action="store_true", help="Also exercise the supervised HTTP/CONNECT tools path with an explicit synthetic policy")
    parser.add_argument("--fault", choices=["revoke", "egress-crash", "broker-crash", "tools-crash", "supervisor-crash", "control-disconnect", "reconfigure"], default="egress-crash")
    args = parser.parse_args()
    assert args.fault != "tools-crash" or args.tools
    network.validate_accelerator(args.accelerator)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    image, output = args.image.resolve(), args.output.resolve()
    assert all("," not in str(path) for path in [image, output])
    network.verify_image(image)
    # Require the explicit, retained lab trust change. Production images never
    # trust this public fixture CA, and this runner makes no provider request.
    assert "add_root_certificate" in (image / "trust.diff").read_text()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(image / "initrd", output / "lab-initrd")
    checks = []
    started = time.monotonic()
    fixture_hash = hashlib.sha256(Path(__file__).with_name("vm-network-fixture.py").read_bytes()).hexdigest()
    summary = {"scope": "two read-only Debian ARM VMs with native loopback SOCKS/TLS fixture; no LUKS, host profile or OpenCode lifecycle",
        "accelerator": args.accelerator, "host_system": platform.system(), "hardware_isolation_verified": False,
        "passed": False, "checks": checks, "authentication": args.authentication, "fault": args.fault, "tools": args.tools,
        "provider_requests": False, "real_tor": False, "image_manifest": (image / "SHA256SUMS").read_text(),
        "fixture_sha256": fixture_hash,
        "sources": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in [Path(__file__).name, "run-network-lab.py", "transport_fixture.py", "packet_capture.py"]}}

    def check(message):
        checks.append(message)
        print("PASS: " + message, flush=True)

    proxy = Proxy(args.authentication == "required", args.tools,
        image / "fixture-cert.pem", image / "fixture-key.pem")
    tools = {"tools": {"session": "a" * 32, "policy": {"version": 1, "rules": [
        {"destination": "api.abliteration.ai", "port": port, "action": "allow", "session": "a" * 32}
        for port in [80, 443]
    ] + [
        {"destination": "denied.example.com", "port": 443, "action": "deny"},
        {"destination": "ask.example.com", "port": 443, "action": "ask"}
    ]}}} if args.tools else {}
    vms = []
    control = None
    try:
        proxy.start()
        with socket.socket() as canary, tempfile.TemporaryDirectory(prefix="oblivion-proxy-", dir="/tmp") as temporary:
            canary.bind(("127.0.0.1", 0))
            canary.listen()
            wire = Path(temporary) / "inside.sock"
            # QEMU's host alias reaches the loopback fixture. The production
            # gateway policy must admit precisely this endpoint and nothing else.
            gateway = network.VM("gateway", image, output, wire, True, args.accelerator)
            vms.append(gateway)
            deadline = time.monotonic() + 10
            while not wire.exists() or not (wire.parent / "control.sock").exists():
                assert gateway.process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            control = network.Control(wire.parent / "control.sock")
            chat = network.VM("chat", image, output, wire, True, args.accelerator)
            vms.append(chat)
            gateway.ready(fixture_hash)
            chat.ready(fixture_hash)
            assert control.receive() == {"ready": True, "version": 1}
            initial = gateway.call("transport-state")
            assert initial["tor"] == "inactive" and not initial["tor_state_file"]
            assert all(not values for values in initial["selectors"].values())
            shutil.copyfile(output / "gateway-outside.pcap", output / "before-configure.pcap")
            summary["before_configure"] = capture(output / "before-configure.pcap")
            assert summary["before_configure"]["ipv4"] == summary["before_configure"]["ipv6"] == 0
            check("startup has no Tor daemon, Tor state, selected route or IP traffic")
            transport = {"mode": "socks5", "endpoint": f"10.0.2.2:{proxy.port}", "authentication":
                {"username": USERNAME, "password": PASSWORD} if proxy.authenticated else None}
            assert not control.call("configure", provider="abliteration-ai", api_key=KEY, transport=transport)["active"]
            state = gateway.call("transport-state")
            assert state["tor"] == "inactive" and not state["tor_state_file"]
            assert state["selectors"]["tor_owners"] == state["selectors"]["tor_connectors"] == []
            assert state["selectors"]["proxy4"] == [{"concat": ["10.0.2.2", proxy.port]}]
            token = secrets.token_hex(32)
            assert control.call("grant", token=token, **tools)["active"]
            summary["processes"] = gateway.call("supervisor-info", tools=args.tools)
            check("SOCKS selection starts the expected grant processes, with distinct unprivileged UIDs and one firewall endpoint")
            assert chat.call("request", token="invalid")["status"] == 401
            assert proxy.snapshot().get("contacts", 0) == 0
            response = chat.call("request", token=token)
            assert response["status"] == 200 and "Synthetic transport response" in response["body"]
            proxy.wait("finished", 1)
            assert proxy.snapshot()["http_requests"] == 1
            check("valid grant streams verified HTTPS through SOCKS with remote domain resolution; invalid grant never contacts the proxy")
            if args.tools:
                assert chat.call("tools-probes", token=token) == {"denied": 6}
                assert proxy.snapshot()["contacts"] == 1
                check("tools reject invalid tokens, denied/ask/unknown destinations, wrong ports and private addresses before contacting SOCKS")
                for index, scheme in enumerate(["http", "https"], start=2):
                    response = chat.call("tools-request", token=token, scheme=scheme)
                    assert response["status"] == 200 and "Synthetic tools response" in response["body"]
                    proxy.wait("finished", index)
                assert proxy.snapshot()["tools_http"] == proxy.snapshot()["tools_https"] == 1
                check("tools HTTP and verified client-side HTTPS cross the real supervisor, firewall and policy connector without API key or local proxy headers at the destination")
            initial_contacts = proxy.snapshot()["contacts"]
            gateway.call("forwarding-on")
            probes = chat.call("probes")
            assert probes["interfaces"] == ["chat0", "lo"] and probes["ipv6_denied"]
            assert gateway.call("proxy-probes", port=proxy.port, other_port=canary.getsockname()[1]) == {"denied": 7}
            assert not select.select([canary], [], [], 0)[0]
            assert proxy.snapshot()["contacts"] == initial_contacts
            rules = gateway.call("rules")
            assert network.drops(rules, "input") > 0 and network.drops(rules, "forward") > 0
            (output / "rules-after-probes.json").write_text(json.dumps(rules, indent=2) + "\n")
            gateway.call("forwarding-off")
            check("compromised chat cannot forward; API/tools/Tor UIDs cannot use external SOCKS; API/tools/connector cannot bypass through local Tor")
            for mode in ["method-rejected", *(["auth-rejected"] if proxy.authenticated else []), "connect-rejected"]:
                proxy.mode = mode
                contacts = proxy.snapshot()["contacts"]
                assert chat.call("request", token=token)["status"] == 502
                proxy.wait("finished", contacts + 1)
                assert proxy.snapshot()[mode.replace("-", "_")] == 1
            assert proxy.snapshot()["http_requests"] == 1
            check("unoffered authentication methods, rejected credentials and CONNECT errors fail without TLS, retries or fallback")
            contacts = proxy.snapshot()["contacts"]
            proxy.stop()
            assert chat.call("request", token=token)["status"] == 502
            assert proxy.snapshot()["contacts"] == contacts
            check("a stopped SOCKS listener returns provider_unavailable without an alternative route")
            proxy.mode = "normal"
            proxy.start()
            assert chat.call("request", token=token)["status"] == 200
            proxy.wait("finished", contacts + 1)
            assert not control.call("revoke")["active"]
            assert chat.call("disconnected")["disconnected"]
            next_token = secrets.token_hex(32)
            assert control.call("grant", token=next_token, **tools)["active"]
            assert chat.call("request", token=token)["status"] == 401
            if args.tools:
                assert chat.call("tools-request", token=token, scheme="https")["status"] == 407
            check("proxy recovery keeps the chosen route; revocation closes the API listener and the next grant rejects the previous token")
            proxy.mode = "hold"
            contacts = proxy.snapshot()["contacts"]
            assert chat.call("stream-start", token=next_token) == {"active": True}
            proxy.wait("stream_started", 1)
            if args.tools:
                assert chat.call("tools-stream-start", token=next_token) == {"active": 2}
                proxy.wait("tools_stream_started", 2)
            if args.fault == "revoke":
                assert not control.call("revoke")["active"]
            elif args.fault == "control-disconnect":
                control.close()
            elif args.fault == "reconfigure":
                body = json.dumps({"operation": "configure", "provider": "abliteration-ai", "api_key": KEY, "transport": {"mode": "tor"}}).encode()
                control.socket.sendall(len(body).to_bytes(4, "big") + body)
                assert control.receive() == {"ok": False, "error": "control_failed"}
            else:
                gateway.call(args.fault)
            proxy.wait("stream_closed", 1)
            if args.tools:
                proxy.wait("tools_stream_closed", 2)
                assert chat.call("tools-stream-closed") == {"closed": 2}
                check(args.fault + " closes both active tools HTTP and CONNECT/TLS streams at the external peer and chat")
            proxy.wait("finished", contacts + (3 if args.tools else 1))
            assert chat.call("stream-closed") == {"closed": True}
            check(args.fault + " closes an established upstream TLS stream and the chat response")
            if args.fault == "revoke":
                assert not control.call("shutdown")["active"]
            # EOF from a crashed connector precedes the supervisor's child-exit
            # observation. Require its bounded shutdown before checking listeners.
            summary["stopped"] = gateway.call("supervisor-stopped")
            assert chat.call("disconnected")["disconnected"]
            state = gateway.call("transport-state")
            assert not state["tor_state_file"] and state["tor"] in ["inactive", "failed"]
            check("shutdown removes all grant processes and route permissions; SOCKS never starts or writes Tor state")
            gateway.stop()
            chat.call("poweroff")
            chat.process.wait(timeout=30)
            chat.reader.join(timeout=10)
            summary["proxy"] = proxy.snapshot()
            assert summary["proxy"]["contacts"] == summary["proxy"]["single_method"]
            summary["captures"] = {path.name: capture(path) for path in output.glob("*.pcap")}
            outside = summary["captures"]["gateway-outside.pcap"]
            assert outside["tcp"] > 0 and outside["ipv4"] == outside["tcp"]
            assert outside["udp"] == outside["ipv6"] == outside["ipv4_fragments"] == 0
            assert all((source, sport) == ("10.0.2.2", proxy.port) or (destination, dport) == ("10.0.2.2", proxy.port)
                for source, sport, destination, dport in outside["tcp_flows"])
            raw = (output / "gateway-outside.pcap").read_bytes()
            assert all(value.encode() not in raw for value in [KEY, token, next_token])
            for role in ["chat", "gateway"]:
                log = (output / f"{role}.log").read_bytes()
                assert all(value.encode() not in log for value in [KEY, PASSWORD, token, next_token])
            check("full outside capture contains only TCP to the configured proxy, no cleartext API key or local token, no DNS/UDP/IPv6; VM consoles contain no secrets")
            summary["passed"] = True
    finally:
        if control is not None:
            control.close()
        for vm in vms:
            vm.stop()
        proxy.stop()
        summary["seconds"] = round(time.monotonic() - started, 2)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps({"passed": summary["passed"], "checks": len(checks), "seconds": summary["seconds"]}), flush=True)


if __name__ == "__main__":
    main()
