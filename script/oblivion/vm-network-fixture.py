#!/usr/bin/python3
"""Typed diagnostics in a lab-only image. No user documents or real API keys."""
import base64
import hashlib
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
import tty
from pathlib import Path

ROLE = sys.argv[1]
API = ("10.88.0.1", 8111)
TOOLS = ("10.88.0.1", 8112)
canaries = []
stream = None
tools_streams = []


def run(*command, **options):
    return subprocess.run(command, check=True, capture_output=True, timeout=30, **options).stdout


def reply(value):
    print("OBLIVION_NET " + json.dumps(value, separators=(",", ":")), flush=True)


def tor(command):
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(10)
        control.connect("/run/tor/control")
        reader = control.makefile("rb")
        cookie = Path("/run/tor/control.authcookie").read_bytes().hex()
        control.sendall(("AUTHENTICATE " + cookie + "\r\n").encode())
        assert reader.readline() == b"250 OK\r\n"
        control.sendall((command + "\r\n").encode())
        lines = []
        while True:
            line = reader.readline().decode().strip()
            assert line.startswith("250"), line
            lines.append(line)
            if line.startswith("250 "):
                return "\n".join(lines)


def open_request(token):
    body = json.dumps({"model": "abliterated-model", "messages": [
        {"role": "user", "content": "synthetic network fixture"}], "stream": True})
    connection = socket.create_connection(API, timeout=10)
    connection.sendall(("POST /v1/chat/completions HTTP/1.1\r\nHost: gateway\r\n"
        f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
    return connection


def request(token):
    with open_request(token) as connection:
        data = b""
        while chunk := connection.recv(65536):
            data += chunk
            assert len(data) <= 65536
        return {"status": int(data.split(b" ", 2)[1]), "body": data.split(b"\r\n\r\n", 1)[1].decode()}


def open_tools(token, scheme, host="api.abliteration.ai", port=None):
    connection = socket.create_connection(TOOLS, timeout=10)
    auth = base64.b64encode(("oblivion-tools:" + token).encode()).decode()
    if scheme == "https":
        target = f"{host}:{port or 443}"
        connection.sendall((f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
            f"Proxy-Authorization: Basic {auth}\r\n\r\n").encode())
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            byte = connection.recv(1)
            assert byte and len(header) < 16384
            header += byte
        if not header.startswith(b"HTTP/1.1 200"):
            return connection, header
        context = ssl.create_default_context(cafile="/usr/lib/oblivion-transport-fixture/cert.pem")
        connection = context.wrap_socket(connection, server_hostname=host)
        connection.sendall(f"GET /tools HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        return connection, b""
    assert scheme == "http" and port is None
    connection.sendall((f"GET http://{host}/tools HTTP/1.1\r\nHost: {host}\r\n"
        f"Proxy-Authorization: Basic {auth}\r\nConnection: close, X-Local-Hop\r\n"
        "X-Local-Hop: synthetic-hop-header\r\n\r\n").encode())
    return connection, b""


def tools_request(token, scheme, host="api.abliteration.ai", port=None):
    connection, data = open_tools(token, scheme, host, port)
    with connection:
        while chunk := connection.recv(4096):
            data += chunk
            assert len(data) < 65536
    return {"status": int(data.split(b" ", 2)[1]), "body": data.split(b"\r\n\r\n", 1)[1].decode()}


def probes():
    # Treat the chat VM as compromised: root may replace routes and its firewall.
    run("ip", "route", "replace", "default", "via", "10.88.0.1", "dev", "chat0")
    run("nft", "flush", "ruleset")
    denied = []
    for host, port in [("10.88.0.1", 9050), ("10.88.0.1", 9051), ("10.88.0.1", 22),
        ("10.88.0.1", 53), ("10.0.2.2", 80), ("10.0.2.3", 53), ("169.254.169.254", 80),
        ("1.1.1.1", 443)]:
        with socket.socket() as client:
            client.settimeout(0.5)
            assert client.connect_ex((host, port)) != 0, (host, port)
        denied.append(f"{host}:{port}")
    for host, port in [("10.88.0.1", 53), ("10.0.2.3", 53), ("1.1.1.1", 443)]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b"OBLIVION_DENIED_UDP", (host, port))
    # Give the chat an IPv6 address and route; the gateway still drops IPv6.
    run("ip", "-6", "address", "replace", "fd00:88::2/64", "dev", "chat0")
    with socket.socket(socket.AF_INET6) as client:
        client.settimeout(0.5)
        assert client.connect_ex(("fd00:88::1", 9050)) != 0
    return {"tcp_denied": denied, "udp_probes_sent": 3, "ipv6_denied": True,
        "interfaces": sorted(p.name for p in Path("/sys/class/net").iterdir())}


def gateway(operation, configuration):
    if operation == "supervisor-info":
        pid = int(run("systemctl", "show", "oblivion-gateway-control.service", "--property=MainPID", "--value"))
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        expected = {"oblivion-api": 1300, "oblivion-egress": 1201}
        if configuration.get("tools", False):
            expected["oblivion-tools"] = 1301
        assert len(children) == len(expected)
        parent_status = Path(f"/proc/{pid}/status").read_text()
        assert "CapEff:\t00000000000010e3" in parent_status and "NoNewPrivs:\t1" in parent_status
        assert "Uid:\t0\t0\t0\t0" in parent_status
        processes = {}
        for value in children:
            child = Path("/proc") / value
            name = (child / "comm").read_text().strip()
            assert name in expected
            uid = expected[name]
            status = (child / "status").read_text()
            assert f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in status
            assert all(f"{field}:\t0000000000000000" in status for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"])
            assert "NoNewPrivs:\t1" in status and (child / "environ").read_bytes() == b""
            assert (child / "cmdline").read_bytes() == f"/usr/bin/{name}\0".encode()
            assert next(line.split()[4:6] for line in (child / "limits").read_text().splitlines() if line.startswith("Max core file size")) == ["0", "0"]
            processes[name] = int(value)
        assert set(processes) == set(expected)
        return {"supervisor_pid": pid, "broker_pid": processes["oblivion-api"], "broker_uid": 1300, "broker_caps": 0,
            "egress_pid": processes["oblivion-egress"], "egress_uid": 1201, "egress_caps": 0,
            **({"tools_pid": processes["oblivion-tools"], "tools_uid": 1301, "tools_caps": 0} if "oblivion-tools" in processes else {})}
    if operation in ["supervisor-crash", "broker-crash", "egress-crash", "tools-crash"]:
        pid = int(run("systemctl", "show", "oblivion-gateway-control.service", "--property=MainPID", "--value"))
        if operation != "supervisor-crash":
            name = {"broker-crash": "oblivion-api", "egress-crash": "oblivion-egress", "tools-crash": "oblivion-tools"}[operation]
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
            assert len(children) in [2, 3]
            pid = next(int(value) for value in children if Path(f"/proc/{value}/comm").read_text().strip() == name)
        os.kill(pid, signal.SIGKILL)
        return {"signalled": True}
    if operation == "supervisor-stopped":
        deadline = time.monotonic() + 20
        while True:
            state = run("systemctl", "show", "oblivion-gateway-control.service", "--property=ActiveState", "--value").decode().strip()
            tor_state = run("systemctl", "show", "oblivion-tor.service", "--property=ActiveState", "--value").decode().strip()
            if state in ["inactive", "failed"] and tor_state in ["inactive", "failed"]:
                break
            assert time.monotonic() < deadline, (state, tor_state)
            time.sleep(0.01)
        assert not any(path.read_text().strip() in ["oblivion-api", "oblivion-egress", "oblivion-tools"] for path in Path("/proc").glob("[0-9]*/comm"))
        selectors = gateway("transport-state", {})["selectors"]
        assert all(not values for values in selectors.values())
        return {"supervisor": state, "tor": tor_state, "broker_absent": True, "egress_absent": True, "tools_absent": True, "routes_empty": True}
    if operation == "transport-state":
        active = run("systemctl", "show", "oblivion-tor.service", "--property=ActiveState", "--value").decode().strip()
        sets = {entry["set"]["name"]: entry["set"].get("elem", []) for entry in json.loads(run("nft", "-j", "list", "ruleset"))["nftables"] if "set" in entry}
        return {"tor": active, "tor_state_file": Path("/var/lib/tor/state").exists(),
            "selectors": {name: sets[name] for name in ["proxy4", "tor_owners", "tor_connectors"]}}
    if operation == "proxy-probes":
        port, other = configuration["port"], configuration["other_port"]
        assert all(isinstance(value, int) and 1 <= value <= 65535 for value in [port, other])
        # A real listening canary makes local Tor bypass denials meaningful.
        with socket.socket() as canary:
            canary.bind(("127.0.0.1", 9050))
            canary.listen()
            for uid, address, target in [(1300, "10.0.2.2", port), (1200, "10.0.2.2", port),
                (1201, "10.0.2.2", other), (1300, "127.0.0.1", 9050), (1201, "127.0.0.1", 9050),
                (1301, "10.0.2.2", port), (1301, "127.0.0.1", 9050)]:
                result = subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "--",
                    "python3", "-c", "import socket,sys; s=socket.socket(); s.settimeout(.4); assert s.connect_ex((sys.argv[1],int(sys.argv[2]))) != 0", address, str(target)],
                    capture_output=True, timeout=5, env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
                assert result.returncode == 0
        return {"denied": 7}
    if operation == "rules":
        return json.loads(run("nft", "-j", "list", "ruleset"))
    if operation == "forwarding-on":
        run("busybox", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        return {"forwarding": True}
    if operation == "forwarding-off":
        run("busybox", "sysctl", "-q", "-w", "net.ipv4.ip_forward=0")
        return {"forwarding": False}
    if operation == "tor-enable":
        tor("SETCONF DisableNetwork=0")
        return {"enabled": True}
    if operation == "tor-restart-disabled":
        run("systemctl", "start", "oblivion-tor.service")
        deadline = time.monotonic() + 10
        while not all(Path(path).exists() for path in ["/run/tor/control", "/run/tor/control.authcookie"]):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert "DisableNetwork=1" in tor("GETCONF DisableNetwork")
        return {"active": True, "network_disabled": True}
    if operation == "tor-status":
        return {"bootstrapped": "PROGRESS=100" in tor("GETINFO status/bootstrap-phase")}
    if operation == "tor-check":
        result = subprocess.run(["setpriv", "--reuid=1201", "--regid=1201", "--clear-groups", "--",
            "curl", "--silent", "--show-error", "--fail", "--connect-timeout", "20", "--max-time", "90",
            "--socks5-hostname", "127.0.0.1:9050", "--proxy-user", "oblivion-lab:synthetic-check",
            "https://check.torproject.org/api/ip"], capture_output=True, timeout=95,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
        assert result.returncode == 0, result.stderr.decode()
        assert json.loads(result.stdout)["IsTor"] is True
        return {"is_tor": True, "verified_tls": True}
    if operation == "tor-crash":
        run("systemctl", "kill", "--signal=SIGKILL", "--kill-whom=main", "oblivion-tor.service")
        deadline = time.monotonic() + 5
        while subprocess.run(["systemctl", "is-active", "--quiet", "oblivion-tor.service"], timeout=5).returncode == 0:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        return {"stopped": True}
    if operation == "direct-denied":
        result = subprocess.run(["setpriv", "--reuid=1300", "--regid=1300", "--clear-groups", "--",
            "curl", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "2", "--max-time", "3",
            "https://1.1.1.1/"], capture_output=True, timeout=5, env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
        assert result.returncode != 0
        return {"api_uid_direct_denied": True}
    raise AssertionError("unknown gateway operation")


assert os.getuid() == 0
assert ROLE in ["gateway", "chat"]
assert len(Path("/proc/swaps").read_text().splitlines()) == 1
tty.setraw(0)
if ROLE == "gateway":
    assert run("systemctl", "show", "oblivion-tor.service", "--property=ActiveState", "--value").decode().strip() == "inactive"
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "0"
    # Actual listening sockets make negative ingress tests meaningful even if
    # a future service accidentally binds to the inside address.
    for port in [22, 53, 9050, 9051]:
        listener = socket.socket()
        listener.bind((API[0], port))
        listener.listen(4)
        canaries.append(listener)
else:
    interface = next(path.name for path in Path("/sys/class/net").iterdir()
        if (path / "address").read_text().strip() == "52:54:00:6f:00:03")
    run("ip", "link", "set", interface, "name", "chat0")
    run("ip", "address", "replace", "10.88.0.2/30", "dev", "chat0")
    run("ip", "link", "set", "chat0", "up")
reply({"ready": ROLE, "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
for line in sys.stdin:
    command = json.loads(line)
    assert set(command) <= {"id", "operation", "api_key", "token", "port", "other_port", "tools", "scheme"}
    try:
        if command["operation"] == "poweroff":
            reply({"id": command["id"], "ok": True})
            break
        if ROLE == "gateway":
            result = gateway(command["operation"], command)
        elif command["operation"] == "request":
            result = request(command["token"])
        elif command["operation"] == "tools-request":
            result = tools_request(command["token"], command["scheme"])
        elif command["operation"] == "tools-probes":
            assert tools_request("invalid", "https")["status"] == 407
            for host, port, expected in [("denied.example.com", 443, 403), ("ask.example.com", 443, 403),
                ("unknown.example.com", 443, 403), ("api.abliteration.ai", 444, 403), ("127.0.0.1", 443, 400)]:
                assert tools_request(command["token"], "https", host, port)["status"] == expected
            result = {"denied": 6}
        elif command["operation"] == "tools-stream-start":
            assert not tools_streams
            for scheme in ["http", "https"]:
                connection, data = open_tools(command["token"], scheme)
                tools_streams.append(connection)
                while b"Synthetic tools response" not in data:
                    chunk = connection.recv(4096)
                    assert chunk and len(data) < 65536
                    data += chunk
                assert data.startswith(b"HTTP/1.1 200")
            result = {"active": 2}
        elif command["operation"] == "tools-stream-closed":
            assert len(tools_streams) == 2
            for connection in tools_streams:
                size = 0
                try:
                    while chunk := connection.recv(4096):
                        size += len(chunk)
                        assert size < 65536
                except (ssl.SSLEOFError, ConnectionResetError):
                    pass
                connection.close()
            tools_streams.clear()
            result = {"closed": 2}
        elif command["operation"] == "stream-start":
            assert stream is None
            stream = open_request(command["token"])
            data = b""
            while b"data:" not in data:
                chunk = stream.recv(4096)
                assert chunk and len(data) < 65536
                data += chunk
            assert data.startswith(b"HTTP/1.1 200")
            result = {"active": True}
        elif command["operation"] == "stream-closed":
            assert stream is not None
            stream.settimeout(10)
            size = 0
            try:
                while chunk := stream.recv(4096):
                    size += len(chunk)
                    assert size < 65536
            except ConnectionResetError:
                pass
            stream.close()
            stream = None
            result = {"closed": True}
        elif command["operation"] == "probes":
            result = probes()
        elif command["operation"] == "disconnected":
            for address in [API, TOOLS]:
                with socket.socket() as connection:
                    connection.settimeout(1)
                    assert connection.connect_ex(address) != 0
            result = {"disconnected": True}
        else:
            raise AssertionError("unknown chat operation")
        reply({"id": command["id"], "ok": True, "result": result})
    except BaseException as error:
        reply({"id": command["id"], "ok": False, "error": type(error).__name__})
        raise
