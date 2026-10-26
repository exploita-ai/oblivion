#!/usr/bin/env python3
"""Capture only the offline synthetic audit container, never the host network."""

import csv
import hashlib
import io
import json
import shutil
import signal
import subprocess
import time
from collections import Counter
from pathlib import Path

OUT = Path("/out")
if not Path("/.dockerenv").exists() or not Path("/work/script/oblivion/probe.py").exists():
    raise SystemExit("Run through run-probes.sh in the network-isolated audit container")
pcap = Path("/tmp/oblivion-audit-network.pcap")
capture_log = OUT / "packet-capture.log"
with capture_log.open("w") as log:
    capture = subprocess.Popen([
        "tcpdump", "-n", "-p", "-U", "--immediate-mode", "-B", "16384",
        "-i", "any", "-s", "0", "-Z", "root", "-w", str(pcap),
    ], stdout=subprocess.DEVNULL, stderr=log)
    try:
        deadline = time.monotonic() + 5
        while "listening on" not in capture_log.read_text():
            if capture.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("tcpdump did not start; inspect packet-capture.log")
            time.sleep(0.05)
        probe = subprocess.run(["python3", "/work/script/oblivion/probe.py"], check=False)
    finally:
        # Let the reader finish processing packets queued at child shutdown.
        time.sleep(0.2)
        capture.send_signal(signal.SIGINT)
        try:
            capture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            capture.kill()
            capture.wait()
    if capture.returncode != 0:
        raise SystemExit("Packet capture failed")
    if probe.returncode != 0:
        raise SystemExit(probe.returncode)
shutil.copyfile(pcap, OUT / "network.pcap")

fields = [
    "frame.number", "frame.len", "frame.cap_len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport", "dns.qry.name", "http.request.method", "http.host", "http.request.uri",
    "tls.handshake.extensions_server_name", "_ws.col.Protocol",
]
command = ["tshark", "-n", "-r", str(pcap), "--enable-heuristic", "http_tcp", "-T", "fields", "-E", "quote=d"]
for field in fields:
    command.extend(["-e", field])
decoded = subprocess.run(command, capture_output=True, text=True, check=True)
(OUT / "packet-fields.tsv").write_text(decoded.stdout)
rows = [dict(zip(fields, values)) for values in csv.reader(io.StringIO(decoded.stdout), delimiter="\t")]
assert all(row["frame.len"] == row["frame.cap_len"] for row in rows), "Truncated packet in capture"
requests = [
    {"frame": int(row["frame.number"]), "method": row["http.request.method"],
     "host": row["http.host"], "uri": row["http.request.uri"]}
    for row in rows if row["http.request.method"]
]
syn = subprocess.run([
    "tshark", "-n", "-r", str(pcap), "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "-T", "fields",
    "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport",
], capture_output=True, text=True, check=True)
destinations = Counter((ipv4 or ipv6, port) for ipv4, ipv6, port in csv.reader(io.StringIO(syn.stdout), delimiter="\t"))
observed_provider_requests = sum(len(scenario["requests"]) for scenario in json.loads((OUT / "runtime-results.json").read_text()))
assert len([request for request in requests if request["uri"] == "/v1/chat/completions"]) == observed_provider_requests > 0
assert "0 packets dropped by kernel" in capture_log.read_text().splitlines(), capture_log.read_text()
for port in ("1234", "11434", "8000"):
    assert ("127.0.0.1", port) in destinations, (port, destinations)
report = {
    "scope": "All interfaces including loopback of the offline synthetic container; not host interfaces or live internet",
    "tcpdump_version": subprocess.check_output(["tcpdump", "--version"], text=True).splitlines()[0],
    "tshark_version": subprocess.check_output(["tshark", "--version"], text=True, stderr=subprocess.DEVNULL).splitlines()[0],
    "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
    "pcap_bytes": pcap.stat().st_size,
    "packets": len(rows),
    "capture_statistics": capture_log.read_text().strip().splitlines(),
    "protocol_counts": dict(Counter(row["_ws.col.Protocol"] for row in rows)),
    "tcp_syn_destinations": [{"address": ip, "port": int(port), "attempts": count}
                             for (ip, port), count in sorted(destinations.items())],
    "http_requests": requests,
    "dns_names": sorted({row["dns.qry.name"] for row in rows if row["dns.qry.name"]}),
    "tls_sni": sorted({row["tls.handshake.extensions_server_name"] for row in rows if row["tls.handshake.extensions_server_name"]}),
    "limits": [
        "No cloud provider, Tor or external HTTPS was exercised.",
        "Blocked connect calls may produce no packets; correlate with strace.",
        "Packet capture alone does not reveal encrypted HTTPS request bodies.",
        "The raw capture contains synthetic HTTP content and stays in ignored artifacts; never enable in production.",
    ],
}
(OUT / "network-results.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"packets": len(rows), "http_requests": len(requests), "pcap_bytes": report["pcap_bytes"]}))
