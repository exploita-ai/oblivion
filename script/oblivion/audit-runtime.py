#!/usr/bin/env python3
"""Read-only metadata snapshot of an Oblivion Linux host, emitted as JSON.

Run with administrative read access. Never reads command arguments, environment,
logs, file contents from archives, credentials, conversation text or packet payloads.
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def command(*args):
    return subprocess.check_output(args, text=True, env={**os.environ, "LC_ALL": "C"})


def process(pid):
    try:
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
        return {key: status[key].strip() for key in ("Name", "Uid", "Gid", "NoNewPrivs", "CapEff", "CapBnd", "Seccomp", "VmLck") if key in status}
    except FileNotFoundError:
        return {"exited_during_snapshot": True}


def endpoint(value):
    address, port = value.rsplit(":", 1)
    address = address.strip("[]").split("%", 1)[0]
    if address == "*":
        return {"scope": "wildcard", "port": port}
    ip = ipaddress.ip_address(address)
    scope = "wildcard" if ip.is_unspecified else "loopback" if ip.is_loopback else "public" if ip.is_global else "nonpublic"
    return {"scope": scope, "port": port}


def main():
    running = sorted(line.split()[0] for line in command("systemctl", "list-units", "--state=running", "--type=service", "--no-legend", "--plain").splitlines())
    properties = ("Id", "ActiveState", "MainPID", "User", "Group", "NoNewPrivileges", "CapabilityBoundingSet",
                  "PrivateNetwork", "PrivateDevices", "ProtectSystem", "ProtectHome", "ProtectProc", "ProcSubset",
                  "RestrictAddressFamilies", "RestrictNamespaces", "RestrictSUIDSGID", "DevicePolicy", "DeviceAllow",
                  "RootDirectory", "ReadWritePaths", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
                  "LimitCORE", "MemorySwapMax", "StandardOutput", "StandardError", "UMask")
    services = []
    for name in running:
        values = {}
        for line in command("systemctl", "show", name, "--property=" + ",".join(properties)).splitlines():
            key, value = line.split("=", 1)
            # Array properties such as DeviceAllow can repeat the same key.
            values[key] = values[key] + "\n" + value if key in values else value
        if values.get("MainPID", "0") != "0":
            values["process"] = process(values["MainPID"])
        services.append(values)
    processes = Counter()
    for path in Path("/proc").iterdir():
        if path.name.isdecimal():
            row = process(path.name)
            if "Name" in row:
                processes[(row["Name"], row["Uid"].split()[1])] += 1
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        separator = fields.index("-")
        target = fields[4]
        if target in ("/", "/tmp", "/var", "/run", "/dev/shm", "/persist", "/run/oblivion/general", "/run/live/medium", "/sys/fs/pstore"):
            mounts.append({"target": target, "type": fields[separator + 1], "options": fields[5],
                           "super_options": fields[separator + 3] if fields[separator + 1] != "overlay" else "omitted: may include overlay paths"})
    sockets = []
    for line in command("ss", "-H", "-t", "-u", "-a", "-n", "-p").splitlines():
        fields = line.split(maxsplit=6)
        sockets.append({"protocol": fields[0], "state": fields[1], "local": endpoint(fields[4]), "peer": endpoint(fields[5]),
                        "processes": re.findall(r'\("([^\"]+)"', fields[6]) if len(fields) > 6 else []})
    policy_paths = ("/proc/sys/kernel/core_pattern", "/proc/sys/fs/suid_dumpable", "/sys/module/efi_pstore/parameters/pstore_disable")
    # Show configuration provenance, not journal records. cat-config preserves
    # the ordering that matters when a vendor drop-in overrides a local one.
    journal_config = command("systemd-analyze", "cat-config", "systemd/journald.conf")
    journal_assignments = [line for line in journal_config.splitlines()
                           if re.fullmatch(r"# /\S+", line) or (line and line[0].isalpha() and "=" in line)]
    overlay = next(line.split(" - ", 1)[1].split()[2] for line in Path("/proc/self/mountinfo").read_text().splitlines()
                   if line.split()[4] == "/")
    upper = next((option.removeprefix("upperdir=") for option in overlay.split(",") if option.startswith("upperdir=")), None)
    nft = json.loads(command("nft", "-j", "list", "ruleset"))["nftables"] if shutil.which("nft") else None
    print(json.dumps({
        "schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(), "architecture": os.uname().machine,
        "kernel": os.uname().release, "services": services,
        "process_counts": [{"name": name, "uid": uid, "count": count} for (name, uid), count in sorted(processes.items())],
        "mounts": mounts, "active_swap_entries": max(0, len(Path("/proc/swaps").read_text().splitlines()) - 1),
        "kernel_policy": {name: Path(name).read_text().strip() for name in policy_paths if Path(name).exists()},
        "boot_privacy_arguments": [arg for arg in Path("/proc/cmdline").read_text().split()
                                   if arg.startswith(("pstore.", "efi_pstore.", "systemd.mask=", "ipv6.disable=", "nopersistence"))],
        "loaded_modules": sorted(line.split()[0] for line in Path("/proc/modules").read_text().splitlines()),
        "root_overlay_upper_fstype": command("findmnt", "-n", "-o", "FSTYPE", "-T", upper).strip() if upper else None,
        "journal_configuration_order": journal_assignments,
        "syslog_forward_socket_present": Path("/run/systemd/journal/syslog").exists(),
        "host_firewall_chains": [{key: row["chain"][key] for key in ("family", "table", "name", "hook", "policy") if key in row["chain"]}
                                 for row in nft if "chain" in row] if nft is not None else None,
        "inet_sockets": sockets,
        "limitations": [
            "Point-in-time host observation; not a guest-process inventory or traffic capture. Idle/conditional services can activate later.",
            "Administrative SSH and the audit process itself affect service/process/socket counts; no workloads, restarts or mutations requested.",
            "IP addresses omitted; only scope, protocol, ports and process names retained. No payloads, argv, environment, logs or user-file contents read.",
            "Process metadata can race with process exit. Systemd properties describe units; process status confirms the observed main process only.",
            "The live laboratory may contain RAM overlays newer than the ISO. Static ISO evidence is recorded separately.",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
