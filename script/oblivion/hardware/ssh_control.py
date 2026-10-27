#!/usr/bin/python3
"""Restrict the diagnostic SSH listener to currently connected private IPv4 subnets."""
import ipaddress
import json
from pathlib import Path
import subprocess
import sys


def addresses():
    private = [ipaddress.ip_network(value) for value in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]
    interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show", "up"], text=True))
    return [ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}")
        for interface in interfaces for address in interface.get("addr_info", [])
        if address["family"] == "inet" and address["scope"] == "global"
        and any(ipaddress.ip_network(f"{address['local']}/{address['prefixlen']}", strict=False).subnet_of(network)
            for network in private)]


def main():
    if sys.argv[1:] not in [["prepare"], ["refresh"]]:
        raise SystemExit("usage: ssh_control.py prepare|refresh")
    # A transient DHCP gap must block access without cancelling the operator's
    # opt-in. The next dispatcher event restores the current private subnets.
    networks = sorted({str(address.network) for address in addresses()})
    exists = subprocess.run(["nft", "list", "table", "inet", "oblivion_hardware"], capture_output=True).returncode == 0
    rules = ("delete table inet oblivion_hardware\n" if exists else "") + """table inet oblivion_hardware {
  set admin_networks { type ipv4_addr; flags interval; """ + (
        "elements = { " + ", ".join(networks) + " }; " if networks else "") + """}
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr @admin_networks tcp dport 22 accept
    tcp dport 22 drop
  }
}
"""
    # The release host policy is independent of this diagnostic filter. Keep
    # its explicit SSH exception in the same transaction as subnet changes.
    if Path("/etc/oblivion/host-firewall.nft").exists():
        rules += "flush set inet oblivion_host debug4\n"
        if networks:
            rules += "add element inet oblivion_host debug4 { " + ", ".join(networks) + " }\n"
    subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)
    if sys.argv[1] == "refresh":
        return
    if not networks:
        raise SystemExit("No private IPv4 network available; SSH remains disabled.")
    key = Path("/run/oblivion-hardware/ssh_host_ed25519_key")
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    subprocess.run(["sshd", "-t", "-f", "/etc/oblivion/hardware/sshd_config"], check=True)


if __name__ == "__main__":
    main()
