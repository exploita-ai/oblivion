#!/usr/bin/python3
"""Fixed diagnostic actions, installed only in the hardware/debug image."""
import json
from pathlib import Path
import subprocess
import sys
from ssh_control import addresses

UNIT = "oblivion-hardware-ssh.service"

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("status", "enable-ssh", "disable-ssh"):
        raise SystemExit(2)
    if sys.argv[1] != "status":
        subprocess.run(["systemctl", "start" if sys.argv[1] == "enable-ssh" else "stop", UNIT], check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    active = subprocess.run(["systemctl", "is-active", "--quiet", UNIT], timeout=5).returncode == 0
    key = Path("/run/oblivion-hardware/ssh_host_ed25519_key.pub")
    fingerprint = None
    if key.exists():
        fingerprint = subprocess.check_output(["ssh-keygen", "-lf", str(key)], text=True, timeout=5).split()[1]
    print(json.dumps({"ssh_active": active, "addresses": [str(value.ip) for value in addresses()], "fingerprint": fingerprint}))

if __name__ == "__main__":
    main()
