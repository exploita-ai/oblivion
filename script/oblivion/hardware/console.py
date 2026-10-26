#!/usr/bin/python3
"""Fixed local operator menu for the separate hardware-test distribution."""
from pathlib import Path
import subprocess
from ssh_control import addresses

UNIT = "oblivion-hardware-ssh.service"
notice = ""
while True:
    active = subprocess.run(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0
    print("\033[0m\033[2J\033[H\033[91mOBLIVION - HARDWARE TEST\033[0m\n")
    print("Alt+F1: manager   |   Alt+F2: network and tests\n")
    print("Test image. Administrative access requires the dedicated Mac key.")
    print("Manager > Network > Save network profiles stores Wi-Fi in the encrypted archive.")
    print("Diagnostics and SSH host keys remain in RAM until shutdown.\n")
    for address in addresses():
        print("Local IP:", address.ip)
        if active:
            print("SSH user: oblivion-test (dedicated Mac key)")
    print("SSH: " + ("ACTIVE" if active else "OFF"))
    key = Path("/run/oblivion-hardware/ssh_host_ed25519_key.pub")
    if active and key.exists():
        print("PC fingerprint (verify on the Mac):")
        print(subprocess.check_output(["ssh-keygen", "-lf", str(key)], text=True).strip())
    print("\n1  Configure Wi-Fi / Ethernet\n2  Enable access from Mac\n3  Disable access from Mac\n4  Show hardware\n5  Power off\nEnter  Refresh status\n")
    print(notice)
    choice = input("Select: ").strip()
    notice = ""
    if choice == "1":
        subprocess.run(["nmtui-connect"])
    elif choice in ["2", "3"]:
        result = subprocess.run(["systemctl", "start" if choice == "2" else "stop", UNIT], capture_output=True)
        notice = "Operation completed." if result.returncode == 0 else "Operation failed. Check the local network connection."
    elif choice == "4":
        subprocess.run(["lscpu"])
        subprocess.run(["lspci", "-nn"])
        print("KVM available:", Path("/dev/kvm").exists())
        input("Enter to return to the menu: ")
    elif choice == "5":
        subprocess.run(["systemctl", "poweroff"], check=True)
        break
