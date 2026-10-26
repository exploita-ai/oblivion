#!/usr/bin/env python3
"""Boot the diagnostic ISO unchanged and exercise Debian networking and SSH."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from packet_capture import capture


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def firmware_ipv6(path):
    # EDK2 may do neighbor discovery before Linux loads. Require every IPv6
    # frame to precede DHCP and to contain only ICMPv6 neighbor/multicast control.
    data = path.read_bytes()
    order = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    offset = 24
    ipv4 = False
    while offset < len(data):
        length = struct.unpack_from(order + "I", data, offset + 8)[0]
        packet = data[offset + 16:offset + 16 + length]
        offset += 16 + length
        if packet[12:14] == b"\x08\x00":
            ipv4 = True
        if packet[12:14] != b"\x86\xdd":
            continue
        assert not ipv4, "IPv6 traffic after Debian IPv4 activation"
        ip = packet[14:]
        start = 40
        protocol = ip[6]
        if protocol == 0:
            protocol = ip[40]
            start += (ip[41] + 1) * 8
        assert protocol == 58 and ip[start] in [130, 131, 132, 133, 134, 135, 136, 143]


parser = argparse.ArgumentParser()
parser.add_argument("--iso", type=Path, required=True)
parser.add_argument("--firmware", type=Path, required=True)
parser.add_argument("--variables", type=Path, required=True)
parser.add_argument("--key", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--media", choices=["cdrom", "usb"], default="cdrom")
parser.add_argument("--previous-key", type=Path)
args = parser.parse_args()
iso = args.iso.resolve(strict=True)
firmware = args.firmware.resolve(strict=True)
variables = args.variables.resolve(strict=True)
key = args.key.resolve(strict=True)
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
assert not any("," in str(path) for path in [iso, firmware, output])
shutil.copyfile(variables, output / "uefi-vars.fd")
disk = output / "unrelated.raw"
with disk.open("xb") as file:
    file.write(b"OBLIVION_HARDWARE_UNRELATED_DISK\n")
    file.truncate(32 * 1024 * 1024)
before = digest(disk)
summary = {"passed": False, "iso_sha256": digest(iso), "media": args.media,
    "outer_accelerator": "tcg", "physical_wifi_tested": False, "session_kvm_tested": False,
    "checks": []}
started = time.monotonic()


def passed(description):
    summary["checks"].append(description)
    print("PASS: " + description, flush=True)


with tempfile.TemporaryDirectory(prefix="oblivion-hardware-") as runtime:
    qmp_path = str(Path(runtime) / "qmp.sock")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg", "-cpu", "max",
        "-m", "2048", "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot",
        "-serial", "file:" + str(output / "serial.log"),
        "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-object", "filter-dump,id=capture,netdev=net0,file=" + str(output / "network.pcap"),
        "-qmp", "unix:" + qmp_path + ",server=on,wait=off",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + str(firmware),
        "-drive", "if=pflash,format=raw,file=" + str(output / "uefi-vars.fd"),
        "-drive", "file=" + str(disk) + ",format=raw,if=virtio",
        *(["-cdrom", str(iso), "-boot", "order=d"] if args.media == "cdrom" else [
            "-device", "qemu-xhci,id=usb",
            "-drive", "file=" + str(iso) + ",format=raw,if=none,id=boot-media,readonly=on",
            "-device", "usb-storage,drive=boot-media,bootindex=1,removable=true"]),
        "-device", "virtio-rng-pci"]
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (output / "qemu.log").open("wb") as log, subprocess.Popen(command, stdout=log, stderr=log) as process:
        probe = None
        try:
            deadline = time.monotonic() + 30
            while not Path(qmp_path).exists():
                assert process.poll() is None, "QEMU stopped before QMP"
                assert time.monotonic() < deadline, "QMP unavailable"
                time.sleep(0.1)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(20)
                client.connect(qmp_path)
                with client.makefile("rwb", buffering=0) as channel:
                    assert "QMP" in json.loads(channel.readline())

                    def qmp(operation, arguments=None):
                        channel.write(json.dumps({"execute": operation, "arguments": arguments or {}}).encode() + b"\n")
                        while True:
                            reply = json.loads(channel.readline())
                            if "event" in reply:
                                continue
                            assert "return" in reply, reply
                            return reply["return"]

                    def keys(*values):
                        qmp("send-key", {"keys": [{"type": "qcode", "data": value} for value in values]})

                    def screen(name):
                        path = output / (name + ".png")
                        qmp("screendump", {"filename": str(path), "format": "png"})
                        # nmtui mixes a blue background and gray panel: local
                        # thresholding keeps its black text readable by OCR.
                        text = subprocess.run(["tesseract", str(path), "stdout", "--psm", "6",
                            *(["-c", "thresholding_method=2"] if name == "nmtui" else [])],
                            check=True, capture_output=True, timeout=30).stdout.decode()
                        (output / (name + ".txt")).write_text(text)
                        return text

                    def wait_screen(name, words, timeout=30):
                        deadline = time.monotonic() + timeout
                        while True:
                            text = screen(name)
                            if all(word in text for word in words):
                                return text
                            assert process.poll() is None, "QEMU stopped"
                            assert time.monotonic() < deadline, "Screen unavailable: " + name
                            time.sleep(0.5)

                    ssh = ["ssh", "-F", "/dev/null", "-i", str(key), "-p", str(port),
                        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=3",
                        "-o", "UserKnownHostsFile=" + str(output / "known_hosts"),
                        "-o", "StrictHostKeyChecking=yes"]

                    def remote(script, user="oblivion-test", check=True):
                        result = subprocess.run([*ssh, user + "@127.0.0.1", script],
                            capture_output=True, text=True, timeout=30)
                        if check:
                            assert result.returncode == 0, result.stderr + result.stdout
                        return result

                    qmp("qmp_capabilities")
                    wait_screen("manager", ["OBLIVION", "Supporto dati USB", "disabilitata"], 300)
                    summary["manager_seconds"] = round(time.monotonic() - started, 2)
                    passed("Unmodified ISO reaches the real manager through UEFI")
                    keys("alt", "f2")
                    wait_screen("hardware-off", ["COLLAUDO HARDWARE", "10.0.2.15", "SPENTO"])
                    scan = subprocess.run(["ssh-keyscan", "-T", "2", "-p", str(port), "127.0.0.1"], capture_output=True)
                    assert not scan.stdout, "SSH listening before local activation"
                    passed("Debian DHCP works and diagnostic SSH is initially off")
                    keys("1")
                    keys("ret")
                    wait_screen("nmtui", ["Wired"])
                    keys("esc")
                    wait_screen("hardware-return", ["COLLAUDO HARDWARE", "SPENTO"])
                    passed("The real Debian nmtui network selector opens and returns")
                    keys("2")
                    keys("ret")
                    wait_screen("hardware-on", ["COLLAUDO HARDWARE", "ATTIVO"])
                    scan = subprocess.run(["ssh-keyscan", "-T", "3", "-t", "ed25519", "-p", str(port), "127.0.0.1"],
                        check=True, capture_output=True, timeout=15)
                    # Only this loopback port, owned by this disposable QEMU VM,
                    # is trusted automatically. Physical PCs require operator verification.
                    (output / "known_hosts").write_bytes(scan.stdout)
                    assert remote("id -u; sudo -n id -u").stdout == "1050\n0\n"
                    assert remote("true", user="root", check=False).returncode != 0
                    denied = Path(runtime) / "denied-key"
                    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(denied)], check=True)
                    wrong = [*ssh]
                    wrong[wrong.index(str(key))] = str(denied)
                    assert subprocess.run([*wrong, "oblivion-test@127.0.0.1", "true"], capture_output=True, timeout=15).returncode != 0
                    passed("Only the operator key authenticates; root SSH is rejected and explicit sudo works")
                    inspection = remote("sudo -n sh -s <<'CHECK'\nset -eux\n"
                        "test $(systemctl show oblivion-manager.service -p User --value) = 1000\n"
                        "test $(systemctl is-enabled ssh.service) = masked\n"
                        "test $(findmnt -n -o FSTYPE /) = overlay\n"
                        "test $(findmnt -n -o FSTYPE /tmp) = tmpfs\n"
                        "test $(findmnt -n -o FSTYPE /var) = tmpfs\n"
                        "test $(findmnt -n -o FSTYPE /run) = tmpfs\n"
                        "test $(wc -l < /proc/swaps) = 1\n"
                        "test $(cat /sys/module/ipv6/parameters/disable) = 1\n"
                        "test $(cat /sys/module/pstore/parameters/backend) = none\n"
                        "test ! -e /sys/module/efi_pstore/parameters/pstore_disable || test $(cat /sys/module/efi_pstore/parameters/pstore_disable) = Y\n"
                        "systemctl is-enabled systemd-pstore.service | grep -q '^masked'\n"
                        "test -z \"$(find /etc/ssh -name 'ssh_host_*' -print)\"\n"
                        "test ! -e /run/oblivion-hardware/canary\n"
                        "test -z \"$(nmcli -t -f NAME connection show | grep oblivion-canary || true)\"\n"
                        "sshd -T -f /etc/oblivion/hardware/sshd_config\n"
                        "findmnt -t overlay,tmpfs\nCHECK")
                    (output / "inspection.txt").write_text(inspection.stdout)
                    for setting in ["passwordauthentication no", "permitrootlogin no", "authenticationmethods publickey", "allowtcpforwarding no"]:
                        assert setting in inspection.stdout, setting
                    host_key = remote("sudo -n cat /run/oblivion-hardware/ssh_host_ed25519_key.pub").stdout
                    (output / "server-key.pub").write_text(host_key)
                    if args.previous_key:
                        assert host_key.split()[1] != args.previous_key.read_text().split()[1]
                        passed("A fresh boot has a different SSH identity and no previous Wi-Fi profile or RAM canary")
                    remote("sudo -n sh -s <<'CHECK'\nset -eu\n"
                        "touch /run/oblivion-hardware/canary\n"
                        "nmcli connection add type wifi ifname '*' con-name oblivion-canary ssid oblivion-canary connection.autoconnect no\n"
                        "nmcli connection modify oblivion-canary wifi-sec.key-mgmt wpa-psk wifi-sec.psk synthetic-test-password\n"
                        "test $(stat -c %a /etc/NetworkManager/system-connections/oblivion-canary.nmconnection) = 600\nCHECK")
                    passed("Manager remains unprivileged; temporary state uses RAM, swap is off and no server private key is baked in")
                    remote("sudo -n python3 - <<'CHECK'\nimport socket, subprocess\n"
                        "subprocess.run(['ip','addr','add','198.51.100.10/32','dev','lo'],check=True)\n"
                        "try:\n with socket.socket() as s:\n  s.settimeout(2)\n  s.bind(('198.51.100.10',0))\n"
                        "  try: s.connect(('10.0.2.15',22))\n  except TimeoutError: pass\n  else: raise AssertionError('SSH accepted non-LAN source')\n"
                        "finally: subprocess.run(['ip','addr','del','198.51.100.10/32','dev','lo'],check=True)\nCHECK")
                    passed("The real nftables rule drops an SSH connection from outside the connected private subnet")
                    with (output / "session.log").open("wb") as session_log:
                        probe = subprocess.Popen([*ssh, "-tt", "oblivion-test@127.0.0.1",
                            "sudo -n sh -c 'echo $$ > /run/oblivion-hardware/probe.pid; exec sleep 300'"],
                            stdin=subprocess.DEVNULL, stdout=session_log, stderr=session_log)
                        deadline = time.monotonic() + 20
                        while remote("sudo -n test -s /run/oblivion-hardware/probe.pid", check=False).returncode:
                            assert probe.poll() is None and time.monotonic() < deadline
                            time.sleep(0.2)
                        keys("3")
                        keys("ret")
                        wait_screen("hardware-stopped", ["COLLAUDO HARDWARE", "SPENTO"])
                        probe.wait(timeout=15)
                    assert not subprocess.run(["ssh-keyscan", "-T", "2", "-p", str(port), "127.0.0.1"], capture_output=True).stdout
                    keys("2")
                    keys("ret")
                    wait_screen("hardware-reenabled", ["COLLAUDO HARDWARE", "ATTIVO"])
                    assert remote("sudo -n sh -c 'test ! -d /proc/$(cat /run/oblivion-hardware/probe.pid)'", check=False).returncode == 0
                    passed("Local SSH disable closes the listener and terminates the established administrative session and command")
                    keys("alt", "f1")
                    wait_screen("manager-return", ["OBLIVION", "Supporto dati USB", "disabilitata"])
                    qmp("system_powerdown")
                process.wait(timeout=90)
            assert process.returncode == 0
            assert digest(disk) == before, "Unrelated synthetic disk changed"
            assert digest(iso) == summary["iso_sha256"], "ISO changed"
            packets = capture(output / "network.pcap")
            (output / "network.json").write_text(json.dumps(packets, indent=2) + "\n")
            firmware_ipv6(output / "network.pcap")
            assert packets["ipv4_fragments"] == 0
            assert set(packets["udp_ports"]) <= {67, 68}, "Unexpected UDP traffic"
            assert all({source, destination} == {"10.0.2.2", "10.0.2.15"} and 22 in [sport, dport]
                for source, sport, destination, dport in packets["tcp_flows"]), "Unexpected TCP traffic"
            summary["firmware_ipv6_control_packets"] = packets["ipv6"]
            passed("Capture limits TCP/UDP to DHCP and diagnostic SSH; only pre-Linux neighbor control may use IPv6")
            passed("ACPI shutdown completes; ISO and unrelated synthetic disk remain byte-identical")
            summary["passed"] = True
        finally:
            if probe and probe.poll() is None:
                probe.kill()
                probe.wait()
            if process.poll() is None:
                process.kill()
                process.wait()
            summary["seconds"] = round(time.monotonic() - started, 2)
            (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
