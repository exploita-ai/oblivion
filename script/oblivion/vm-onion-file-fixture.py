#!/usr/bin/python3 -B
"""Diagnostics and a fixed HTTP peer, only in disposable test images."""
import errno
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tty
import zipfile

ROOT = Path("/run/oblivion-onion")
STAGE = Path("/run/oblivion-onion-stage")
PAYLOAD = b"Oblivion file VM synthetic payload\n"


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=15).decode().strip()


def unit(name):
    values = dict(line.split("=", 1) for line in run("systemctl", "show", name,
        "--property=ActiveState,MainPID,Result,ExecMainStatus").splitlines())
    return {"name": name, "active": values["ActiveState"], "pid": int(values["MainPID"]),
            "result": values["Result"], "exit_status": int(values["ExecMainStatus"])}


def workers():
    return [unit(line.split()[0]) for line in run("systemctl", "list-units", "--all", "--plain",
        "--no-legend", "oblivion-onion-worker@*.service").splitlines() if line.strip()]


def inspect():
    units = [unit(f"oblivion-onion-{name}.service") for name in ("file", "relay", "stage", "source")] + workers()
    for value in units:
        if not value["pid"]:
            continue
        try:
            status = Path(f'/proc/{value["pid"]}/status').read_text()
        except FileNotFoundError:
            continue
        uid = 0 if value["name"] == "oblivion-onion-file.service" else 1000 if (
            "worker@" in value["name"] or "relay" in value["name"]) else 1002
        assert f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in status, value
        assert "NoNewPrivs:\t1" in status
        assert f'CapEff:\t{11 if uid == 0 else 0:016x}' in status
        if "worker@" in value["name"]:
            assert os.readlink(f'/proc/{value["pid"]}/ns/net') != os.readlink('/proc/1/ns/net')
    assert not run("ip", "-4", "route", "show", "default")
    assert Path("/proc/swaps").read_text().count("\n") == 1
    assert Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() == "1"
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "0"
    assert sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["file0", "lo"]
    assert " / squashfs ro," in Path("/proc/mounts").read_text()
    assert not any(Path("/usr/bin", name).exists() for name in ("tor", "curl", "oblivion-api", "oblivion-egress"))
    devices = sorted(p.name for p in Path("/sys/block").glob("vd*"))
    assert devices in (["vda"], ["vda", "vdb"])
    if len(devices) == 2:
        assert Path("/sys/block/vdb/serial").read_text().strip() == "oblivion-backup"
    return {"units": units, "controller_sha256": hashlib.sha256(Path("/usr/bin/oblivion-onion-file").read_bytes()).hexdigest(),
            "policy_sha256": hashlib.sha256(run("nft", "--stateless", "--numeric", "list", "ruleset").encode()).hexdigest()}


def share_seal():
    active = [value for value in workers() if value["pid"]]
    assert len(active) == 1
    fd = os.open(f'/proc/{active[0]["pid"]}/root/run/oblivion-onion/share', os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert os.fstatvfs(fd).f_flag & os.ST_RDONLY
        try:
            writable = os.open("a.txt", os.O_WRONLY, dir_fd=fd)
        except OSError as error:
            assert error.errno == errno.EROFS, error
        else:
            os.close(writable)
            raise AssertionError("Share snapshot is writable")
    finally:
        os.close(fd)
    snapshot = list(STAGE.glob("*/files"))
    assert len(snapshot) == 1
    for path in [snapshot[0], *snapshot[0].rglob("*")]:
        info = path.stat()
        assert info.st_uid == 0 and info.st_gid == 1000
        assert info.st_mode & 0o777 == (0o550 if path.is_dir() else 0o440)
    return {"read_only": True}


def frozen():
    assert not [value for value in workers() if value["pid"]]
    assert unit("oblivion-onion-relay.service")["pid"] == 0
    files = []
    for path in [ROOT / "receive", *(ROOT / "receive").rglob("*")]:
        info = path.stat()
        assert info.st_uid == 1002 and info.st_gid == 1002
        assert info.st_mode & 0o777 == (0o500 if path.is_dir() else 0o400)
        if path.is_file():
            files.append({"path": str(path.relative_to(ROOT / "receive")), "bytes": info.st_size,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    assert not (ROOT / "imports").exists()
    return {"files": files}


def peer(operation):
    connection = http.client.HTTPConnection("10.89.0.2", 8080, timeout=5)
    try:
        if operation == "backup-ranges":
            size = 512 * 1024**2
            for start, end, expected in [(0, 7, b"LUKS\xba\xbe\0\x02"), (size-32, size-1, b"OBLIVION_BACKUP_FIXTURE_12345678")]:
                connection.request("GET", "/download", headers={"Range":f"bytes={start}-{end}","Accept-Encoding":"gzip"})
                response = connection.getresponse()
                assert response.status == 206
                assert response.getheader("Content-Range") == f"bytes {start}-{end}/{size}"
                assert response.getheader("Content-Encoding") is None
                assert "session.oblivion" in response.getheader("Content-Disposition")
                assert response.read(1024) == expected
            connection.request("GET", "/download", headers={"Range":f"bytes={size}-"})
            response = connection.getresponse()
            assert response.status == 416
            response.read(65536)
            # Interrupt an actual streaming response, then resume its immutable
            # bytes through the upstream Range handler rather than starting over.
            connection.request("GET", "/download")
            response = connection.getresponse()
            assert response.status == 200
            first = response.read(1024**2)
            assert len(first) == 1024**2
            actual = hashlib.sha256(first)
            connection.close()
            connection = http.client.HTTPConnection("10.89.0.2", 8080, timeout=5)
            connection.request("GET", "/download", headers={"Range":f"bytes={len(first)}-"})
            response = connection.getresponse()
            assert response.status == 206
            assert response.getheader("Content-Range") == f"bytes {len(first)}-{size-1}/{size}"
            length = len(first)
            while chunk := response.read(1024**2):
                length += len(chunk)
                assert length <= size
                actual.update(chunk)
            expected = hashlib.sha256(b"LUKS\xba\xbe\0\x02" + bytes(1024**2-8))
            for _ in range(510):
                expected.update(bytes(1024**2))
            expected.update(bytes(1024**2-32) + b"OBLIVION_BACKUP_FIXTURE_12345678")
            assert length == size, ("incomplete_backup", length, size)
            assert actual.digest() == expected.digest(), "backup_hash_mismatch"
            return {"raw_ranges_verified":True, "resumed_bytes":length, "complete_hash_verified":True}
        if operation == "download":
            connection.request("GET", "/download")
            response = connection.getresponse()
            body = response.read(1024 * 1024)
            assert response.status == 200
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                assert set(archive.namelist()) == {"a.txt", "z.txt"}
                assert archive.read("a.txt") == PAYLOAD and archive.read("z.txt") == b"second fixture"
            return {"downloaded": len(body)}
        if operation == "upload":
            boundary = "OblivionFileVMFixture"
            body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file[]"; filename="citta.txt"\r\n'
                    'Content-Type: application/octet-stream\r\n\r\n').encode() + PAYLOAD + f'\r\n--{boundary}--\r\n'.encode()
            connection.request("POST", "/upload-ajax", body,
                {"Content-Type": f"multipart/form-data; boundary={boundary}"})
            response = connection.getresponse()
            response.read(65536)
            assert response.status == 200
            return {"uploaded": len(PAYLOAD)}
        if operation == "refused":
            try:
                connection.connect()
            except OSError:
                return {"refused": True}
            raise AssertionError("HTTP port remains reachable")
        raise ValueError("Unknown peer operation")
    finally:
        connection.close()


def main():
    mode = sys.argv[1]
    assert mode in ("file", "peer")
    if mode == "peer":
        names = [path.name for path in Path("/sys/class/net").iterdir() if path.name != "lo"]
        assert len(names) == 1
        run("ip", "address", "replace", "10.89.0.1/30", "dev", names[0])
        run("ip", "link", "set", names[0], "up")
        assert not run("ip", "-4", "route", "show", "default")
    tty.setraw(sys.stdin.fileno())

    def reply(value):
        print("OBLIVION_ONION_FILE_LAB " + json.dumps(value, separators=(",", ":")), flush=True)

    reply({"ready": True, "mode": mode})
    for line in sys.stdin:
        command = json.loads(line)
        assert set(command) == {"operation"}
        operation = command["operation"]
        if operation == "shutdown":
            reply({"ok": True})
            break
        if mode == "peer":
            reply({"ok": True, **peer(operation)})
            continue
        if operation == "info":
            reply({"ok": True, **inspect()})
        elif operation == "share-seal":
            reply({"ok": True, **share_seal()})
        elif operation == "frozen":
            reply({"ok": True, **frozen()})
        elif operation == "kill-owner":
            owner = unit("oblivion-onion-file.service")
            assert owner["pid"] > 1
            os.kill(owner["pid"], signal.SIGKILL)
            reply({"ok": True})
        else:
            raise ValueError("Invalid fixture operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
        print('OBLIVION_ONION_FILE_LAB {"ok":false,"error":"fixture_failed"}', flush=True)
        raise
