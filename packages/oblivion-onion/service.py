#!/opt/oblivion-onionshare/bin/python -IB
# SPDX-License-Identifier: GPL-3.0-or-later
"""Private file-VM worker. Tor publication belongs to the gateway, not here.

The supervisor stages selected files in ROOT/share before starting this worker.
An inherited Unix socket carries bounded commands/status; stdout/stderr are
discarded before importing upstream. No file paths or credentials are accepted
in the control protocol. The HTTP listener is a separate, private Unix socket.
"""
import argparse
import fcntl
import json
import logging
import os
from pathlib import Path
import selectors
import secrets
import shutil
import signal
import socket
import stat
import sys
import tempfile
import threading
import time

ROOT = Path("/run/oblivion-onion")
MAX_BYTES = 256 * 1024 * 1024
MAX_BACKUP_BYTES = 1024 ** 4
MAX_FILES = 1024
MAX_TTL = 3600
MAX_CONTROL = 4096


class Refused(Exception):
    pass


class Service:
    def __init__(self, root):
        self.root = root
        self.web = None
        self.thread = None
        self.state = "not_started"
        self.mode = None
        self.deadline = None
        self.files = 0
        self.bytes = 0
        self.rejected = 0
        self.transferred_bytes = 0
        self.received = set()
        self.attempted_files = 0
        self.owns_runtime = False
        self.lock = threading.Lock()

    def start(self, config):
        if self.state != "not_started":
            raise Refused("already_started")
        if not isinstance(config, dict) or set(config) != {"op", "mode", "max_bytes", "max_files", "ttl_seconds"}:
            raise Refused("invalid_request")
        if config["mode"] not in ("share", "receive", "backup") or config["op"] != "start":
            raise Refused("invalid_request")
        backup = config["mode"] == "backup"
        for key, maximum in (("max_bytes", MAX_BACKUP_BYTES if backup else MAX_BYTES), ("max_files", 1 if backup else MAX_FILES), ("ttl_seconds", MAX_TTL)):
            if type(config[key]) is not int or not 1 <= config[key] <= maximum:
                raise Refused("invalid_limits")
        self._prepare_runtime()
        self.mode = config["mode"]

        # Imports happen only after HOME/XDG/TMP point at this operation's RAM.
        from onionshare_cli.common import Common
        from onionshare_cli.mode_settings import ModeSettings
        from onionshare_cli.web.web import Web
        from onionshare_cli.web.receive_mode import ReceiveModeRequest
        from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
        from werkzeug.utils import secure_filename
        from flask import abort, make_response, request
        from waitress.server import create_server

        common = Common(verbose=False)
        common.load_settings(str(self.root / "config/settings.json"))
        settings = ModeSettings(common, filename=str(self.root / "config/mode.json"))
        settings.set("general", "title", "Oblivion file transfer")
        settings.set("share", "autostop_sharing", False)
        settings.set("share", "log_filenames", False)
        settings.set("receive", "data_dir", str(self.root / "receive"))
        settings.set("receive", "disable_text", True)
        settings.set("receive", "max_upload_size", config["max_bytes"])
        settings.set("receive", "max_upload_size_total", True)
        settings.set("receive", "webhook_url", None)
        owner = self

        class QuietWeb(Web):
            def add_request(self, request_type, path=None, data=None):
                # Do not retain upstream's unbounded request/history queue,
                # arbitrary URLs, filenames or per-chunk progress dictionaries.
                if request_type == self.REQUEST_UPLOAD_TOO_LARGE:
                    with owner.lock:
                        owner.rejected += 1
                if request_type == self.REQUEST_PROGRESS and owner.mode == "receive":
                    with owner.lock:
                        owner.transferred_bytes = min(config["max_bytes"], owner.bytes + sum(value["uploaded_bytes"] for value in data["progress"].values()))

        class BoundedRequest(ReceiveModeRequest):
            accepted_files = ()

            def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
                if filename and self.upload_request:
                    normalized = secure_filename(filename)
                    if not normalized or any(
                        normalized == existing or normalized == existing + ".part" or normalized + ".part" == existing
                        for existing in self.progress
                    ):
                        self.upload_error = True
                        raise BadRequest()
                    if owner.attempted_files >= config["max_files"]:
                        self.upload_error = True
                        raise RequestEntityTooLarge()
                    owner.attempted_files += 1
                return super()._get_file_stream(total_content_length, content_type, filename, content_length)

            def close(self):
                if self.closed:
                    return
                super().close()
                if not self.upload_request or self.receive_mode_dir is None:
                    return
                # A .part rename alone does not prove that multipart parsing
                # completed. Only the successful route/response admits files;
                # disconnects, duplicate names and malformed bodies are dropped.
                accepted = self.accepted_files and not (
                    self.upload_error or self.upload_too_large or self.total_upload_size_exceeded
                )
                if not accepted:
                    shutil.rmtree(self.receive_mode_dir, ignore_errors=True)
                    return
                # Upstream parses every multipart file field. Only file[] is
                # part of its upload contract; discard files supplied under
                # other field names instead of leaving unlisted data behind.
                for path in Path(self.receive_mode_dir).iterdir():
                    if path not in self.accepted_files:
                        path.unlink()
                with owner.lock:
                    for path in self.accepted_files:
                        owner.received.add(path)
                    owner.files = len(owner.received)
                    owner.bytes = sum(path.stat().st_size for path in owner.received)

        self.web = QuietWeb(common, False, settings, mode="share" if backup else self.mode)
        self.web.app.logger.disabled = True
        self.web.app.config.update(MAX_CONTENT_LENGTH=config["max_bytes"], MAX_FORM_PARTS=config["max_files"])
        self.web.app.request_class = BoundedRequest if self.mode == "receive" else self.web.app.request_class

        @self.web.app.before_request
        def bounded_download_range():
            if self.mode not in ("share", "backup") or request.path != "/download" or not request.headers.get("Range"):
                return None
            share = self.web.share_mode
            size = share.gzip_filesize if share.should_use_gzip() else self.bytes
            parsed = request.range
            selection = parsed.range_for_length(size) if parsed is not None else None
            if parsed is not None and parsed.units == "bytes" and len(parsed.ranges) == 1:
                start, end = parsed.ranges[0]
                if start < 0 and end is None:
                    selection = (max(0, size + start), size)
            if selection is None:
                abort(416)
            # Werkzeug owns syntax/bounds; upstream streams the normalized
            # single range. Its parser alone admits starts beyond EOF.
            request.environ["HTTP_RANGE"] = f"bytes={selection[0]}-{selection[1]-1}"

        @self.web.app.after_request
        def accepted_upload(response):
            if self.mode in ("share", "backup") and response.status_code in (200, 206) and "Content-Disposition" in response.headers:
                if self.mode == "backup":
                    response.headers.set("Content-Disposition", "attachment", filename="session.oblivion")
                    response.headers.set("Content-Type", "application/octet-stream")
                original = response.response

                def counted_download():
                    try:
                        for chunk in original:
                            yield chunk
                            with self.lock:
                                self.transferred_bytes = min(self.bytes, self.transferred_bytes + len(chunk))
                    finally:
                        close = getattr(original, "close", None)
                        if close is not None:
                            close()

                # Count actual yielded bytes, not upstream's absolute file
                # cursor (which includes skipped bytes on Range requests).
                response.response = counted_download()
            if self.mode == "receive" and request.upload_request and 200 <= response.status_code < 400:
                # Upstream also detects the lifetime byte ceiling while parsing
                # request.files, after the route's initial limit check. Reflect
                # that late refusal in HTTP too, rather than reporting success.
                if request.upload_too_large or request.total_upload_size_exceeded:
                    return make_response(self.web.receive_mode.upload_too_large_response(request.path == "/upload-ajax"))
                if request.admitted and not (request.upload_error or request.upload_too_large or request.total_upload_size_exceeded):
                    request.accepted_files = tuple(
                        Path(value.stream.filename) for value in request.files.getlist("file[]")
                        if value.filename and hasattr(value.stream, "filename")
                    )
            return response

        if self.mode == "share":
            self._check_share(config)
            self.web.share_mode.set_file_info([str(self.root / "share")])
            self.bytes = self.web.share_mode.download_filesize
        if backup:
            self._backup(config)
        # One request worker serializes the upstream lifetime upload budget.
        # Waitress buffers (including oversized/malformed HTTP bodies) can only
        # spill to this VM's quota-limited RAM TMPDIR. No public TCP listener.
        self.web.unix_socket = str(self.root / "http/service.sock")
        self.web.waitress = create_server(
            self.web.app, unix_socket=self.web.unix_socket, unix_socket_perms="600",
            clear_untrusted_proxy_headers=True, ident="OnionShare", threads=1,
            connection_limit=8, channel_timeout=30, cleanup_interval=5,
            max_request_body_size=min(MAX_BYTES, config["max_bytes"]), max_request_header_size=16384,
            expose_tracebacks=False,
        )
        self.web.running = True
        self.thread = threading.Thread(target=self.web.waitress.run, daemon=True)
        self.thread.start()
        self.state = "serving"
        self.deadline = time.monotonic() + config["ttl_seconds"]
        return self.status()

    def _backup(self, config):
        # The controller attaches exactly one closed LUKS file through an
        # O_RDONLY QMP descriptor. This device is never decrypted or mounted.
        path = "/dev/oblivion-backup"
        with open(path, "rb", buffering=0) as source:
            if not stat.S_ISBLK(os.fstat(source.fileno()).st_mode):
                raise Refused("invalid_backup")
            if int.from_bytes(fcntl.ioctl(source, 0x125E, bytes(4)), sys.byteorder) != 1:  # BLKROGET
                raise Refused("backup_not_read_only")
            size = int.from_bytes(fcntl.ioctl(source, 0x80081272, bytes(8)), sys.byteorder)  # BLKGETSIZE64
            if not 32 * 1024 ** 2 <= size <= config["max_bytes"] or source.read(8) != b"LUKS\xba\xbe\0\x02":
                raise Refused("invalid_backup")
        self.files, self.bytes = 1, size
        share = self.web.share_mode
        # Reuse the pinned upstream streaming/Range handler. Its ordinary
        # set_file_info eagerly hashes and compresses regular files; neither
        # operation is appropriate for a potentially terabyte-size block view.
        share.download_filename = path
        share.download_filesize = size
        share.download_etag = secrets.token_hex(16)
        share.is_zipped = True  # serve as-is, with no gzip preparation
        share.download_individual_files = False
        self.web.app.view_functions["index"] = lambda path="": '<!doctype html><title>Oblivion encrypted backup</title><h1>Encrypted session backup</h1><p>The session password is required to restore this LUKS2 volume.</p><a href="/download">Download session.oblivion</a>'

    def _prepare_runtime(self):
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refused("unsafe_runtime")
        # Refuse a persistent directory even if a launcher was misconfigured.
        mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
        matching = [fields for fields in mounts if self.root == Path(fields[4]) or Path(fields[4]) in self.root.parents]
        mount = max(matching, key=lambda fields: len(fields[4]))
        if mount[mount.index("-") + 1] != "tmpfs":
            raise Refused("runtime_not_volatile")
        self.owns_runtime = True
        for name in ("home", "config", "cache", "tmp", "http", "receive"):
            (self.root / name).mkdir(mode=0o700)
        os.environ.clear()
        os.environ.update({
            "HOME": str(self.root / "home"), "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_CACHE_HOME": str(self.root / "cache"), "XDG_DATA_HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"), "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin",
        })
        tempfile.tempdir = str(self.root / "tmp")

    def _check_share(self, config):
        source = self.root / "share"
        if not source.is_dir() or source.is_symlink():
            raise Refused("invalid_source")
        entries = 0
        for directory, folders, filenames in os.walk(source, followlinks=False):
            for name in folders + filenames:
                path = Path(directory) / name
                info = path.lstat()
                entries += 1
                if any(ord(character) < 32 or ord(character) == 127 for character in name):
                    raise Refused("invalid_source")
                if entries > config["max_files"] or len(path.relative_to(source).parts) > 32:
                    raise Refused("source_limit")
                if stat.S_ISDIR(info.st_mode):
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise Refused("invalid_source")
                self.files += 1
                self.bytes += info.st_size
                if self.bytes > config["max_bytes"]:
                    raise Refused("source_limit")
        if self.files == 0:
            raise Refused("empty_source")

    def status(self):
        if self.state == "serving" and (not self.thread.is_alive() or not self.web.running):
            raise Refused("server_failed")
        with self.lock:
            return {"state": self.state, "mode": self.mode, "files": self.files,
                    "bytes": self.bytes, "transferred_bytes": self.transferred_bytes,
                    "rejected": self.rejected}

    def freeze(self):
        if self.state == "serving":
            self.web.stop(0)
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                raise Refused("shutdown_failed")
            self.web.running = False
            self.state = "frozen"
        if self.state != "frozen":
            raise Refused("not_started")
        with self.lock:
            files = [{"path": str(path.relative_to(self.root / "receive")), "bytes": path.stat().st_size}
                     for path in sorted(self.received)]
        return {**self.status(), "received": files}

    def stop(self):
        if not self.owns_runtime:
            self.state = "stopped"
            return
        if self.web is not None:
            if self.state == "serving":
                self.freeze()
            self.web.cleanup()
        for path in self.root.iterdir():
            # Production mounts the approved snapshot read-only into this
            # namespace. Its supervisor owns disposal after this unit exits.
            if path.name == "share" and os.statvfs(path).f_flag & os.ST_RDONLY:
                continue
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        self.state = "stopped"

    def handoff(self):
        if self.mode != "receive":
            raise Refused("invalid_handoff")
        result = self.freeze()
        self.web.cleanup()
        # The privileged supervisor stops/reaps this entire unit, then owns
        # the RAM intake for verified selection/copy. No HTTP worker remains
        # alive while approved files are exported to the session.
        self.owns_runtime = False
        return result


def main():
    os.umask(0o077)
    # Upstream prints filenames and progress in non-verbose mode too. Never
    # connect either output stream to a journal, terminal or persistent log.
    with open(os.devnull, "wb") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-fd", type=int, default=3)
    args = parser.parse_args()
    if os.getuid() != 1000 or not 3 <= args.control_fd < 1024:
        return 1
    service = Service(ROOT)
    control = socket.socket(fileno=args.control_fd)
    if control.family != socket.AF_UNIX:
        raise Refused("invalid_control")
    control.setblocking(False)

    def stopped(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)

    def reply(value):
        control.settimeout(2)
        control.sendall(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
        control.setblocking(False)

    pending = b""
    initial_deadline = time.monotonic() + 15
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(control, selectors.EVENT_READ)
            while True:
                remaining = (service.deadline or initial_deadline) - time.monotonic()
                if remaining <= 0:
                    reply({"ok": False, "error": "expired"})
                    break
                if not selector.select(timeout=remaining):
                    continue
                data = control.recv(MAX_CONTROL + 1)
                if not data:
                    break
                pending += data
                if len(pending) > MAX_CONTROL:
                    raise Refused("invalid_request")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    command = json.loads(line)
                    if isinstance(command, dict) and command.get("op") == "start":
                        result = service.start(command)
                    elif command == {"op": "status"}:
                        result = service.status()
                    elif command == {"op": "freeze"}:
                        result = service.freeze()
                    elif command == {"op": "handoff"}:
                        reply({"ok": True, "status": service.handoff()})
                        return 0
                    elif command == {"op": "stop"}:
                        service.stop()
                        reply({"ok": True, "status": service.status()})
                        return 0
                    else:
                        raise Refused("invalid_request")
                    reply({"ok": True, "status": result})
    except Refused as error:
        reply({"ok": False, "error": str(error)})
        return 1
    except Exception:
        # Never serialize exception messages, stack traces, paths or requests.
        reply({"ok": False, "error": "operation_failed"})
        return 1
    finally:
        service.stop()
        control.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
