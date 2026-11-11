"""Configure only app-owned paths; no hardware/network/OS preference changes."""
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import sys


def identities():
    yield from ((1100, "oblivion-vm"), (1101, "oblivion-gateway-vm"), (1102, "oblivion-import-vm"), (1103, "oblivion-export-vm"), (1105, "oblivion-onion-gateway-vm"), (1106, "oblivion-onion-file-vm"))
    for slot in range(1, 32):
        for offset, role in ((0, "session"), (1, "gateway-vm"), (2, "import-vm"), (3, "export-vm"), (5, "onion-gateway-vm"), (6, "onion-file-vm")):
            yield 16000 + slot * 16 + offset, f"oblivion-{role}-s{slot}"


def regular(path, mode=None):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError("unsafe_application_config")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise ValueError("unsafe_application_config")
    return info


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def configure(account):
    if os.geteuid() != 0 or not account or len(account) > 64:
        raise ValueError("choose_existing_non_root_account")
    manager = pwd.getpwnam(account)
    if not 0 < manager.pw_uid < 2**32 - 1 or manager.pw_shell in ("/usr/sbin/nologin", "/bin/false"):
        raise ValueError("choose_existing_non_root_account")
    users = {entry.pw_uid: entry.pw_name for entry in pwd.getpwall()}
    groups = {entry.gr_gid: entry.gr_name for entry in grp.getgrall()}
    for uid, name in identities():
        if (uid in users and users[uid] != name or uid in groups and groups[uid] != name
                or name in users.values() and users.get(uid) != name
                or name in groups.values() and groups.get(uid) != name or uid == manager.pw_uid):
            raise ValueError("reserved_service_identity_occupied")
    installation = Path("/etc/oblivion/installation.json")
    regular(installation)
    if json.loads(installation.read_text()) != {"version": 1, "mode": "controller-runtime"}:
        raise ValueError("incompatible_installation_profile")
    config_path = Path("/etc/oblivion/controller.json")
    if config_path.exists() or config_path.is_symlink():
        regular(config_path, 0o600)
        config = json.loads(config_path.read_text())
        if config.get("manager_uid") != manager.pw_uid:
            raise ValueError("existing_application_config_differs")
    else:
        config = json.loads(Path("/usr/share/oblivion/controller.template.json").read_text())
        config["manager_uid"] = manager.pw_uid
    tmpfile = Path("/etc/tmpfiles.d/oblivion.conf")
    rule = f"d /run/oblivion-manager 0700 {manager.pw_uid} - -\n"
    if tmpfile.exists() or tmpfile.is_symlink():
        regular(tmpfile)
        if tmpfile.read_text() != rule:
            raise ValueError("existing_application_runtime_rule_differs")
    # Complete preflight before writing anything. Existing encrypted images and
    # generated configuration are never replaced during install or upgrade.
    data = Path("/var/lib/oblivion")
    if data.exists() or data.is_symlink():
        info = data.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("unsafe_application_data_directory")
    else:
        data.mkdir(mode=0o700)
    if not config_path.exists():
        create(config_path, json.dumps(config, indent=2) + "\n", 0o600)
    if not tmpfile.exists():
        create(tmpfile, rule, 0o644)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("choose_existing_non_root_account")
        configure(sys.argv[1])
    except (OSError, ValueError, KeyError):
        print("Oblivion configuration failed: select an existing non-root account and check app-path ownership and reserved identities.", file=sys.stderr)
        raise SystemExit(1)
