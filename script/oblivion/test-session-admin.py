#!/usr/bin/env python3
"""Run through the real guest terminal; only synthetic files and a local deb."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(*command, env=None):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=40, env=env)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


assert os.getuid() == 1000
assert run("sudo", "-n", "id", "-u") == "0"
assert run("findmnt", "-n", "-o", "FSTYPE", "/") == "overlay"
assert run("findmnt", "-n", "-o", "FSTYPE", "/run/oblivion-system/base") == "squashfs"
for path in ("/tmp", "/var/tmp", "/var/log"):
    assert run("findmnt", "-n", "-o", "FSTYPE", path) == "tmpfs"
assert sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"]
assert not Path("/run/oblivion-api/token").exists()
assert run("sudo", "-n", "python3", "-c",
           "import os; assert os.environ['https_proxy'] == 'http://synthetic:grant@127.0.0.1:9'; "
           "assert os.environ['HISTFILE'] == '/dev/null'; assert os.environ['NODE_USE_ENV_PROXY'] == '1'; "
           "assert os.environ['npm_config_logs_max'] == '0'; assert 'OPENCODE_PASSWORD' not in os.environ",
           env={**os.environ, "https_proxy": "http://synthetic:grant@127.0.0.1:9", "OPENCODE_PASSWORD": "synthetic"}) == ""

if sys.argv[1] == "seed":
    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / "package"
        (package / "DEBIAN").mkdir(parents=True)
        (package / "DEBIAN").chmod(0o755)
        (package / "DEBIAN/control").write_text(
            "Package: oblivion-admin-fixture\nVersion: 1.0\nArchitecture: all\n"
            "Maintainer: Oblivion Test <test@example.invalid>\nDescription: synthetic persistence probe\n")
        (package / "usr/bin").mkdir(parents=True)
        program = package / "usr/bin/oblivion-admin-fixture"
        program.write_text("#!/bin/sh\nprintf 'installed-in-session\\n'\n")
        program.chmod(0o755)
        run("dpkg-deb", "--root-owner-group", "--build", str(package), directory + "/fixture.deb")
        run("sudo", "-n", "apt-get", "install", "-y", directory + "/fixture.deb")
    run("sudo", "-n", "sh", "-c", "printf session-config > /etc/oblivion-admin-fixture")
    Path("/vault/workspace/admin-document").write_text("preserve-document")
    Path("/tmp/admin-temporary").write_text("volatile")
    Path("/var/tmp/admin-temporary").write_text("volatile")
    assert run("oblivion-admin-fixture") == "installed-in-session"
elif sys.argv[1] == "verify":
    assert run("oblivion-admin-fixture") == "installed-in-session"
    assert run("dpkg-query", "-W", "-f=${Status}", "oblivion-admin-fixture") == "install ok installed"
    assert run("sudo", "-n", "cat", "/etc/oblivion-admin-fixture") == "session-config"
    assert Path("/vault/workspace/admin-document").read_text() == "preserve-document"
    assert not Path("/tmp/admin-temporary").exists()
    assert not Path("/var/tmp/admin-temporary").exists()
elif sys.argv[1] == "isolated":
    assert not Path("/usr/bin/oblivion-admin-fixture").exists()
    assert not Path("/etc/oblivion-admin-fixture").exists()
    assert not Path("/vault/workspace/admin-document").exists()
else:
    raise AssertionError("unknown phase")
print("ADMIN_" + sys.argv[1].upper() + "_PASSED", flush=True)
