#!/usr/bin/python3 -B
"""Describe the tools actually bundled in this immutable session image."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

BASE = Path("/usr/lib/oblivion")
COMMANDS = (
    "bash", "sh", "ls", "cp", "mv", "rm", "mkdir", "find", "grep", "sed", "awk",
    "sort", "uniq", "head", "tail", "wc", "cut", "xargs", "diff", "patch", "sha256sum",
    "timeout", "tar", "gzip", "bzip2", "xz", "zip", "unzip", "file", "tree", "less", "nano",
    "tmux", "ps", "top", "watch", "curl", "openssl", "jq", "sqlite3", "git", "rg", "python3",
    "node", "npm", "npx", "pdfinfo", "pdftotext", "strings", "binwalk", "xxd",
    "hexdump", "nm", "objdump", "readelf", "patchelf", "pwn", "ropper", "gdb",
    "ltrace", "strace",
)
GUIDANCE = """# Oblivion session tools

These commands were checked while building this session image. Run
`oblivion-tools --json` for the package versions and command paths.

Python: use `python3 -m venv .venv` and `.venv/bin/python -m pip` for project
dependencies. Node and npm are available. No C/C++ compiler, Rust, Go, browser
or office suite is promised by this image; check before using other programs.

Binary analysis: strings (use -e l for UTF-16LE), binwalk, xxd, hexdump, nm,
objdump, readelf and patchelf are installed. Python's `pwn`/`pwnlib` (pwntools),
`ropper`, `angr` and `imghdr` are importable with python3; pwn and ropper also
have command-line launchers. imghdr is a compatibility module, not a shell
command. Project virtualenvs need --system-site-packages to reuse these modules.
The bundled angr 10 uses `from angr import claripy` for symbolic expressions.
Pwntools automatic update checks are disabled. Analysis output belongs in the
workspace; Ropper's default ~/.ropper cache stays inside the encrypted home.
Binwalk scans are available; optional extraction helpers are not all bundled.
Debugging: gdb, ltrace and strace can launch and trace your own processes.
They do not grant access to other users, other sessions or the host. Automatic
debuginfod downloads and GDB history saving are disabled. Save any explicit
trace output under /vault/workspace, or use /tmp for temporary traces.

Keep projects and durable dependencies under /vault/workspace or /vault/home.
Temporary files and package caches use RAM and may disappear when the VM stops.
Tools normally run as the session user; sudo grants root inside this VM only.
Use sudo apt-get update and sudo apt-get install PACKAGE for extra Debian tools.
Installed packages and system changes persist inside this session's encrypted
volume, share its free space, and are not shared with any other session. In an
ephemeral session they disappear when the session is destroyed. sudo does not
grant access to the host or bypass its network gateway. Use it only when needed.

The session may be offline. In chat mode, proxy-aware HTTP/HTTPS tools inherit
an opening-scoped proxy capability. Node's built-in fetch and HTTP(S) clients
use its native environment proxy support; other libraries need proxy support.
The host controls one global gateway policy: Open Web allows public HTTP/HTTPS
unless a rule blocks it; Strict requires allow rules; Offline denies all external
traffic. You cannot change this policy from the guest. A configured proxy does
not prove connectivity. Never bypass it, change routes or fall back to a
direct connection. Do not print proxy credentials or environment dumps.

To download a permitted HTTPS URL, prefer curl rather than trying absent wget
or invoking several alternative runtimes. There is no automatic public-IP check.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.build:
        packages = (BASE / "session-packages.txt").read_text().split()
        commands = {name: shutil.which(name) for name in COMMANDS}
        if not all(commands.values()):
            raise RuntimeError("Missing required session command")
        versions = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n", *packages], text=True,
        )
        node = json.loads((BASE / "session-node.json").read_text())
        architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        npm_packages = []
        for package in sorted((BASE / "node/lib/node_modules/npm").rglob("package.json")):
            data = json.loads(package.read_text())
            if "name" in data and "version" in data:
                npm_packages.append({"name": data["name"], "version": data["version"],
                                     "path": str(package.relative_to(BASE / "node"))})
        manifest = {"format_version": 1, "commands": commands,
                    "packages": dict(line.split("\t", 1) for line in versions.splitlines()),
                    "components": {"analysis": json.loads(Path("/opt/oblivion-analysis/inventory.json").read_text()),
                                   "node": {"version": node["version"], "npm": node["npm"],
                                            **node["architectures"][architecture], "npm_packages": npm_packages}}}
        (BASE / "session-tools.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (BASE / "session-tools.md").write_text(
            GUIDANCE + "\nAvailable commands: " + ", ".join(commands) + ".\n",
        )
        return
    if args.json:
        print((BASE / "session-tools.json").read_text(), end="")
        return
    print((BASE / "session-tools.md").read_text(), end="")


if __name__ == "__main__":
    main()
