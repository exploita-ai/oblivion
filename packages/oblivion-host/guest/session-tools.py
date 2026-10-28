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
    "node", "npm", "npx", "pdfinfo", "pdftotext",
)
GUIDANCE = """# Oblivion session tools

These commands were checked while building this session image. Run
`oblivion-tools --json` for the package versions and command paths.

Python: use `python3 -m venv .venv` and `.venv/bin/python -m pip` for project
dependencies. Node and npm are available. No C/C++ compiler, Rust, Go, browser
or office suite is promised by this image; check before using other programs.

Keep projects and durable dependencies under /vault/workspace or /vault/home.
Temporary files and package caches use RAM and may disappear when the VM stops.
Tools run as an unprivileged session user. Do not use sudo or install OS packages.

The session may be offline. In chat mode, proxy-aware HTTP/HTTPS tools inherit
an opening-scoped proxy capability. Node's built-in fetch and HTTP(S) clients
use its native environment proxy support; other libraries need proxy support.
Remote destinations still require gateway Rules approval. A configured proxy
does not prove connectivity. Never bypass it, change routes or fall back to a
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
                    "components": {"node": {"version": node["version"], "npm": node["npm"],
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
