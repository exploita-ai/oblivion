#!/usr/bin/env python3
"""Install pinned official Linux agents into a guest rootfs without npm scripts.

Run during an image build or an explicit installation step. Downloads originate
from the upstream npm packages and must match the committed SHA-512 lock. This
does not authorize redistribution of a package under different license terms.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


def install(agent, architecture, lock, root, verify):
    version = lock["agents"][agent]["version"]
    source = lock["agents"][agent]["architectures"][architecture]
    target = root / "usr/lib/oblivion/agents" / agent
    entrypoint = root / "usr/bin" / agent
    if target.exists() or entrypoint.exists() or entrypoint.is_symlink():
        raise ValueError(f"Refusing to replace an existing {agent} installation")
    target.parent.mkdir(parents=True, exist_ok=True)
    entrypoint.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{agent}-build-", dir=target.parent) as directory:
        work = Path(directory)
        digest = hashlib.sha512()
        size = 0
        with urllib.request.urlopen(source["url"], timeout=60) as response, (work / "agent.tgz").open("wb") as output:
            if not response.url.startswith("https://registry.npmjs.org/"):
                raise ValueError("Agent download left the official npm registry")
            while chunk := response.read(65536):
                size += len(chunk)
                if size > 512 * 1024 * 1024:
                    raise ValueError("Agent archive exceeds the download limit")
                digest.update(chunk)
                output.write(chunk)
        integrity = "sha512-" + base64.b64encode(digest.digest()).decode("ascii")
        if integrity != source["integrity"]:
            raise ValueError(f"{agent} archive differs from install-agents.json")
        with tarfile.open(work / "agent.tgz", "r:gz") as archive:
            archive.extractall(work / "unpacked", filter="data")
        package = work / "unpacked/package"
        metadata = json.loads((package / "package.json").read_text())
        if metadata["name"] != source["package"] or metadata["version"] != source["version"]:
            raise ValueError(f"{agent} package identity differs from the lock")
        executable = package / source["executable"]
        if not executable.is_file() or not executable.resolve().is_relative_to(package.resolve()):
            raise ValueError(f"{agent} executable is missing from the upstream package")
        executable.chmod(0o755)
        if verify:
            output = subprocess.run([str(executable), "--version"], check=True, capture_output=True,
                                    text=True, timeout=30, env={"PATH": os.defpath, "HOME": directory})
            if version not in output.stdout:
                raise ValueError(f"{agent} version output differs from the lock")
        package.rename(target)
        try:
            entrypoint.symlink_to(Path("../lib/oblivion/agents") / agent / source["executable"])
        except OSError:
            shutil.rmtree(target)
            raise
    print(f"Installed {agent} {version} ({architecture}), upstream SHA-512 verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", choices=("arm64", "amd64"))
    parser.add_argument("root", type=Path, help="Guest rootfs to receive usr/bin and usr/lib/oblivion/agents")
    parser.add_argument("agents", nargs="+", choices=("codex", "claude", "opencode2"))
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_suffix(".json"))
    parser.add_argument("--verify", action="store_true", help="Run --version on the matching Linux architecture")
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text())
    if lock["version"] != 1:
        raise ValueError("Unsupported agent lock format")
    for agent in dict.fromkeys(args.agents):
        install(agent, args.architecture, lock, args.root.resolve(), args.verify)


if __name__ == "__main__":
    main()
