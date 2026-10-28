#!/usr/bin/env python3
"""Build-only installer for the pinned upstream Node LTS archive and its npm."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", choices=("arm64", "amd64"))
    parser.add_argument("lock", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text())
    source = lock["architectures"][args.architecture]
    with tempfile.TemporaryDirectory(prefix="oblivion-node-build-") as directory:
        work = Path(directory)
        checksum = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(source["url"], timeout=60) as response, (work / "node.tar.xz").open("wb") as output:
            while chunk := response.read(65536):
                size += len(chunk)
                if size > 128 * 1024 * 1024:
                    raise ValueError("Node archive exceeds the build download limit")
                checksum.update(chunk)
                output.write(chunk)
        if checksum.hexdigest() != source["sha256"]:
            raise ValueError("Node archive checksum differs from session-node.json")
        with tarfile.open(work / "node.tar.xz", "r:xz") as archive:
            archive.extractall(work / "unpacked", filter="data")
        root = work / "unpacked" / source["url"].rsplit("/", 1)[1].removesuffix(".tar.xz")
        if json.loads((root / "lib/node_modules/npm/package.json").read_text())["version"] != lock["npm"]:
            raise ValueError("Bundled npm version differs from session-node.json")
        (args.output / "bin").mkdir(parents=True)
        shutil.copy2(root / "bin/node", args.output / "bin/node")
        shutil.copytree(root / "lib/node_modules/npm", args.output / "lib/node_modules/npm", symlinks=True)
        shutil.copy2(root / "LICENSE", args.output / "LICENSE")
        (args.output / "bin/npm").symlink_to("../lib/node_modules/npm/bin/npm-cli.js")
        (args.output / "bin/npx").symlink_to("../lib/node_modules/npm/bin/npx-cli.js")


if __name__ == "__main__":
    main()
