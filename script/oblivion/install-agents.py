#!/usr/bin/env python3
"""Install original pinned Linux clients, their distribution policy and notices.

Archive integrity identifies upstream bytes. It does not establish legal
acceptance. The separate distribution inventory records the applicable license
category and documented conditions without replacing native authentication.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request


POLICIES = {
    "codex": ("permissive", "Apache-2.0", "Apache-2.0", ("LICENSE", "NOTICE"),
              ("include-license-and-notices", "retain-copyright")),
    "opencode2": ("permissive", "MIT", "MIT", ("LICENSE",),
                  ("include-license-and-notices", "retain-copyright")),
    "claude": ("commercial-native", "LicenseRef-Anthropic-Claude-Code", "SEE LICENSE IN LICENSE.md", ("LICENSE.md",),
               ("commercial-terms-apply", "unmodified-native-client", "native-authentication-methods-preserved",
                "end-user-owned-provider-credentials", "direct-provider-billing", "no-usage-resale-or-intermediation",
                "no-implied-endorsement")),
}
DOCUMENTATION = Path("usr/share/doc/oblivion-agents")
EVIDENCE = Path("usr/lib/oblivion/build-evidence.json")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def distribution(agent, metadata):
    policy = metadata["distribution"]
    category, license, package_license, required, conditions = POLICIES[agent]
    if (policy["category"], policy["license"], policy["package_license"], policy["conditions"]) != (
            category, license, package_license, list(conditions)):
        raise ValueError("Official client distribution policy differs")
    if agent == "claude" and (policy.get("terms_url"), policy.get("integration_url")) != (
            "https://www.anthropic.com/legal/commercial-terms", "https://code.claude.com/docs/en/legal-and-compliance"):
        raise ValueError("Claude Code distribution terms are missing")
    names = []
    for notice in policy["notices"]:
        path = PurePosixPath(notice["path"])
        if (len(path.parts) != 2 or path.parts[0] != f'{agent}-{metadata["version"]}'
                or path.name in (".", "..", "distribution.json") or "\\" in notice["path"]
                or re.fullmatch(r"[0-9a-f]{64}", notice["sha256"]) is None
                or not notice["source"].startswith("https://raw.githubusercontent.com/")):
            raise ValueError("Invalid official client notice provenance")
        names.append(path.name)
    if len(names) != len(set(names)) or not set(required).issubset(names):
        raise ValueError("Required official client notices are missing")
    return policy


def notice_inputs(lock_path, agent, metadata):
    policy = distribution(agent, metadata)
    result = {}
    for notice in policy["notices"]:
        path = lock_path.parent / "agent-notices" / notice["path"]
        if (path.parent.is_symlink() or path.is_symlink() or not path.is_file()
                or not 0 < path.stat().st_size <= 1024 * 1024 or sha256(path) != notice["sha256"]):
            raise ValueError("Official client notice differs from its pinned source")
        result[path.name] = path.read_bytes()
    return result


def package_identity(package, metadata, source):
    value = json.loads((package / "package.json").read_text())
    if (value["name"], value["version"], value.get("license")) != (
            source["package"], source["version"], metadata["distribution"]["package_license"]):
        raise ValueError("Official client package identity or license differs from the lock")
    executable = package / source["executable"]
    if not executable.is_file() or not executable.resolve().is_relative_to(package.resolve()):
        raise ValueError("Official client executable is missing from the upstream package")
    return executable


def installed_client(root, agent, metadata, source):
    policy = distribution(agent, metadata)
    package = root / "usr/lib/oblivion/agents" / agent
    executable = package_identity(package, metadata, source)
    native = root / "usr/lib/oblivion/agents/bin" / agent
    entrypoint = root / "usr/bin" / agent
    if (not native.is_symlink() or native.readlink() != Path("..") / agent / source["executable"]
            or not entrypoint.is_symlink() or entrypoint.readlink() != Path("../lib/oblivion/guest/agent-wrapper.sh")):
        raise ValueError("Installed official client entrypoint differs")
    documentation = root / DOCUMENTATION / agent
    notices = []
    for notice in policy["notices"]:
        path = documentation / PurePosixPath(notice["path"]).name
        if path.is_symlink() or not path.is_file() or sha256(path) != notice["sha256"]:
            raise ValueError("Installed official client notice is missing or changed")
        notices.append({"path": path.relative_to(root).as_posix(), "sha256": notice["sha256"], "source": notice["source"]})
    policy_path = documentation / "distribution.json"
    if policy_path.is_symlink() or policy_path.read_bytes() != encoded(policy):
        raise ValueError("Installed official client distribution policy differs")
    # Preserve and identify upstream notices even when a platform package omits
    # its own top-level license. Supplemental pinned notices are always required.
    upstream = [{"path": path.relative_to(root).as_posix(), "sha256": sha256(path)}
                for path in sorted(package.rglob("*"))
                if path.is_file() and any(part.lower().startswith(("license", "licence", "notice", "copying", "copyright"))
                                          for part in path.relative_to(package).parts)]
    return {
        "id": agent, "version": metadata["version"],
        "package": {key: source[key] for key in ("package", "version", "url", "integrity")},
        "executable": {"path": executable.relative_to(root).as_posix(), "sha256": sha256(executable)},
        "distribution": {key: value for key, value in policy.items() if key != "notices"},
        "policy": {"path": policy_path.relative_to(root).as_posix(), "sha256": sha256(policy_path)},
        "notices": notices, "upstream_notices": upstream,
    }


def require_clients(root, agents):
    expected = set(agents)
    packages = root / "usr/lib/oblivion/agents"
    native = packages / "bin"
    if (({path.name for path in packages.iterdir() if path.name != "bin"} if packages.exists() else set()) != expected
            or ({path.name for path in native.iterdir()} if native.exists() else set()) != expected):
        raise ValueError("Unlisted or incomplete official client installation")
    for agent in POLICIES:
        for path in (root / "usr/bin" / agent, root / DOCUMENTATION / agent):
            if (path.exists() or path.is_symlink()) != (agent in expected):
                raise ValueError("Unlisted or incomplete official client installation")


def verify_installed(root):
    evidence = json.loads((root / EVIDENCE).read_text())
    lock_path = root / DOCUMENTATION / "install-agents.json"
    lock = json.loads(lock_path.read_text())
    architecture = evidence["architecture"]
    clients = evidence["clients"]
    if (evidence["format"] != "oblivion-official-clients" or evidence["version"] != 1 or lock["version"] != 1
            or architecture not in ("arm64", "amd64") or evidence["lock_sha256"] != sha256(lock_path)
            or not clients or len({client["id"] for client in clients}) != len(clients)):
        raise ValueError("Invalid installed official client evidence")
    require_clients(root, [client["id"] for client in clients])
    for client in clients:
        metadata = lock["agents"][client["id"]]
        if client != installed_client(root, client["id"], metadata, metadata["architectures"][architecture]):
            raise ValueError("Installed official client evidence differs from the filesystem")
    return evidence


def install(agent, architecture, metadata, notices, root, verify, *, opener=urllib.request.urlopen):
    version = metadata["version"]
    source = metadata["architectures"][architecture]
    target = root / "usr/lib/oblivion/agents" / agent
    native = root / "usr/lib/oblivion/agents/bin" / agent
    entrypoint = root / "usr/bin" / agent
    documentation = root / DOCUMENTATION / agent
    if any(path.exists() or path.is_symlink() for path in (target, native, entrypoint, documentation)):
        raise ValueError(f"Refusing to replace an existing {agent} installation")
    target.parent.mkdir(parents=True, exist_ok=True)
    native.parent.mkdir(parents=True, exist_ok=True)
    entrypoint.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{agent}-build-", dir=target.parent) as directory:
        work = Path(directory)
        digest = hashlib.sha512()
        size = 0
        with opener(source["url"], timeout=60) as response, (work / "agent.tgz").open("wb") as output:
            if urllib.parse.urlsplit(response.url).scheme != "https" or urllib.parse.urlsplit(response.url).netloc != "registry.npmjs.org":
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
        executable = package_identity(package, metadata, source)
        executable.chmod(0o755)
        if verify:
            output = subprocess.run([str(executable), "--version"], check=True, capture_output=True,
                                    text=True, timeout=30, env={"PATH": os.defpath, "HOME": directory})
            if version not in output.stdout:
                raise ValueError(f"{agent} version output differs from the lock")
        package.rename(target)
        try:
            documentation.mkdir(parents=True)
            for name, data in notices.items():
                (documentation / name).write_bytes(data)
            (documentation / "distribution.json").write_bytes(encoded(metadata["distribution"]))
            native.symlink_to(Path("..") / agent / source["executable"])
            entrypoint.symlink_to(Path("../lib/oblivion/guest/agent-wrapper.sh"))
        except OSError:
            native.unlink(missing_ok=True)
            shutil.rmtree(target)
            if documentation.exists():
                shutil.rmtree(documentation)
            raise
    print(f"Installed {agent} {version} ({architecture}), upstream SHA-512 and required notices verified")


def install_selected(lock_path, architecture, agents, root, verify, *, opener=urllib.request.urlopen):
    lock = json.loads(lock_path.read_text())
    if lock["version"] != 1 or architecture not in ("arm64", "amd64"):
        raise ValueError("Unsupported agent lock or architecture")
    selected = list(dict.fromkeys(agents))
    if not selected or not set(selected).issubset(POLICIES):
        raise ValueError("Choose pinned official clients")
    # Validate every selected policy and all required notice bytes before any
    # network access or installation. A SHA-512 pin alone is not a license gate.
    notices = {agent: notice_inputs(lock_path, agent, lock["agents"][agent]) for agent in selected}
    require_clients(root, [])
    if (root / EVIDENCE).exists() or (root / DOCUMENTATION / "install-agents.json").exists():
        raise ValueError("Refusing to replace official client build evidence")
    for agent in selected:
        install(agent, architecture, lock["agents"][agent], notices[agent], root, verify, opener=opener)
    (root / DOCUMENTATION / "install-agents.json").write_bytes(lock_path.read_bytes())
    evidence = {"format": "oblivion-official-clients", "version": 1, "architecture": architecture,
                "lock_sha256": sha256(lock_path), "clients": [
                    installed_client(root, agent, lock["agents"][agent], lock["agents"][agent]["architectures"][architecture])
                    for agent in selected]}
    with (root / EVIDENCE).open("xb") as output:
        output.write(encoded(evidence))
    return verify_installed(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", choices=("arm64", "amd64"))
    parser.add_argument("root", type=Path, help="Guest rootfs to receive clients and their required notices")
    parser.add_argument("agents", nargs="+", choices=("codex", "claude", "opencode2"))
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_suffix(".json"))
    parser.add_argument("--verify", action="store_true", help="Run --version on the matching Linux architecture")
    args = parser.parse_args()
    install_selected(args.lock, args.architecture, args.agents, args.root.resolve(), args.verify)


if __name__ == "__main__":
    main()
