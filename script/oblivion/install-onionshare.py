#!/usr/bin/python3 -B
"""Build the locked OnionShare environment; never called at runtime."""
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request


def install(lock, source, destination):
    descriptor = json.loads(source.read_text())
    blocks = re.split(r"\n(?=[a-z][a-z0-9-]*==)", lock.read_text())
    upstream = next(block for block in blocks if block.startswith(descriptor["package"] + "=="))
    if not upstream.startswith(f'{descriptor["package"]}=={descriptor["version"]} \\\n'):
        raise ValueError("Upstream version differs from source descriptor")
    if re.findall(r"--hash=sha256:([a-f0-9]{64})", upstream) != [descriptor["wheel_sha256"]]:
        raise ValueError("Upstream wheel differs from source descriptor")
    subprocess.run([sys.executable, "-m", "venv", str(destination)], check=True)
    # Stem's locked release is source-only. Build it with the same explicitly
    # hashed setuptools/wheel/packaging as the full lock, without PEP 517's
    # otherwise unpinned, network-resolved build environment.
    bootstrap = destination / "build-tools.lock"
    bootstrap.write_text("\n".join(block for block in blocks if re.match(r"(?:setuptools|wheel|packaging)==", block)))
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    for requirements, report in ((bootstrap, "bootstrap-report.json"), (lock, "install-report.json")):
        subprocess.run([
            str(destination / "bin/python"), "-m", "pip", "--isolated", "install",
            "--index-url", "https://pypi.org/simple", "--require-hashes", "--no-deps",
            "--no-build-isolation", "--no-cache-dir", "--no-compile",
            "--report", str(destination / report), "-r", str(requirements),
        ], check=True, env=environment)
    subprocess.run([str(destination / "bin/python"), "-m", "pip", "check"], check=True, env=environment)
    shutil.copyfile(source, destination / "source.json")
    shutil.copyfile(lock, destination / "requirements.lock")
    license_sources = source.parent / "onionshare-licenses.json"
    shutil.copyfile(license_sources, destination / "license-sources.json")
    for supplement in json.loads(license_sources.read_text())["sources"]:
        with urllib.request.urlopen(supplement["url"], timeout=30) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != supplement["sha256"]:
            raise ValueError("Supplemental license source differs")
        directory = destination / "licenses" / supplement["package"]
        directory.mkdir(parents=True)
        if "members" not in supplement:
            (directory / supplement["filename"]).write_bytes(data)
            continue
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for name in supplement["members"]:
                member = archive.getmember(name)
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError("Invalid supplemental license")
                (directory / Path(name).name).write_bytes(archive.extractfile(member).read())
    subprocess.run([
        str(destination / "bin/python"), "-B", __file__, "--inventory", str(destination),
    ], check=True, env=environment)
    # The HTTP worker has no package manager. Retain the reports, locked
    # sources and installed third-party licenses for image/release auditing.
    for entry in (destination / "lib").glob("python*/site-packages/pip*"):
        shutil.rmtree(entry)
    for entry in (destination / "bin").glob("pip*"):
        entry.unlink()
    bootstrap.unlink()


def inventory(destination):
    reports = [json.loads((destination / name).read_text()) for name in ("bootstrap-report.json", "install-report.json")]
    downloads = {
        re.sub(r"[-_.]+", "-", item["metadata"]["name"]).lower(): item["download_info"]
        for report in reports for item in report["install"]
    }
    supplements = {value["package"]: value for value in json.loads((destination / "license-sources.json").read_text())["sources"]}
    components = []
    for distribution in sorted(importlib.metadata.distributions(), key=lambda value: value.metadata["Name"].lower()):
        name = distribution.metadata["Name"]
        if name.lower() == "pip":
            continue
        canonical = re.sub(r"[-_.]+", "-", name).lower()
        download = downloads[canonical]
        licenses = []
        for entry in distribution.files or []:
            if any(part.lower().startswith(("license", "licence", "copying", "copyright", "notice")) for part in entry.parts):
                path = Path(distribution.locate_file(entry))
                if path.is_file():
                    licenses.append({"path": str(path.relative_to(destination)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        if canonical in supplements:
            if supplements[canonical]["version"] != distribution.version:
                raise ValueError("Supplemental license version differs")
            licenses.extend({"path": str(path.relative_to(destination)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                            for path in sorted((destination / "licenses" / canonical).iterdir()))
        if not licenses:
            raise ValueError(f"Missing packaged license: {canonical}")
        components.append({
            "name": canonical, "version": distribution.version,
            "url": download["url"], "sha256": download["archive_info"]["hashes"]["sha256"],
            "license": distribution.metadata.get("License-Expression") or distribution.metadata.get("License"),
            "licenses": licenses,
            **({"license_source": supplements[canonical]} if canonical in supplements else {}),
        })
    (destination / "inventory.json").write_text(json.dumps({
        "format_version": 1, "upstream": json.loads((destination / "source.json").read_text()),
        "requirements_sha256": hashlib.sha256((destination / "requirements.lock").read_bytes()).hexdigest(),
        "components": components,
    }, indent=2) + "\n")


if __name__ == "__main__":
    if sys.argv[1] == "--inventory":
        inventory(Path(sys.argv[2]))
    else:
        install(*(Path(value) for value in sys.argv[1:]))
