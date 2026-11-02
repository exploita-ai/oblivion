#!/usr/bin/python3 -B
"""Install the reviewed binary-analysis bundle at image build time only."""
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


def install(lock, destination):
    subprocess.run([sys.executable, "-m", "venv", str(destination)], check=True)
    blocks = re.split(r"\n(?=[a-z][a-z0-9-]*==)", lock.read_text())
    bootstrap = destination / "build-tools.lock"
    bootstrap.write_text("\n".join(block for block in blocks if re.match(r"(?:setuptools|wheel|packaging)==", block)))
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    for requirements, report in ((bootstrap, "bootstrap-report.json"), (lock, "install-report.json")):
        subprocess.run([
            str(destination / "bin/python"), "-m", "pip", "--isolated", "install",
            "--index-url", "https://pypi.org/simple", "--require-hashes", "--no-deps",
            "--no-build-isolation", "--no-cache-dir", "--no-compile",
            "--only-binary=:all:", "--no-binary=ropper,filebytes,mulpyplexer,arpy",
            "--report", str(destination / report), "-r", str(requirements),
        ], check=True, env=environment)
    subprocess.run([str(destination / "bin/python"), "-m", "pip", "check"], check=True, env=environment)
    shutil.copyfile(lock, destination / "requirements.lock")
    # Some upstream wheels omit their license files. Keep the notices from the
    # corresponding hash-verified source archives beside the installed bundle.
    shutil.copyfile(lock.parent / "session-analysis-licenses.json", destination / "license-sources.json")
    for source in json.loads((destination / "license-sources.json").read_text())["sources"]:
        with urllib.request.urlopen(source["url"], timeout=30) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise ValueError("Analysis license source differs")
        directory = destination / "licenses" / source["package"]
        directory.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for name in source["members"]:
                member = archive.getmember(name)
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError("Invalid analysis license member")
                (directory / Path(name).name).write_bytes(archive.extractfile(member).read())
    subprocess.run([str(destination / "bin/python"), "-B", __file__, "--inventory", str(destination)], check=True)
    # Expose the bundled modules to ordinary python3 without replacing Debian's
    # interpreter. Project virtualenvs remain isolated unless explicitly opted in.
    site = next((destination / "lib").glob("python*/site-packages"))
    system_site = Path("/usr/local/lib") / site.parent.name / "dist-packages"
    system_site.mkdir(parents=True, exist_ok=True)
    (system_site / "oblivion-analysis.pth").write_text(str(site) + "\n")
    for name in ("pwn", "ropper"):
        (Path("/usr/local/bin") / name).symlink_to(destination / "bin" / name)
    bootstrap.unlink()


def inventory(destination):
    downloads = {
        re.sub(r"[-_.]+", "-", item["metadata"]["name"]).lower(): item["download_info"]
        for name in ("bootstrap-report.json", "install-report.json")
        for item in json.loads((destination / name).read_text())["install"]
    }
    components = []
    supplements = {value["package"]: value for value in json.loads((destination / "license-sources.json").read_text())["sources"]}
    for distribution in sorted(importlib.metadata.distributions(), key=lambda value: value.metadata["Name"].lower()):
        name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
        licenses = []
        for entry in distribution.files or []:
            if any(part.lower().startswith(("license", "licence", "copying", "copyright", "notice")) for part in entry.parts):
                path = Path(distribution.locate_file(entry))
                if path.is_file():
                    licenses.append({"path": str(path.relative_to(destination)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        if name in supplements:
            if supplements[name]["version"] != distribution.version:
                raise ValueError("Analysis license version differs")
            licenses.extend({"path": str(path.relative_to(destination)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                            for path in sorted((destination / "licenses" / name).iterdir()))
        if not licenses:
            raise ValueError(f"Missing analysis license: {name}")
        components.append({
            "name": name, "version": distribution.version,
            "url": downloads[name]["url"], "sha256": downloads[name]["archive_info"]["hashes"]["sha256"],
            "license": distribution.metadata.get("License-Expression") or distribution.metadata.get("License"),
            "licenses": licenses,
            **({"license_source": supplements[name]} if name in supplements else {}),
        })
    (destination / "inventory.json").write_text(json.dumps({
        "format_version": 1,
        "requirements_sha256": hashlib.sha256((destination / "requirements.lock").read_bytes()).hexdigest(),
        "components": components,
    }, indent=2) + "\n")


if __name__ == "__main__":
    if sys.argv[1] == "--inventory":
        inventory(Path(sys.argv[2]))
    else:
        install(*(Path(value) for value in sys.argv[1:]))
