#!/usr/bin/env python3
"""Create a short-lived TLS identity for synthetic, offline laboratories."""

import subprocess
from pathlib import Path


def generate(directory: Path):
    certificate = directory / "fixture-cert.pem"
    key = directory / "fixture-key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "1", "-subj", "/CN=Oblivion isolated fixture",
        "-addext", "subjectAltName=DNS:api.abliteration.ai",
        "-keyout", str(key), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    return certificate, key
