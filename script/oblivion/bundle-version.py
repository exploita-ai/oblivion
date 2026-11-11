#!/usr/bin/env python3
"""The current bundle channel/version contract and source-ref naming policy."""
import argparse
import re


BASE = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
NUMBER = r"[1-9][0-9]*"
VERSIONS = {
    "dev": BASE + r"~dev" + NUMBER + r"\.[0-9a-f]{12}",
    "rc": BASE + r"~rc" + NUMBER,
    "stable": BASE,
}


def validate(channel, version):
    if (not isinstance(channel, str) or channel not in VERSIONS
            or not isinstance(version, str) or len(version) > 64
            or re.fullmatch(VERSIONS[channel], version) is None):
        raise ValueError("invalid_bundle_channel_or_version")


def resolve(ref, revision, run_number, base_version="1.0.0"):
    validate("stable", base_version)
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("invalid_bundle_source_revision")
    if not isinstance(run_number, str) or re.fullmatch(NUMBER, run_number) is None:
        raise ValueError("invalid_bundle_run_number")
    if not isinstance(ref, str):
        raise ValueError("invalid_bundle_source_ref")
    tag = re.fullmatch(r"refs/tags/v(" + BASE + r")(?:-rc\.(" + NUMBER + r"))?", ref)
    if tag:
        channel = "rc" if tag[2] else "stable"
        version = tag[1] + ("~rc" + tag[2] if tag[2] else "")
        validate(channel, version)
        return {"channel": channel, "product_version": version}
    if re.fullmatch(r"refs/pull/" + NUMBER + r"/merge", ref) is None:
        if not ref.startswith("refs/heads/"):
            raise ValueError("invalid_bundle_source_ref")
        branch = ref.removeprefix("refs/heads/")
        if (not branch or branch.endswith(("/", ".")) or "//" in branch or ".." in branch or "@{" in branch
                or any(ord(char) < 33 or ord(char) == 127 or char in "~^:?*[\\" for char in branch)
                or any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))):
            raise ValueError("invalid_bundle_source_ref")
    version = base_version + "~dev" + run_number + "." + revision[:12]
    validate("dev", version)
    return {"channel": "dev", "product_version": version}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate")
    check.add_argument("--channel", required=True)
    check.add_argument("--product-version", required=True)
    source = commands.add_parser("resolve")
    source.add_argument("--ref", required=True)
    source.add_argument("--revision", required=True)
    source.add_argument("--run-number", required=True)
    source.add_argument("--base-version", default="1.0.0")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            validate(args.channel, args.product_version)
            return
        for key, value in resolve(args.ref, args.revision, args.run_number, args.base_version).items():
            print(key + "=" + value)
    except ValueError as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
