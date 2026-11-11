#!/bin/sh
set -eu
cd "$(dirname "$0")"
swift build -c release
codesign --force --sign - --entitlements virtualization.entitlements .build/release/oblivion-vm
