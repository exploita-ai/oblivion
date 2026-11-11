#!/bin/sh
# Build native artifacts from a separately built matching controller ISO.
set -eu
cd "$(dirname "$0")/../.."
version=${OBLIVION_DESKTOP_VERSION:-}
channel=${OBLIVION_BUNDLE_CHANNEL:-}
python3 -B script/oblivion/bundle-version.py validate --channel "$channel" --product-version "$version"
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform=darwin-arm64; manager=bun-darwin-arm64; arch=arm64 ;;
    Linux-x86_64) platform=linux-x86_64; manager=bun-linux-x64; arch=amd64 ;;
    Linux-aarch64) platform=linux-arm64; manager=bun-linux-arm64; arch=arm64 ;;
    *) echo 'Build on Apple Silicon macOS or x86_64/arm64 Linux; cross compilation is not supported' >&2; exit 2 ;;
esac
runtime=${OBLIVION_DESKTOP_RUNTIME:-artifacts/oblivion-runtime-$arch}
output=${OBLIVION_DESKTOP_OUTPUT:-artifacts/oblivion-desktop-$platform/$version}
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Desktop output already exists' >&2; exit 2; }
mkdir -p "$(dirname "$output")"
work=$(mktemp -d "$(dirname "$output")/.desktop-build.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
source_id=$(python3 -B script/oblivion/bundle-native.py prepare --runtime "$runtime" --platform "$platform" --output "$work/bundle")
OBLIVION_BUNDLE_CHANNEL="$channel" OBLIVION_DESKTOP_VERSION="$version" OBLIVION_DESKTOP_SOURCE_SHA256="$source_id" OBLIVION_DESKTOP_PLATFORM="$platform" CARGO_TARGET_DIR="$work/host-target" \
    cargo build --manifest-path packages/oblivion-host/Cargo.toml --locked --offline --release --bin oblivion
if [ "$platform" = darwin-arm64 ]; then
    sh packages/oblivion-native/build.sh
    helper=packages/oblivion-native/.build/release/oblivion-vm
else
    CARGO_TARGET_DIR="$work/helper-target" cargo build --manifest-path packages/oblivion-native-linux/Cargo.toml --locked --offline --release --bin oblivion-vm
    helper="$work/helper-target/release/oblivion-vm"
fi
bun run --cwd packages/oblivion-manager script/build.ts "--target=$manager" "--output=$work/manager/oblivion-manager"
python3 -B script/oblivion/bundle-native.py assemble --prepared "$work/bundle" \
    --platform "$platform" --channel "$channel" --product-version "$version" --cli "$work/host-target/release/oblivion" \
    --helper "$helper" --manager "$work/manager/oblivion-manager" --manager-assets "$work/manager/assets" --output "$output"
