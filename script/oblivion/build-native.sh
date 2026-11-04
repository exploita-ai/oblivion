#!/bin/sh
# Native development artifacts only; consume a separately built matching ISO.
set -eu
cd "$(dirname "$0")/../.."
version=${OBLIVION_DESKTOP_VERSION:-}
[ -n "$version" ] || { echo 'Set OBLIVION_DESKTOP_VERSION, for example 1.0.0~dev20261104' >&2; exit 2; }
case "$version" in *~dev*) ;; *) echo 'Only explicit ~dev desktop versions are supported' >&2; exit 2;; esac
case "$version" in [0-9]*) ;; *) echo 'Desktop versions must start with a digit' >&2; exit 2;; esac
case "$version" in *[!0-9A-Za-z.+:~-]*) echo 'Desktop version contains unsupported characters' >&2; exit 2;; esac
[ "${#version}" -le 64 ] || { echo 'Desktop version exceeds 64 characters' >&2; exit 2; }
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform=darwin-arm64; manager=bun-darwin-arm64; arch=arm64 ;;
    Linux-x86_64) platform=linux-x86_64; manager=bun-linux-x64; arch=amd64 ;;
    *) echo 'Build on Apple Silicon macOS or x86_64 Linux; cross compilation is not supported' >&2; exit 2 ;;
esac
runtime=${OBLIVION_DESKTOP_RUNTIME:-artifacts/oblivion-stack-$arch}
output=${OBLIVION_DESKTOP_OUTPUT:-artifacts/oblivion-desktop-$platform/$version}
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Desktop output already exists' >&2; exit 2; }
mkdir -p "$(dirname "$output")"
work=$(mktemp -d "$(dirname "$output")/.desktop-build.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
source_id=$(python3 -B script/oblivion/bundle-native.py prepare --runtime "$runtime" --platform "$platform" --output "$work/bundle")
OBLIVION_DESKTOP_SOURCE_SHA256="$source_id" OBLIVION_DESKTOP_PLATFORM="$platform" CARGO_TARGET_DIR="$work/host-target" \
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
    --platform "$platform" --product-version "$version" --cli "$work/host-target/release/oblivion" \
    --helper "$helper" --manager "$work/manager/oblivion-manager" --manager-assets "$work/manager/assets" --output "$output"
