#!/bin/sh
# Build either the shared private controller or the outer bootable Live OS.
set -eu
cd "$(dirname "$0")/../.."
[ "$#" -eq 1 ] || { echo 'Usage: build-image.sh controller|live' >&2; exit 2; }
case "$1" in
    controller) target=controller-runtime-artifacts; output=oblivion-runtime; image_name=${OBLIVION_IMAGE_NAME:-oblivion-development}; set -- ;;
    live)
        target=live-iso-artifacts; output=oblivion-stack
        channel=${OBLIVION_BUNDLE_CHANNEL:-}
        version=${OBLIVION_DESKTOP_VERSION:-}
        python3 -B script/oblivion/bundle-version.py validate --channel "$channel" --product-version "$version"
        image_name=${OBLIVION_IMAGE_NAME:-oblivion-$version}
        set -- --build-arg "OBLIVION_BUNDLE_CHANNEL=$channel" --build-arg "OBLIVION_DESKTOP_VERSION=$version"
        ;;
    *) echo 'Image role must be controller or live' >&2; exit 2 ;;
esac
arch=${OBLIVION_ARCH:-arm64}
case "$arch" in
    amd64) manager=bun-linux-x64 ;;
    arm64) manager=bun-linux-arm64 ;;
    *) echo 'OBLIVION_ARCH must be amd64 or arm64' >&2; exit 2 ;;
esac
bun run --cwd packages/oblivion-tools build
bun run --cwd packages/oblivion-manager script/build.ts "--target=$manager"
for name in @opentui/core @opentui/solid solid-js zod shell-quote; do
    mkdir -p "artifacts/oblivion-manager/$manager/licenses/$name"
    cp "packages/oblivion-manager/node_modules/$name/LICENSE" "artifacts/oblivion-manager/$manager/licenses/$name/LICENSE"
done
docker buildx build --platform "linux/$arch" --file script/oblivion/Dockerfile.vm-lab \
    --target "$target" \
    "$@" \
    --build-arg "OBLIVION_IMAGE_NAME=$image_name" \
    --build-arg "OBLIVION_HOST_KERNEL_VERSION=${OBLIVION_HOST_KERNEL_VERSION:-}" \
    --build-arg "MANAGER_BINARY=artifacts/oblivion-manager/$manager/oblivion-manager" \
    --build-arg "MANAGER_ASSETS=artifacts/oblivion-manager/$manager/assets" \
    --build-arg "MANAGER_LICENSES=artifacts/oblivion-manager/$manager/licenses" \
    --output "type=local,dest=artifacts/$output-$arch" .
