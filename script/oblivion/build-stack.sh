#!/bin/sh
# Build the official-agent runtime consumed by the native headless launcher.
set -eu
cd "$(dirname "$0")/../.."
arch=${OBLIVION_ARCH:-arm64}
case "$arch" in
    amd64) manager=bun-linux-x64 ;;
    arm64) manager=bun-linux-arm64 ;;
    *) echo 'OBLIVION_ARCH must be amd64 or arm64' >&2; exit 2 ;;
esac
bun run --cwd packages/oblivion-tools build
bun run --cwd packages/oblivion-manager script/build.ts "--target=$manager"
docker buildx build --platform "linux/$arch" --file script/oblivion/Dockerfile.vm-lab \
    --target stack-runtime-iso \
    --build-arg "OBLIVION_IMAGE_NAME=${OBLIVION_IMAGE_NAME:-oblivion-development}" \
    --build-arg "OBLIVION_HOST_KERNEL_VERSION=${OBLIVION_HOST_KERNEL_VERSION:-}" \
    --build-arg "MANAGER_BINARY=artifacts/oblivion-manager/$manager/oblivion-manager" \
    --build-arg "MANAGER_ASSETS=artifacts/oblivion-manager/$manager/assets" \
    --output "type=local,dest=artifacts/oblivion-stack-$arch" .
