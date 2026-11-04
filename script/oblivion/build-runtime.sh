#!/bin/sh
# Build the shared private controller ISO, not the outer bootable Live OS.
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
for name in @opentui/core @opentui/solid solid-js zod; do
    mkdir -p "artifacts/oblivion-manager/$manager/licenses/$name"
    cp "packages/oblivion-manager/node_modules/$name/LICENSE" "artifacts/oblivion-manager/$manager/licenses/$name/LICENSE"
done
docker buildx build --platform "linux/$arch" --file script/oblivion/Dockerfile.vm-lab \
    --target controller-runtime-artifacts \
    --build-arg "OBLIVION_IMAGE_NAME=${OBLIVION_IMAGE_NAME:-oblivion-development}" \
    --build-arg "OBLIVION_HOST_KERNEL_VERSION=${OBLIVION_HOST_KERNEL_VERSION:-}" \
    --build-arg "MANAGER_BINARY=artifacts/oblivion-manager/$manager/oblivion-manager" \
    --build-arg "MANAGER_ASSETS=artifacts/oblivion-manager/$manager/assets" \
    --build-arg "MANAGER_LICENSES=artifacts/oblivion-manager/$manager/licenses" \
    --output "type=local,dest=artifacts/oblivion-runtime-$arch" .
