#!/bin/sh
# Development artifact only. This target never creates an ISO or publishes.
set -eu
cd "$(dirname "$0")/../.."
arch=${OBLIVION_ARCH:-amd64}
version=${OBLIVION_DEB_VERSION:-}
[ -n "$version" ] || { echo 'Set OBLIVION_DEB_VERSION, for example 1.0.0~dev20261104' >&2; exit 2; }
case "$version" in *~dev*) ;; *) echo 'Only explicit ~dev package versions are supported' >&2; exit 2;; esac
case "$arch" in
    amd64) manager=bun-linux-x64 ;;
    arm64) manager=bun-linux-arm64 ;;
    *) echo 'OBLIVION_ARCH must be amd64 or arm64' >&2; exit 2;;
esac
bun run --cwd packages/oblivion-tools build
bun run --cwd packages/oblivion-manager script/build.ts "--target=$manager"
revision=$(git rev-parse HEAD)
dirty=false
[ -z "$(git status --porcelain --untracked-files=normal)" ] || dirty=true
docker buildx build --platform "linux/$arch" --file script/oblivion/Dockerfile.vm-lab \
    --target debian-package-artifacts --build-arg "OBLIVION_DEB_VERSION=$version" \
    --build-arg "OBLIVION_SOURCE_REVISION=$revision" --build-arg "OBLIVION_SOURCE_DIRTY=$dirty" \
    --build-arg "MANAGER_BINARY=artifacts/oblivion-manager/$manager/oblivion-manager" \
    --build-arg "MANAGER_ASSETS=artifacts/oblivion-manager/$manager/assets" \
    --output "type=local,dest=artifacts/oblivion-debian-$arch" .
