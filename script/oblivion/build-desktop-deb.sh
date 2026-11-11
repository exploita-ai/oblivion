#!/bin/sh
# Build the Linux desktop package from the same native bundle as the Live OS.
set -eu
cd "$(dirname "$0")/../.."
arch=${OBLIVION_ARCH:-amd64}
version=${OBLIVION_DEB_VERSION:-}
channel=${OBLIVION_BUNDLE_CHANNEL:-}
python3 -B script/oblivion/bundle-version.py validate --channel "$channel" --product-version "$version"
case "$arch" in
    amd64) manager=bun-linux-x64 ;;
    arm64) manager=bun-linux-arm64 ;;
    *) echo 'OBLIVION_ARCH must be amd64 or arm64' >&2; exit 2 ;;
esac
output="artifacts/oblivion-desktop-deb-$arch"
package="oblivion-desktop_${version}_$arch.deb"
for file in "$output/$package" "$output/$package.sha256"; do
    [ ! -e "$file" ] && [ ! -L "$file" ] || { echo 'Desktop package output already exists' >&2; exit 2; }
done
revision=$(git rev-parse HEAD)
dirty=false
[ -z "$(git status --porcelain --untracked-files=normal)" ] || dirty=true
bun run --cwd packages/oblivion-tools build
bun run --cwd packages/oblivion-manager script/build.ts "--target=$manager"
for name in @opentui/core @opentui/solid solid-js zod shell-quote; do
    mkdir -p "artifacts/oblivion-manager/$manager/licenses/$name"
    cp "packages/oblivion-manager/node_modules/$name/LICENSE" "artifacts/oblivion-manager/$manager/licenses/$name/LICENSE"
done
mkdir -p "$output"
work=$(mktemp -d "$output/.desktop-export.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
docker buildx build --platform "linux/$arch" --file script/oblivion/Dockerfile.vm-lab \
    --target desktop-debian-artifacts --build-arg "OBLIVION_DESKTOP_VERSION=$version" \
    --build-arg "OBLIVION_BUNDLE_CHANNEL=$channel" \
    --build-arg "OBLIVION_SOURCE_REVISION=$revision" --build-arg "OBLIVION_SOURCE_DIRTY=$dirty" \
    --build-arg "OBLIVION_HOST_KERNEL_VERSION=${OBLIVION_HOST_KERNEL_VERSION:-}" \
    --build-arg "MANAGER_BINARY=artifacts/oblivion-manager/$manager/oblivion-manager" \
    --build-arg "MANAGER_ASSETS=artifacts/oblivion-manager/$manager/assets" \
    --build-arg "MANAGER_LICENSES=artifacts/oblivion-manager/$manager/licenses" \
    --output "type=local,dest=$work" .
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$work" && sha256sum -c "$package.sha256")
else
    (cd "$work" && shasum -a 256 -c "$package.sha256")
fi
ln "$work/$package" "$output/$package"
ln "$work/$package.sha256" "$output/$package.sha256"
