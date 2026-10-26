#!/bin/sh
set -eu
# Build only: this toolchain and the Debian source tree never enter the live OS.
sed -i 's/Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
apt-get update
apt-get install -y --no-install-recommends dpkg-dev meson ninja-build gcc libc6-dev \
    pkg-config libwlroots-0.18-dev libwayland-dev wayland-protocols libxkbcommon-dev python3
mkdir -p /source /out
cd /source
apt-get source cage=0.2.0-2
cd cage-0.2.0
python3 /build-cage/patch-cage.py
meson setup build --buildtype=release -Dman-pages=disabled
ninja -C build
cp build/cage /out/oblivion-cage
cp LICENSE oblivion.patch /out/
sha256sum /source/*dsc /source/*tar* > /out/cage-source.sha256
