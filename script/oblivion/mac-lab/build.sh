#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
out="${OBLIVION_LAB_APP:-$PWD/artifacts/oblivion-mac-lab/OblivionLab.app}"
mkdir -p "$out/Contents/MacOS"
xcrun swiftc -O -parse-as-library -target arm64-apple-macos15.0 -framework AppKit -framework Virtualization \
    script/oblivion/mac-lab/main.swift -o "$out/Contents/MacOS/OblivionLab"
cat > "$out/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.oblivion.mac-lab</string>
<key>CFBundleName</key><string>OblivionLab</string>
<key>CFBundleExecutable</key><string>OblivionLab</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
</dict></plist>
PLIST
codesign --force --sign - --entitlements script/oblivion/mac-lab/entitlements.plist "$out"
printf '%s\n' "$out"
