#!/bin/zsh
# Renders the icon with the Metal shader and packs it into Resources/AppIcon.icns.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
ICONSET="$TMP/AppIcon.iconset"
mkdir -p "$ICONSET" Resources docs

swift scripts/IconShader.swift "$TMP/icon_1024.png" 1024
for s in 16 32 128 256 512; do
  sips -z $s $s "$TMP/icon_1024.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z $((s * 2)) $((s * 2)) "$TMP/icon_1024.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o Resources/AppIcon.icns
sips -z 512 512 "$TMP/icon_1024.png" --out docs/icon.png >/dev/null
rm -rf "$TMP"
echo "Wrote Resources/AppIcon.icns and docs/icon.png"
