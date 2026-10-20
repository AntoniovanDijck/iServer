#!/bin/zsh
# Builds iServer.app. With --install it is copied to ~/Applications and launched.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/iServer.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -o "$APP/Contents/MacOS/iServer" Sources/main.swift -framework AppKit -framework ServiceManagement
cp Info.plist "$APP/Contents/"
cp Resources/AppIcon.icns "$APP/Contents/Resources/"
codesign --force --sign - "$APP"
echo "Built $APP"

if [[ "${1:-}" == "--install" ]]; then
  pkill -x iServer 2>/dev/null || true
  mkdir -p ~/Applications
  rm -rf ~/Applications/iServer.app
  cp -R "$APP" ~/Applications/
  open ~/Applications/iServer.app
  echo "Installed and launched ~/Applications/iServer.app"
fi
