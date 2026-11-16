#!/bin/zsh
# Builds iServer.app. With --install it is copied to ~/Applications and launched.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/iServer.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# Target the minimum macOS from Info.plist so the compiler flags APIs that need a newer system.
swiftc -O -target "$(uname -m)-apple-macos13.0" -o "$APP/Contents/MacOS/iServer" Sources/main.swift -framework AppKit -framework ServiceManagement -framework IOKit
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
