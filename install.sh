#!/bin/bash
# install.sh acts as the primary build pipeline for Advoid.
# It delegates to the Go compiler for blocklist generation, invokes
# LLVM to construct the engine, and structures the final application bundle.
set -e

# Add Homebrew LLVM to PATH so the dependency check and compiler can find them
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

# Assert Dependencies
for cmd in go clang swiftc llc llvm-link; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed or not in PATH."
        exit 1
    fi
done

echo "Building Advoid..."

# 1. Restore DNS and cleanup legacy daemons to prevent dead internet routing
echo "Restoring network state and cleaning up daemons..."
networksetup -listallnetworkservices | grep -v '*' | tail -n +2 | while read -r service; do
    sudo networksetup -setdnsservers "$service" empty
done 2>/dev/null || true

sudo launchctl bootout system /Library/LaunchDaemons/com.machole.daemon.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.machole.daemon.plist
sudo rm -f /Library/LaunchDaemons/com.kevin.machole.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.advoid.daemon.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.advoid.daemon.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.machole.daemon.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.machole.daemon.plist

# 1. Generate Blocklist (Go)
echo "Generating blocklist.ll from StevenBlack list..."
go run compile_blocklist.go

# 1.5 Process local blocklist if present
LOCAL_TXT="blocklist.local.txt"
LOCAL_HASHES="blocklist.local.hashes"
LOCAL_INSTALL_DIR="/usr/local/etc/advoid"
if [ -f "$LOCAL_TXT" ]; then
    echo "Processing local blocklist from $LOCAL_TXT..."
    go run compile_blocklist.go -local "$LOCAL_TXT" -output "$LOCAL_HASHES"
    sudo mkdir -p "$LOCAL_INSTALL_DIR"
    sudo cp "$LOCAL_HASHES" "$LOCAL_INSTALL_DIR/local.hashes"
    echo "Installed local hashes to $LOCAL_INSTALL_DIR/local.hashes"
else
    echo "No local blocklist found ($LOCAL_TXT). Skipping."
fi

# 2. Compile Engine (LLVM)
echo "Compiling LLVM core engine (advoid)..."
llvm-link advoid.ll blocklist.ll -S -o final.ll
llc -O0 final.ll -filetype=obj -o final.o -mtriple=arm64-apple-macosx14.0.0
clang final.o -o advoid-engine

# 3. Prepare App Bundle
echo "Structuring Advoid.app bundle..."
APP_DIR="Advoid.app"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Move the core engine into the bundle
mv advoid-engine "$APP_DIR/Contents/MacOS/advoid-engine"
chmod +x "$APP_DIR/Contents/MacOS/advoid-engine"

# 4. Compile UI (Swift)
echo "Compiling Swift Menu Bar UI..."
swiftc advoid-menu.swift -o "$APP_DIR/Contents/MacOS/Advoid"

# 4.5 Generate Info.plist
cat <<EOF > "$APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Advoid</string>
    <key>CFBundleIdentifier</key>
    <string>com.advoid.menu</string>
    <key>CFBundleName</key>
    <string>Advoid</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF

# Move resources
if [ -f "advoid.png" ]; then
    cp advoid.png "$APP_DIR/Contents/Resources/advoid.png"
fi
if [ -f "AppIcon.icns" ]; then
    cp AppIcon.icns "$APP_DIR/Contents/Resources/AppIcon.icns"
fi

# 5. Move to Applications
echo "Installing to /Applications..."
rm -rf /Applications/Advoid.app
cp -R "$APP_DIR" /Applications/

echo "Advoid installed to /Applications/Advoid.app!"
echo "Opening Advoid..."
open /Applications/Advoid.app
