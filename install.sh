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

# The IR targets arm64-apple-macosx. Refuse to build on anything else rather than
# producing a binary that cannot run.
if [ "$(uname -m)" != "arm64" ]; then
    echo "Error: Advoid targets Apple Silicon (arm64) only; this machine is $(uname -m)."
    exit 1
fi

# Resolve a macOS SDK. clang's compiled-in default sysroot can reference an SDK
# that is not present (e.g. MacOSX26.sdk on a machine with only 15.x installed),
# which makes linking fail with "library 'System' not found".
SDK_PATH="$(xcrun --show-sdk-path 2>/dev/null || true)"
if [ -z "$SDK_PATH" ] || [ ! -d "$SDK_PATH" ]; then
    SDK_PATH="$(ls -d /Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk 2>/dev/null | sort -V | tail -1)"
fi
if [ -z "$SDK_PATH" ] || [ ! -d "$SDK_PATH" ]; then
    echo "Error: no macOS SDK found. Install Xcode or the Command Line Tools:"
    echo "       xcode-select --install"
    exit 1
fi
echo "Using SDK: $SDK_PATH"

# Confirm the toolchain can actually link a trivial program before doing the slow
# blocklist work, so failures surface in seconds rather than minutes.
echo 'int main(void){return 0;}' > /tmp/advoid_linkcheck.c
if ! clang -isysroot "$SDK_PATH" /tmp/advoid_linkcheck.c -o /tmp/advoid_linkcheck 2>/dev/null \
   && ! clang /tmp/advoid_linkcheck.c -o /tmp/advoid_linkcheck -L"$SDK_PATH/usr/lib" 2>/dev/null; then
    echo "Error: clang cannot link against $SDK_PATH."
    echo "       Try: sudo xcode-select --reset && xcode-select --install"
    rm -f /tmp/advoid_linkcheck.c
    exit 1
fi
rm -f /tmp/advoid_linkcheck.c /tmp/advoid_linkcheck

echo "Building Advoid..."

# 1. Restore DNS and cleanup legacy daemons to prevent dead internet routing
echo "Restoring network state and cleaning up daemons..."
networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' | while read -r service; do
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
    sudo chown root:wheel "$LOCAL_INSTALL_DIR"
    sudo chmod 755 "$LOCAL_INSTALL_DIR"
    sudo cp "$LOCAL_HASHES" "$LOCAL_INSTALL_DIR/local.hashes"
    sudo chown root:wheel "$LOCAL_INSTALL_DIR/local.hashes"
    sudo chmod 0644 "$LOCAL_INSTALL_DIR/local.hashes"
    echo "Installed local hashes to $LOCAL_INSTALL_DIR/local.hashes"
else
    echo "No local blocklist found ($LOCAL_TXT). Skipping."
fi

# 1.8 Create the engine state directory. Owned by root and not world-writable so
# no local user can pre-create the stats/status files or swap them for symlinks.
STATE_DIR="/usr/local/var/advoid"
# Root-owned engine location. launchd must not run anything the user can modify.
ENGINE_PATH="/usr/local/libexec/advoid-engine"
echo "Creating state directory $STATE_DIR..."
sudo mkdir -p "$STATE_DIR"
sudo chown root:wheel "$STATE_DIR"
# 0755 so the unprivileged menu bar app can read the engine's status and stats
# files. Both are written 0644 by the engine; neither contains query history.
sudo chmod 755 "$STATE_DIR"

# 2. Compile Engine (LLVM)
echo "Compiling LLVM core engine (advoid)..."
llvm-link advoid.ll blocklist.ll -S -o final.ll
llc -O2 final.ll -filetype=obj -o final.o -mtriple=arm64-apple-macosx14.0.0
link_engine() {
    if clang -isysroot "$SDK_PATH" final.o -o advoid-engine 2>/dev/null; then
        return 0
    fi
    echo "  (retrying link without sysroot, using the SDK stubs directly)"
    if clang final.o -o advoid-engine \
        -L"$SDK_PATH/usr/lib" -Wl,-platform_version,macos,14.0,14.0 2>/dev/null; then
        return 0
    fi
    # Last resort: /usr/lib always carries the shim, so an unsysrooted link works
    # as long as the linker does not insist on a missing SDK.
    clang final.o -o advoid-engine -Wl,-platform_version,macos,14.0,14.0
}
link_engine
if [ ! -x advoid-engine ]; then
    echo "Error: failed to link advoid-engine."
    echo "       SDK in use: $SDK_PATH"
    echo "       Try: sudo xcode-select --reset && xcode-select --install"
    exit 1
fi

# 3. Prepare App Bundle
echo "Structuring Advoid.app bundle..."
APP_DIR="Advoid.app"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Move the core engine into the bundle
mv advoid-engine "$APP_DIR/Contents/MacOS/advoid-engine"
chmod +x "$APP_DIR/Contents/MacOS/advoid-engine"

# The LaunchDaemon runs as root, so it must not execute a file inside the app
# bundle: that path is user-writable, which turns any process running as the user
# into persistent root via KeepAlive. Install the engine root-owned and
# non-writable, and point the plist at this path instead.
echo "Installing engine to $ENGINE_PATH (root-owned)..."
sudo mkdir -p "$(dirname "$ENGINE_PATH")"
sudo cp "$APP_DIR/Contents/MacOS/advoid-engine" "$ENGINE_PATH"
sudo chown root:wheel "$ENGINE_PATH"
sudo chmod 0555 "$ENGINE_PATH"

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

# Remove state files left behind by older builds that wrote to /tmp.
sudo rm -f /tmp/advoid.stats /tmp/advoid.status.txt /tmp/advoid-error.txt /tmp/advoid-script.txt

echo "Advoid installed to /Applications/Advoid.app!"
echo "Opening Advoid..."
open /Applications/Advoid.app
