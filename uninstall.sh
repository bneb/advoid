#!/bin/bash
# uninstall.sh gracefully tears down Advoid and restores system defaults.
set -e

echo "Uninstalling Advoid..."

echo "1. Restoring default DNS settings..."
networksetup -setdnsservers Wi-Fi empty 2>/dev/null || true
networksetup -setdnsservers Ethernet empty 2>/dev/null || true

echo "2. Terminating UI application..."
killall Advoid 2>/dev/null || true

echo "3. Removing background daemon..."
if [ -f "/Library/LaunchDaemons/com.advoid.daemon.plist" ]; then
    sudo launchctl bootout system /Library/LaunchDaemons/com.advoid.daemon.plist 2>/dev/null || true
    sudo rm -f /Library/LaunchDaemons/com.advoid.daemon.plist
fi

echo "4. Removing Application bundle..."
sudo rm -rf /Applications/Advoid.app

echo "Advoid has been completely uninstalled."
