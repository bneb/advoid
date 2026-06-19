import Cocoa

/// AppDelegate manages the macOS Menu Bar lifecycle and zero-configuration installation.
/// It verifies the presence of the LLVM daemon and registers it dynamically via launchctl.
class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var statusItem: NSStatusItem!
    var statsBlockedItem: NSMenuItem!
    var statsForwardedItem: NSMenuItem!
    var statsUptimeItem: NSMenuItem!

    // applicationDidFinishLaunching initializes the Menu Bar item and checks daemon status.
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        setupMenu()
        
        DispatchQueue.main.async {
            self.checkAndInstallDaemon()
            let initialStatus = self.getDNSStatus()
            self.updateIcon(isActive: initialStatus)
        }
    }

    // setupMenu configures the status item length and attaches the dropdown menu.
    func setupMenu() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        menu.addItem(NSMenuItem(title: "Enable Adblock", action: #selector(enable), keyEquivalent: "e"))
        menu.addItem(NSMenuItem(title: "Disable Adblock", action: #selector(disable), keyEquivalent: "d"))
        menu.addItem(NSMenuItem.separator())
        statsBlockedItem = NSMenuItem(title: "Blocked: —", action: nil, keyEquivalent: "")
        statsBlockedItem.isEnabled = false
        menu.addItem(statsBlockedItem)
        statsForwardedItem = NSMenuItem(title: "Forwarded: —", action: nil, keyEquivalent: "")
        statsForwardedItem.isEnabled = false
        menu.addItem(statsForwardedItem)
        statsUptimeItem = NSMenuItem(title: "Uptime: —", action: nil, keyEquivalent: "")
        statsUptimeItem.isEnabled = false
        menu.addItem(statsUptimeItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))

        statusItem.menu = menu
    }

    // updateIcon modifies the status item and menu based on the active state.
    func updateIcon(isActive: Bool) {
        updateMenuStates(isActive: isActive)
        
        guard let button = statusItem.button else { return }
        
        if let imagePath = Bundle.main.path(forResource: "advoid", ofType: "png"),
           let image = NSImage(contentsOfFile: imagePath) {
            image.size = NSSize(width: 18, height: 18)
            image.isTemplate = true
            button.image = image
            button.title = ""
            button.alphaValue = isActive ? 1.0 : 0.4
        } else {
            button.title = isActive ? "🛡️ (ON)" : "🛡️ (OFF)"
        }
    }
    
    // updateMenuStates toggles the checkmarks and interactability.
    func updateMenuStates(isActive: Bool) {
        guard let menu = statusItem.menu else { return }
        let enableItem = menu.item(withTitle: "Enable Adblock")
        let disableItem = menu.item(withTitle: "Disable Adblock")
        
        enableItem?.state = isActive ? .on : .off
        disableItem?.state = isActive ? .off : .on
        
        enableItem?.isEnabled = !isActive
        disableItem?.isEnabled = isActive
    }

    // getActiveNetworkServices queries the system for active network interfaces to configure.
    func getActiveNetworkServices() -> [String] {
        let process = Process()
        process.launchPath = "/usr/sbin/networksetup"
        process.arguments = ["-listallnetworkservices"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.launch()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let output = String(data: data, encoding: .utf8) {
            return output.components(separatedBy: .newlines).filter { !$0.isEmpty && !$0.contains("*") }
        }
        return []
    }

    // enable routes system DNS queries to the local loopback interface.
    @objc func enable() {
        for service in getActiveNetworkServices() {
            let task = Process()
            task.launchPath = "/usr/sbin/networksetup"
            task.arguments = ["-setdnsservers", service, "127.0.0.1"]
            task.launch()
        }
        updateIcon(isActive: true)
    }

    // disable restores the system DNS configuration to DHCP defaults.
    @objc func disable() {
        for service in getActiveNetworkServices() {
            let task = Process()
            task.launchPath = "/usr/sbin/networksetup"
            task.arguments = ["-setdnsservers", service, "empty"]
            task.launch()
        }
        updateIcon(isActive: false)
    }

    // checkAndInstallDaemon verifies the existence of the launchd plist.
    func checkAndInstallDaemon() {
        let plistPath = "/Library/LaunchDaemons/com.advoid.daemon.plist"
        if FileManager.default.fileExists(atPath: plistPath) { return }
        
        let enginePath = Bundle.main.bundlePath + "/Contents/MacOS/advoid-engine"
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>com.advoid.daemon</string>
            <key>ProgramArguments</key>
            <array><string>\(enginePath)</string></array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
        </dict>
        </plist>
        """
        
        let tmpPlist = NSTemporaryDirectory() + "com.advoid.daemon.plist"
        try? plistContent.write(toFile: tmpPlist, atomically: true, encoding: .utf8)
        executePrivilegedInstall(tmpPath: tmpPlist, targetPath: plistPath)
    }
    
    // executePrivilegedInstall triggers the AppleScript root payload.
    func executePrivilegedInstall(tmpPath: String, targetPath: String) {
        let script = """
        do shell script "cp \(tmpPath) \(targetPath) && chown root:wheel \(targetPath) && launchctl bootstrap system \(targetPath) || launchctl load -w \(targetPath)" with administrator privileges
        """
        try? script.write(toFile: "/tmp/advoid-script.txt", atomically: true, encoding: .utf8)
        
        let alert = NSAlert()
        alert.messageText = "Advoid Engine Setup"
        alert.informativeText = "Advoid needs to install its core engine. You will be prompted for your password."
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        
        if let errorDescription = runAppleScript(script: script) {
            handleInstallError(description: errorDescription)
        }
    }
    
    // runAppleScript safely executes an AppleScript payload and returns an error description if it fails.
    func runAppleScript(script: String) -> String? {
        guard let appleScript = NSAppleScript(source: script) else { return "Failed to compile AppleScript" }
        var error: NSDictionary?
        let _ = appleScript.executeAndReturnError(&error)
        return error?.description
    }

    // handleInstallError displays a critical alert when installation fails and terminates the app.
    func handleInstallError(description: String) {
        let errStr = "Engine error: \(description)"
        try? errStr.write(toFile: "/tmp/advoid-error.txt", atomically: true, encoding: .utf8)
        let failAlert = NSAlert()
        failAlert.messageText = "Installation Failed"
        failAlert.informativeText = errStr
        failAlert.alertStyle = .critical
        NSApp.activate(ignoringOtherApps: true)
        failAlert.runModal()
        NSApplication.shared.terminate(nil)
    }
    
    // getDNSStatus parses the networksetup output to determine if DNS is bound locally.
    func getDNSStatus() -> Bool {
        let task = Process()
        task.launchPath = "/usr/sbin/networksetup"
        task.arguments = ["-getdnsservers", "Wi-Fi"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let output = String(data: data, encoding: .utf8) {
            return output.contains("127.0.0.1")
        }
        return false
    }

    // menuWillOpen is called when the user clicks the menu bar icon.
    // We refresh stats just before the menu appears.
    func menuWillOpen(_ menu: NSMenu) {
        refreshStats()
    }

    // refreshStats reads /tmp/advoid.stats and updates the menu items.
    func refreshStats() {
        let statsPath = "/tmp/advoid.stats"
        guard let content = try? String(contentsOfFile: statsPath, encoding: .utf8) else { return }
        let lines = content.components(separatedBy: .newlines).filter { !$0.isEmpty }
        guard lines.count >= 3 else { return }

        if let blocked = Int64(lines[0]) {
            statsBlockedItem.title = "Blocked: \(formatCount(blocked))"
        }
        if let forwarded = Int64(lines[1]) {
            statsForwardedItem.title = "Forwarded: \(formatCount(forwarded))"
        }
        if let uptime = Int64(lines[2]) {
            statsUptimeItem.title = "Uptime: \(formatUptime(uptime))"
        }
    }

    // formatCount formats a large integer with locale-aware grouping (e.g., 1,234,567).
    func formatCount(_ count: Int64) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        return formatter.string(from: NSNumber(value: count)) ?? "\(count)"
    }

    // formatUptime converts seconds to a human-readable duration.
    func formatUptime(_ seconds: Int64) -> String {
        if seconds < 60 { return "\(seconds)s" }
        if seconds < 3600 { return "\(seconds / 60)m \(seconds % 60)s" }
        let h = seconds / 3600
        let m = (seconds % 3600) / 60
        return "\(h)h \(m)m"
    }

    // applicationWillTerminate ensures DNS is restored if the app is force quit or OS shuts down.
    func applicationWillTerminate(_ notification: Notification) {
        disable()
    }

    // quit safely terminates the UI application and restores default DNS settings.
    @objc func quit() {
        disable()
        NSApplication.shared.terminate(self)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
