import Cocoa

/// AppDelegate manages the macOS Menu Bar lifecycle and zero-configuration installation.
/// It verifies the presence of the LLVM daemon and registers it dynamically via launchctl.
class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var statusItem: NSStatusItem!
    var statsBlockedItem: NSMenuItem!
    var statsForwardedItem: NSMenuItem!
    var statsUptimeItem: NSMenuItem!
    var statusItem_engine: NSMenuItem!

    // Paths owned by the engine. These live under /usr/local/var so an
    // unprivileged user cannot pre-create them or swap them for symlinks.
    let statsPath = "/usr/local/var/advoid/advoid.stats"
    let engineStatusPath = "/usr/local/var/advoid/advoid.status"
    let daemonPlistPath = "/Library/LaunchDaemons/com.advoid.daemon.plist"
    /// Root-owned, non-writable engine location created by install.sh.
    let engineInstallPath = "/usr/local/libexec/advoid-engine"

    // applicationDidFinishLaunching initializes the Menu Bar item and checks daemon status.
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        setupMenu()

        DispatchQueue.main.async {
            self.checkAndInstallDaemon()
            let initialStatus = self.getDNSStatus()
            self.updateIcon(isActive: initialStatus)
            // A fresh install leaves system DNS untouched, so Advoid is installed
            // but doing nothing until the user discovers the menu. Offer to activate
            // once the engine is confirmed healthy -- prompting rather than
            // silently redirecting every lookup on the machine.
            if !initialStatus && self.engineHealth() {
                self.promptToActivate()
            }
        }
    }

    /// promptToActivate asks before changing system DNS. Silently pointing every
    /// lookup at Advoid would be a surprise the user cannot undo without knowing
    /// where to look, so this is a dialog with Enable as the default action.
    func promptToActivate() {
        let alert = NSAlert()
        alert.messageText = "Turn on Adblock?"
        alert.informativeText = """
        Advoid is installed and its engine is running, but system DNS is not \
        pointing at it yet. Turning it on routes DNS through Advoid on this Mac. \
        You can turn it off again from this menu.
        """
        alert.addButton(withTitle: "Turn On")
        alert.addButton(withTitle: "Not Now")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            self.enable()
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
        statusItem_engine = NSMenuItem(title: "Engine: —", action: nil, keyEquivalent: "")
        statusItem_engine.isEnabled = false
        menu.addItem(statusItem_engine)
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
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            NSLog("Advoid: could not list network services: %@", error.localizedDescription)
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        if let output = String(data: data, encoding: .utf8) {
            // The first line is a header; services marked with '*' are disabled.
            return output.components(separatedBy: .newlines)
                .dropFirst()
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("*") }
        }
        return []
    }

    /// setDNSServers applies a DNS server list to the given services and returns the
    /// names of any service the change failed on. networksetup needs root, so a
    /// failure here previously went unnoticed while the UI still claimed success.
    func setDNSServers(_ servers: String, services: [String]) -> [String] {
        var failures: [String] = []
        for service in services {
            let task = Process()
            task.launchPath = "/usr/sbin/networksetup"
            task.arguments = ["-setdnsservers", service, servers]
            task.standardOutput = FileHandle.nullDevice
            task.standardError = FileHandle.nullDevice
            do {
                try task.run()
                task.waitUntilExit()
                if task.terminationStatus != 0 {
                    failures.append(service)
                }
            } catch {
                failures.append(service)
            }
        }
        return failures
    }

    // enable routes system DNS queries to the local loopback interface.
    @objc func enable() {
        // Refuse to point DNS at a port nothing is listening on: that is a total
        // outage. If the engine does not answer, tell the user instead.
        guard engineHealth() else {
            let alert = NSAlert()
            alert.messageText = "Advoid engine is not running"
            alert.informativeText = """
            The DNS engine is not responding, so enabling Advoid would break name \
            resolution. Check /Library/LaunchDaemons/com.advoid.daemon.plist and the \
            system log, then try again.
            """
            alert.alertStyle = .critical
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
            return
        }

        let services = getActiveNetworkServices()
        let failures = setDNSServers("127.0.0.1", services: services)
        if !failures.isEmpty {
            NSLog("Advoid: failed to set DNS on: %@", failures.joined(separator: ", "))
            let alert = NSAlert()
            alert.messageText = "Could not configure DNS"
            alert.informativeText = "macOS refused the change for: \(failures.joined(separator: ", ")). Advoid is not active."
            alert.alertStyle = .warning
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
        updateIcon(isActive: getDNSStatus())
    }

    // disable restores the system DNS configuration to DHCP defaults.
    @objc func disable() {
        _ = setDNSServers("empty", services: getActiveNetworkServices())
        updateIcon(isActive: false)
    }

    /// engineHealth reports whether the engine is actually serving DNS.
    ///
    /// This asks the engine directly rather than reading a state file: the engine
    /// runs as root and its private state directory is not readable by this app, so
    /// a file-based check reports "not running" even when everything is healthy.
    /// A well-formed DNS reply is proof the engine is bound and processing queries,
    /// which is exactly the condition that matters before pointing system DNS at it.
    func engineHealth() -> Bool {
        return dnsProbe(name: "example.com", qtype: 1)
    }

    /// dnsProbe sends one UDP DNS query to the local engine and reports whether a
    /// valid response comes back.
    func dnsProbe(name: String, qtype: UInt16, timeout: TimeInterval = 1.5) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        if fd < 0 { return false }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(53).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        // Minimal DNS query: 12-byte header, one question, qtype/qclass IN.
        var query = [UInt8]()
        func append16(_ v: UInt16) {
            query.append(UInt8(v >> 8))
            query.append(UInt8(v & 0xff))
        }
        append16(0x4AD0)          // transaction ID
        append16(0x0100)          // RD set
        append16(1)               // QDCOUNT
        append16(0)               // ANCOUNT
        append16(0)               // NSCOUNT
        append16(0)               // ARCOUNT
        let txidHi = query[0], txidLo = query[1]
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8)
            if bytes.count > 63 { return false }
            query.append(UInt8(bytes.count))
            query.append(contentsOf: bytes)
        }
        query.append(0)           // root label
        append16(qtype)
        append16(1)               // class IN

        let sent = query.withUnsafeBufferPointer { buf -> Int in
            withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, buf.baseAddress, buf.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if sent <= 0 { return false }

        var reply = [UInt8](repeating: 0, count: 512)
        let got = recv(fd, &reply, reply.count, 0)
        // A valid answer is at least a full header, echoes the transaction ID, and
        // has the QR bit set.
        guard got >= 12 else { return false }
        guard reply[0] == txidHi, reply[1] == txidLo else { return false }
        return (reply[2] & 0x80) != 0
    }

    /// engineStatusDetail returns the engine's self-reported startup status when it
    /// happens to be readable, for extra detail in the menu. Optional, never used to
    /// decide whether the engine is alive.
    func engineStatusDetail() -> String? {
        guard let content = try? String(contentsOfFile: engineStatusPath, encoding: .utf8) else {
            return nil
        }
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    // checkAndInstallDaemon verifies the existence of the launchd plist.
    func checkAndInstallDaemon() {
        if FileManager.default.fileExists(atPath: daemonPlistPath) {
            verifyEngineRunning()
            return
        }

        // Point at the root-owned copy, never at the app bundle. launchd runs
        // this as root; a bundle path is user-writable, so any process running as
        // the user could rewrite the daemon and have KeepAlive execute it as root.
        let enginePath = engineInstallPath
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

        // Write the plist to a directory only this user can write to, then move it
        // into place as root. A shared /tmp path could be pre-created by another
        // local user and swapped between write and copy.
        let stagingDir = NSTemporaryDirectory() + "advoid-\(getpid())"
        let tmpPlist = stagingDir + "/com.advoid.daemon.plist"
        do {
            try FileManager.default.createDirectory(atPath: stagingDir, withIntermediateDirectories: true)
            try plistContent.write(toFile: tmpPlist, atomically: true, encoding: .utf8)
        } catch {
            NSLog("Advoid: could not stage daemon plist: %@", error.localizedDescription)
            handleInstallError(description: error.localizedDescription)
            return
        }
        executePrivilegedInstall(tmpPath: tmpPlist, targetPath: daemonPlistPath)
        try? FileManager.default.removeItem(atPath: stagingDir)
    }

    /// verifyEngineRunning reports the engine's self-reported health in the menu so
    /// a bind failure is visible instead of silently breaking DNS.
    func verifyEngineRunning() {
        if engineHealth() {
            if let detail = engineStatusDetail(), detail != "ok" {
                statusItem_engine.title = "Engine: running (\(detail))"
            } else {
                statusItem_engine.title = "Engine: running"
            }
        } else {
            statusItem_engine.title = "Engine: NOT RESPONDING"
        }
    }

    // executePrivilegedInstall triggers the AppleScript root payload.
    func executePrivilegedInstall(tmpPath: String, targetPath: String) {
        // Quote both paths; NSTemporaryDirectory can contain spaces.
        let script = """
        do shell script "cp '\(tmpPath)' '\(targetPath)' && chown root:wheel '\(targetPath)' && chmod 644 '\(targetPath)' && (launchctl bootstrap system '\(targetPath)' || launchctl load -w '\(targetPath)')" with administrator privileges
        """

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

    // handleInstallError reports installation failure and terminates the app.
    func handleInstallError(description: String) {
        // Log to the system log rather than a world-writable file.
        NSLog("Advoid: engine installation failed: %@", description)
        let failAlert = NSAlert()
        failAlert.messageText = "Installation Failed"
        failAlert.informativeText = "Engine error: \(description)"
        failAlert.alertStyle = .critical
        NSApp.activate(ignoringOtherApps: true)
        failAlert.runModal()
        NSApplication.shared.terminate(nil)
    }

    // getDNSStatus reports whether every active service points at the local engine.
    // Checking only Wi-Fi reported the wrong state on Ethernet-only Macs.
    func getDNSStatus() -> Bool {
        let services = getActiveNetworkServices()
        if services.isEmpty { return false }
        var configured = 0
        for service in services {
            if dnsServers(for: service).contains("127.0.0.1") {
                configured += 1
            }
        }
        // Consider it active when at least one configured service uses the engine.
        return configured > 0
    }

    /// dnsServers returns the DNS servers configured for a network service.
    func dnsServers(for service: String) -> [String] {
        let task = Process()
        task.launchPath = "/usr/sbin/networksetup"
        task.arguments = ["-getdnsservers", service]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
        } catch {
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return output.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // menuWillOpen is called when the user clicks the menu bar icon.
    // We refresh stats just before the menu appears.
    func menuWillOpen(_ menu: NSMenu) {
        refreshStats()
    }

    // refreshStats reads the engine stats file and updates the menu items.
    func refreshStats() {
        verifyEngineRunning()
        // Stats live in the same private directory, so they may be unreadable.
        // Leave the placeholders in place rather than showing stale numbers.
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
