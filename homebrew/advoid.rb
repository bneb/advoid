cask "advoid" do
  version "1.0.0"
  sha256 :no_check

  url "https://github.com/bneb/advoid/releases/download/v#{version}/advoid.zip",
      verified: "github.com/bneb/advoid/"
  name "Advoid"
  desc "Local DNS adblocker for macOS with an LLVM IR packet engine"
  homepage "https://github.com/bneb/advoid"

  depends_on macos: ">= :sonoma"

  app "Advoid.app"

  # Advoid manages its own daemon installation and DNS configuration.
  # On uninstall, inform the user to run the uninstall script first.
  uninstall_postflight do
    system_command "/bin/launchctl",
                   args: ["bootout", "system", "/Library/LaunchDaemons/com.advoid.daemon.plist"],
                   sudo: true
  end

  zap trash: [
    "/Library/LaunchDaemons/com.advoid.daemon.plist",
    "~/Library/Preferences/com.advoid.menu.plist",
  ]

  livecheck do
    url :stable
    strategy :github_latest
  end
end
