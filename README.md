# <img src="advoid.png" width="32" height="32" alt="Advoid Mascot" style="vertical-align: middle; border-radius: 4px;" /> Advoid

Advoid is a local DNS adblocker for macOS. It resolves DNS queries directly from the loopback interface, blocking known ad and telemetry domains using a compiled LLVM IR matching engine.

## Architecture
- **Engine:** Written in LLVM IR (`advoid.ll`), processing UDP packets on port 53.
- **Blocklist Compiler:** A Go utility (`compile_blocklist.go`) that fetches the StevenBlack hosts list, filters it against a hardcoded system Safelist, and compiles it into an LLVM `switch` statement using an FNV-1a hash.
- **UI:** A macOS Menu Bar application written in Swift for toggling DNS state dynamically across all active system network interfaces.
- **Memory Model:** The engine operates without dynamic heap allocations during packet processing, using vectorized 64-bit register writes to mutate the stack buffer at wire-speed.

For a comprehensive technical deep-dive into the FNV-1a hashing logic and system daemonization, read the [Architecture Document](ARCHITECTURE.md).

## State Management
When the app launches, it routes macOS DNS to `127.0.0.1`.
- **Enable:** Binds system DNS to the local engine.
- **Disable:** Restores the system to default DHCP DNS routing.

## Installation

The installer script compiles the engine and UI, and packages them into `/Applications/Advoid.app`.

```bash
git clone https://github.com/bneb/advoid.git
cd advoid
./install.sh
```

Upon first launch, Advoid will prompt for administrator privileges to bootstrap the `launchd` background engine.

## Uninstallation

To gracefully teardown the daemon, restore DNS settings, and remove the binary:

```bash
./uninstall.sh
```

## State Constraints
Advoid strictly manages its lifecycle to prevent routing DNS to a dead port:
1. **Startup:** The UI verifies the `launchd` engine's presence. If installation fails, the UI terminates.
2. **Termination:** Quitting the application unbinds DNS from localhost.
3. **Reinstallation:** The `install.sh` script restores DNS to DHCP before clearing legacy daemons to maintain connectivity during the build.

## Debugging

Advoid does not log blocked domains to disk to avoid I/O blocking. To trace DNS requests, use macOS packet tracing:

```bash
sudo tcpdump -i lo0 -n udp port 53
```
