# <img src="advoid.png" width="32" height="32" alt="Advoid Mascot" style="vertical-align: middle; border-radius: 4px;" /> Advoid

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/bneb/advoid/actions/workflows/ci.yml/badge.svg)](https://github.com/bneb/advoid/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bneb/advoid?include_prereleases)](https://github.com/bneb/advoid/releases/latest)

Advoid is a local DNS adblocker for macOS. It resolves DNS queries directly from the loopback interface, blocking known ad and telemetry domains using a compiled LLVM IR matching engine.

> **Disclaimer:** Advoid intercepts all DNS traffic on your Mac and requires administrator privileges to install. If the engine crashes or is misconfigured, DNS resolution will fail and your internet will stop working. To recover: open the menu bar app and click **Disable**, or run `./uninstall.sh`. This is MIT-licensed software with no warranty. It works on my machine.

## System Requirements

- **Mac with Apple Silicon** (arm64). Intel Macs are not supported.
- **macOS 14 Sonoma or later.** May work on earlier versions but untested.
- **Administrator account** (required once, at install, to set up the launchd daemon).
- For the prebuilt app: nothing else.
- For building from source: Go, Swift, Clang, and Homebrew LLVM.

## Get Advoid

| Channel | Status | What you get |
|---------|--------|--------------|
| [GitHub Releases](https://github.com/bneb/advoid/releases) | Available after first tag | `Advoid.app` in a zip. Right-click → Open on first launch (app is not code-signed). |
| Homebrew Cask | [PR pending](homebrew/advoid.rb) | `brew install --cask advoid`. One command, auto-updates via `brew upgrade`. |
| Build from source | Always available | `git clone` + `./install.sh`. Full control, but needs dev tools. |
| Mac App Store | Not planned | Would require sandboxing and notarization — incompatible with DNS interception at the system level. |

To update the blocklist: either download a new release (the blocklist is compiled in at build time), or rebuild from source to pull the latest StevenBlack list.

## Architecture
- **Engine:** Written in LLVM IR (`advoid.ll`), processing UDP packets on port 53.
- **Blocklist Compiler:** A Go utility (`compile_blocklist.go`) that fetches the StevenBlack hosts list, filters it against a hardcoded system Safelist, and compiles it into an LLVM `switch` statement using an FNV-1a hash.
- **UI:** A macOS Menu Bar application written in Swift for toggling DNS state dynamically across all active system network interfaces.
- **Memory Model:** The engine operates without dynamic heap allocations during packet processing, using vectorized 64-bit register writes to mutate the stack buffer at wire-speed.

For a comprehensive technical deep-dive into the FNV-1a hashing logic and system daemonization, read the [Architecture Document](ARCHITECTURE.md).

For a line-by-line walkthrough of the LLVM IR packet engine — including socket setup, FNV-1a hashing, the 150,000-case switch statement, and in-place DNS packet mutation — read the **[Technical Deep Dive](TECHNICAL.md)**.

## How Advoid Compares

| | Advoid | Pi-hole | AdGuard Home | Browser Extension | NextDNS |
|---|---|---|---|---|---|
| **Scope** | System-wide DNS | Network-wide DNS | Network-wide DNS | Browser only | Cloud DNS |
| **Setup** | Menu bar app | Raspberry Pi / Docker | Docker / binary | Browser install | Change DNS setting |
| **Memory** | ~1.5 MB | ~100 MB | ~50 MB | Varies | N/A (cloud) |
| **Blocklist** | Compiled at build time | SQLite, auto-updating | Filter lists, auto-updating | Extension-managed | Cloud-managed |
| **Local-only** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❌ Third party sees all DNS |
| **Dashboard** | Menu bar toggle | Web UI | Web UI | Extension popup | Web dashboard |
| **Blocked latency** | Microseconds (in-place mutation) | Milliseconds (hash table lookup) | Milliseconds (filter traversal) | Milliseconds (JS interceptor) | Milliseconds (WAN RTT) |
| **Code size** | ~1,200 lines | ~50k+ lines | ~100k+ lines | Varies | Closed source |

Advoid's tradeoff: no dashboard, no auto-updates, no cache — in exchange for minimal code, flat memory, and a hot path you can step through in a debugger and fully understand.

For detailed measurements, see [BENCHMARKS.md](BENCHMARKS.md).

## State Management
When the app launches, it routes macOS DNS to `127.0.0.1`.
- **Enable:** Binds system DNS to the local engine.
- **Disable:** Restores the system to default DHCP DNS routing.

## Installation

### Download the app (once available)

Download `Advoid.app` from [GitHub Releases](https://github.com/bneb/advoid/releases), move it to `/Applications`, and open it. macOS will show a Gatekeeper warning — right-click the app and select Open, then confirm. On first launch, Advoid will ask for your admin password to install the background engine. After that, it runs automatically.

Homebrew coming soon: `brew install --cask advoid`

### Build from source

If you prefer to build it yourself, or want to customize the blocklist before installing:

```bash
git clone https://github.com/bneb/advoid.git
cd advoid
./install.sh
```

Requires Go, Swift/Xcode, Clang, and Homebrew LLVM (`brew install llvm`). The script compiles the engine, packages the `.app` bundle, and copies it to `/Applications`. On first launch, the app will prompt for your admin password to set up the launchd daemon.

### What the install actually does

1. Compiles the engine from LLVM IR and the menu bar app from Swift.
2. Copies `Advoid.app` to `/Applications`.
3. On first launch, the app creates a LaunchDaemon plist at `/Library/LaunchDaemons/com.advoid.daemon.plist` and loads it — this is the only step that needs your password.
4. The daemon starts listening on `127.0.0.1:53`. The app sets your network interfaces to use `127.0.0.1` as the DNS server.

To undo: run `./uninstall.sh` or click Disable in the menu bar, then drag the app to the Trash.

## Uninstallation

To gracefully teardown the daemon, restore DNS settings, and remove the binary:

```bash
./uninstall.sh
```

## Custom Blocklist

Add your own domains to block by creating `blocklist.local.txt` in the repo directory before building:

```
# blocklist.local.txt — one domain per line
ads.example.com
tracking.mysite.net
```

Rebuild to compile them into the engine:

```bash
./install.sh
```

The custom list is compiled alongside the StevenBlack hosts list at build time. For runtime loading, place a pre-computed hash file at `/usr/local/etc/advoid/local.hashes` — the engine reads it at startup. Generate it with:

```bash
go run compile_blocklist.go -local ~/.config/advoid/blocklist.txt -output blocklist.local.hashes
sudo mkdir -p /usr/local/etc/advoid
sudo cp blocklist.local.hashes /usr/local/etc/advoid/local.hashes
```

Then restart the daemon from the menu bar (Disable → Enable).

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

## Statistics

Click the menu bar icon to see live statistics:

- **Blocked** — queries sinkholed to `0.0.0.0`
- **Forwarded** — queries relayed upstream to Cloudflare
- **Uptime** — how long the daemon has been running

Counts are written to `/tmp/advoid.stats` every 128 queries by the engine. The menu bar app reads them when you open the menu.

## Sharp Edges

Things I'd fix if this were more than a personal project:

- **Build-time blocklist.** Updating the blocklist requires a full rebuild (`./install.sh`). Pi-hole updates automatically. I chose compile-time lookup over runtime convenience. The local hashes file feature partially addresses this for custom domains, but the main blocklist is still AOT.
- **No query caching.** Every allowed query is forwarded upstream, even if it was resolved 10 seconds ago. Pi-hole and AdGuard Home cache responses. Adding a small TTL cache would cut upstream latency for repeat queries, but it'd mean dynamic memory or a pre-allocated cache array, and I haven't gotten to it.
- **arm64 only.** The IR is tied to the Darwin/ARM64 syscall ABI and struct layouts (sin_len byte at offset 0, etc.). Porting to x86-64 means changing the datalayout, triple, and syscall conventions.
- **No IPv6.** The engine creates an IPv4 socket. IPv6 DNS queries won't be intercepted. Adding a second socket is straightforward but doubles the pollfd management.
- **Error handling is minimal.** If `@recvfrom` or `@sendto` fail, the engine doesn't notice. In practice this hasn't been a problem — DNS is UDP, packets get dropped sometimes, clients retry — but it's not robust.
- **No code signing for the binary.** macOS Gatekeeper will flag the unsigned binary. You'll need to right-click → Open on first launch. Proper notarization requires an Apple Developer account.
- **The custom blocklist path is hardcoded.** `/usr/local/etc/advoid/local.hashes` works on my machine but isn't configurable. Making it a command-line argument or config file would be better.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build prerequisites and architecture overview. Bug reports, patches, and benchmark numbers welcome. Read [SECURITY.md](SECURITY.md) for vulnerability reporting.

## FAQ

### Why LLVM IR instead of C or Rust?

I wanted to know exactly what instructions were running on every DNS query. C gives you the C abstract machine — the compiler is free to optimize within the standard, and you get what you get. Writing IR directly means every load, store, and branch is intentional. The blocklist-as-switch-statement thing started as a "what if" and turned out to work well — 150k domains compile to a single computed branch with no hash table overhead.

It's not the pragmatic choice. C would have been faster to write, Rust would have been safer. But for a personal project where the goal was understanding the full stack from syscall to response packet, IR was the right level of abstraction.

### Does it work on Intel Macs?

Currently arm64 (Apple Silicon) only. The LLVM IR targets `arm64-apple-macosx`. Intel support would require adjusting the target triple and datalayout. PRs welcome.

### How do I update the blocklist?

Rebuild from source with `./install.sh`. The Go compiler fetches the latest StevenBlack hosts list, re-hashes all domains, and regenerates the switch statement. A future release may add auto-updating with prebuilt binary releases.

### Will this slow down my internet?

No. DNS interception adds microseconds of latency per query — negligible compared to network round-trip time to the upstream resolver. DNS is not on the data path; your actual internet traffic (streaming, browsing, downloads) does not pass through Advoid. Only the initial domain lookup does.

### What about IPv6?

The current engine only creates an IPv4 socket. IPv6 DNS queries (over IPv6 transport) are not intercepted and will use your system's default DNS. Adding IPv6 support requires a second listening socket. This is a planned improvement.

### How is this different from editing /etc/hosts?

`/etc/hosts` blocks are static — you can't toggle them on/off without editing the file. Advoid gives you a menu bar toggle and forwards unblocked queries to Cloudflare instead of relying on your system resolver. It also compiles 150,000+ domains into an efficient lookup, which would be impractical in a flat hosts file.

### Does it auto-start on boot?

Yes. The engine is installed as a macOS LaunchDaemon (`com.advoid.daemon.plist`) with `RunAtLoad` and `KeepAlive` enabled. The menu bar app can be added to Login Items for the UI.

### Where are the logs?

There are none. Advoid does not log queries to disk to avoid I/O blocking and for privacy. Use `sudo tcpdump -i lo0 -n udp port 53` to inspect live DNS traffic.

## License

MIT — see [LICENSE](LICENSE) for details.

---

## How this was built

I used several AI models and tools when designing, writing, and testing this product. I wrote none of this completely independently. I did review all code.
