# Changelog

All notable changes to Advoid will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **TCP DNS service.** The engine now listens on TCP as well as UDP and relays TCP
  queries upstream. RFC 1035 §4.2.1 requires a client that receives a truncated
  (TC=1) answer to retry over TCP on the same port; previously nothing was
  listening, so those queries failed outright.
- Truncation signalling: when an upstream UDP answer exactly fills the 512-byte
  buffer it is almost certainly cut off, so the engine now sets the TC bit and lets
  the client retry over TCP instead of accepting a corrupt packet.
- Explicit startup failure handling. `socket()`, `bind()`, and `listen()` results
  are checked; a bind conflict logs the port, writes a failure status file, and
  exits non-zero rather than polling unbound sockets forever.
- `SO_REUSEADDR` on every socket so a daemon restart does not fail with
  `EADDRINUSE` while old TCP sockets linger in `TIME_WAIT`.
- Per-qtype sinkhole answers: blocked A queries return `0.0.0.0`, blocked AAAA
  queries return `::`, and every other qtype gets a NOERROR/NODATA response rather
  than a fabricated A record (RFC 3596 / RFC 9460).
- Engine health file at `/usr/local/var/advoid/advoid.status`, written at startup
  and surfaced in the menu bar as an "Engine:" row.
- Suffix-aware safelist in the blocklist compiler: an entry now protects the domain
  and all of its subdomains.
- Hash collision detection in the compiler. Two distinct domains mapping to one
  64-bit hash now fail the build instead of silently blocking the wrong name.
- Reproducible blocklist generation: `writeIR` emits cases in sorted order, and CI
  asserts that two consecutive runs produce identical output.
- Minimum-domain assertion in the compiler so a failed or restructured upstream
  fetch cannot silently produce a near-empty blocklist.
- `tests/engine_test.py` — behavioural regression suite covering answer types,
  NODATA, UDP and TCP forwarding, TC-bit propagation with TCP fallback, malformed
  input, and duplicate-instance bind failure. Wired into CI.
- Upstream fetch now rejects non-200 responses.

### Changed
- **Build now uses `llc -O2` instead of `-O0`.** At `-O0` LLVM compiles the
  generated switch into ~670k instructions of compare/branch chains and each
  lookup costs ~45 µs; at `-O2` it is ~12 ns. Behaviour is identical (verified over
  5,000 hashes); the cost is roughly a minute of build time.
- Engine scratch files moved from `/tmp` to `/usr/local/var/advoid`, created
  `root:wheel` mode 0700 by `install.sh`, so an unprivileged user cannot
  pre-create them or swap them for symlinks. `uninstall.sh` removes the directory.
- Menu bar app reports the engine's real health, checks `networksetup` exit codes
  instead of assuming success, and evaluates DNS state across all active network
  services rather than only Wi-Fi.
- `sinkhole` returns the length of the reply it built, so the UDP and TCP send
  paths send the full message rather than the query-length prefix.
- Documentation updated with measured numbers: blocklist size, binary size, and
  engine hot-path latency at `-O0` versus `-O2`.

### Security and robustness
This pass reviewed the TCP implementation added in this release as an adversary
would, and found several defects, including two I introduced. All are fixed except
the one noted as a blocker below.

Fixed in the engine:
- **Out-of-bounds write in the sinkhole answer.** `write_answer` wrote 16 bytes of
  RDATA unconditionally, so an A record placed near the end of the 512-byte packet
  buffer wrote up to 12 bytes past it. The bound check now uses the real record
  size (12 + address length) and the second 8-byte store is AAAA-only.
- **Out-of-bounds write in DNS-over-TCP framing.** A 16-bit length prefix can be
  65535, and framing adds 2 more bytes, so a maximum-length message could write one
  byte past the buffer. Messages above 65534 are now rejected.
- **Blocking-read denial of service.** The accepted TCP socket had no receive
  timeout, so a client that connected and stalled froze every query indefinitely.
  Both client and upstream sockets now carry a 5s `SO_RCVTIMEO`/`SO_SNDTIMEO`.
- **Blocking `connect()` denial of service.** `SO_SNDTIMEO` does not bound
  `connect()` on Darwin — verified: a connect to an unroutable address with a 2s
  timeout never returned. Because DNS is handled inline, an unreachable upstream
  hung the resolver. The connect is now non-blocking with a `poll()`-bounded wait.
- **Non-blocking socket never restored.** When `connect()` succeeded immediately the
  code skipped the restore, leaving the socket non-blocking so `recv()` returned
  EAGAIN and a large upstream answer was misread as a short read. Verified in C:
  the restore is what makes a 1015-byte reply arrive instead of EAGAIN.
- **`getsockopt` called with the wrong ABI.** Its final argument is a `socklen_t*`,
  not a `socklen_t`; passing the integer `4` made it write to address 0x4. Confirmed
  against the SDK headers, which also confirmed `setsockopt`/`sendto`/`bind` do
  take a `socklen_t` value.
- **Wrong `SO_RCVTIMEO` constant.** Used `0x1004`; the SDK value is `0x1006`. The
  wrong constant would have made the timeout a silent no-op. All socket, fcntl and
  poll constants are now verified against the SDK rather than from memory.

### TCP relay: fixed
The "relays only after two prior upstream queries" bug had a single-line cause in
`set_io_timeout`:

```llvm
%o8 = getelementptr inbounds [16 x i8], ptr %tv, i64 8   ; == %tv + 128
```

The index scales by the element type, so `tv_usec` was written 128 bytes past the
`struct timeval` — into the caller's stack frame. Depending on how much traffic had
already been served, that landed on the upstream sockaddr (so queries never left
the machine) or on a `pollfd` entry (so replies were not noticed until some
unrelated packet woke `poll()`). Two prior queries simply shifted the corruption
onto the UDP listener's entry, leaving the upstream path intact — which is exactly
the "works after two queries" symptom. The same bug meant the 5 s socket timeouts
were being configured from stale stack bytes, so they were not reliably in effect.

Correct form is `getelementptr inbounds [16 x i8], ptr %tv, i64 0, i64 8`. With
that one line, a TCP relay works as the very first query on a fresh engine, and
the behaviour suite goes from 23/27 to 31/32.

The upstream leg remains UDP from a 4096-byte buffer, so answers larger than 4096
bytes are still not retrievable: such a client receives the upstream's truncated
answer with TC set rather than a corrupt one. That is the one remaining suite
failure and it is a real limitation, not a crash.

A second fix in the same area: `%c_addr_tmp` was allocated inside the relay block,
so the stack grew 16 bytes for every relayed reply in a process that never
returns. It is now allocated once in `main`'s entry block.

### Security
Findings from an adversarial review pass. Each was verified against the running
system before and after the fix.

- **Blocklist was bypassed by one uppercase letter.** `hash_qname` hashed the raw
  wire bytes while the compiler hashed the lowercase list entries, so
  `doubleclick.net` was blocked and `DoubLeClick.net` was forwarded. The hash
  loop now folds A-Z to a-z branchlessly, and the compiler lowercases before
  hashing. A regression test covers mixed-case queries.
- **The daemon listened on every interface.** `sin_addr` was left zeroed, i.e.
  `INADDR_ANY`, which makes the Mac an open resolver for every network it joins
  and is a DNS amplification target. Both listeners now bind `127.0.0.1`
  explicitly, which is what the documentation already claimed.
- **The root daemon executed a user-writable binary.** The LaunchDaemon pointed
  at `Advoid.app/Contents/MacOS/advoid-engine`, which is owned by the invoking
  user, so any process running as that user could rewrite the root daemon and
  have `KeepAlive` execute it. The engine is now installed to
  `/usr/local/libexec/advoid-engine`, root:wheel mode 0555, and the plist points
  only there.
- **The resolver was killed by SIGPIPE.** Writing a relayed answer to a TCP
  client that had already disconnected raised SIGPIPE and terminated the root
  daemon, so one client giving up took name resolution down for every app.
  `SO_NOSIGPIPE` is now set on accepted sockets.
- **`uninstall.sh` and `install.sh` skipped the first network service.** The
  filter `grep -v '*' | tail -n +2` removed the header — which itself contains an
  asterisk — and then dropped the first real service, so DNS could be left
  pointing at an engine that had just been deleted. The pipeline now strips the
  header first and filters disabled entries.
- **The test suite could not actually run.** `@local_port` was a single byte, so
  only ports 0-255 were expressible and all of them are privileged; CI's
  unprivileged run could never bind and therefore never tested the engine. The
  port is now a full 16-bit value written big-endian, and CI runs on 5333.
- `/usr/local/etc/advoid` (which supplies hashes the root daemon enforces) is now
  created root-owned with explicit modes instead of relying on `sudo cp`.

### Fixed
- Answers larger than 4096 bytes were unreachable. When forwarding a query that
  arrived over TCP, the engine let the upstream impose the 512-byte UDP limit, so
  the client's RFC 1035 4.2.1 TCP retry returned the same truncated answer it had
  just been told to fetch again. The engine now appends an OPT record advertising
  its own 4096-byte buffer when forwarding a TCP query that carries none, and the
  upstream returns the complete answer in one datagram. Verified against Cloudflare:
  a query with `OPT(4096)` returns 1028 bytes with TC clear.
- The menu bar app reported "Advoid engine is not running" on a perfectly healthy
  install. The health check read a status file inside a root-owned `0700`
  directory, which the unprivileged app cannot open, so it always concluded the
  engine was down and refused to enable. The check now probes the engine with a
  real DNS query over `127.0.0.1:53` and treats a well-formed reply as healthy; the
  status file is a supplementary detail only. It is now written `0644` (via
  `fchmod`, so umask cannot change it) and the state directory is `0755`.
- `install.sh` failed to link on machines whose clang has a stale default sysroot.
  A Homebrew clang 22 on macOS 15 looks for `MacOSX26.sdk`, which does not exist,
  producing `ld: library 'System' not found`. The script now resolves the SDK via
  `xcrun --show-sdk-path` (falling back to the newest installed
  `MacOSX*.sdk`), verifies it can link a trivial program *before* the slow
  blocklist and `llc` steps, and retries the engine link against the SDK's stubs.
- `install.sh` now refuses to build on non-arm64 hosts instead of installing a
  binary that cannot run.
- `recvfrom` and `sendto` error returns were ignored. A `-1` from `recvfrom` was
  treated as an enormous length, so the QNAME scan read past the packet buffer.
- `isSafelisted` only matched exact domains, so `securemetrics.apple.com` was
  blocked despite `apple.com` being safelisted.
- DNS answer records were emitted with fields written in host byte order for some
  paths; multi-byte fields now use explicit big-endian stores.
- The menu bar app wrote the daemon plist to a shared `/tmp` path that another
  local user could pre-create, and wrote error text to `/tmp` as well.
- Test and CI paths no longer claim `~150,000` domains; the generated count is
  whatever StevenBlack currently serves.

## [1.0.0] - 2025-06-18

### Added
- Initial public release.
- LLVM IR packet engine (`advoid.ll`) with zero-allocation DNS interception on `127.0.0.1:53`.
- AOT blocklist compiler in Go, sourcing domains from StevenBlack/hosts and emitting a compiled LLVM `switch` statement via FNV-1a hashing.
- Native macOS menu bar application in Swift with Enable/Disable DNS toggling.
- `launchd` daemonization with self-installing plist.
- `install.sh` and `uninstall.sh` scripts for build-from-source and teardown.
- Safelist for critical infrastructure domains (localhost, github.com, apple.com, icloud.com).
- Upstream DNS forwarding to Cloudflare (`1.1.1.1`) for non-blocked queries.
- Custom blocklist support: `blocklist.local.txt` for AOT-compiled custom domains.
- Runtime local hashes loading: engine reads `/usr/local/etc/advoid/local.hashes` at startup via `@load_local_hashes`.
- `compile_blocklist.go -local` mode for converting text blocklists to binary hashes.
- LLVM IR functions `@load_local_hashes` and `@check_local` for runtime custom blocklist checking.
- MIT license.
- CI workflow (`.github/workflows/ci.yml`) with build, Go tests, and DNS smoke tests.
- Release workflow (`.github/workflows/release.yml`) for tagged GitHub Releases.
- Community docs: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- `TECHNICAL.md` — line-by-line LLVM IR engine deep dive.
- `BENCHMARKS.md` — reproducible benchmark methodology.
- README comparison table, badges, and Homebrew install instructions.
- `homebrew/advoid.rb` cask formula.


[1.0.0]: https://github.com/bneb/advoid/releases/tag/v1.0.0
[Unreleased]: https://github.com/bneb/advoid/compare/v1.0.0...HEAD
