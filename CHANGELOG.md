# Changelog

All notable changes to Advoid will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[1.0.0]: https://github.com/bneb/advoid/releases/tag/v1.0.0
[Unreleased]: https://github.com/bneb/advoid/compare/v1.0.0...HEAD
