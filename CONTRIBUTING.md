# Contributing to Advoid

Thanks for your interest in contributing! Advoid is a local DNS adblocker for macOS — a 742-line codebase spanning LLVM IR, Go, and Swift.

## Prerequisites

Building Advoid from source requires:

- **Go** 1.21+ — blocklist compiler
- **Swift** (Xcode or Command Line Tools) — menu bar UI
- **LLVM toolchain** (Homebrew): `brew install llvm` — `llc`, `llvm-link`
- **Clang** — linking the engine object file

Add Homebrew LLVM to your PATH before building:
```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
```

## Architecture

The project has three isolated components:

| Component | Language | File | Purpose |
|-----------|----------|------|---------|
| Blocklist Compiler | Go | `compile_blocklist.go` | Fetches StevenBlack/hosts, computes FNV-1a hashes, emits `blocklist.ll` |
| Packet Engine | LLVM IR | `advoid.ll` | Intercepts DNS on `127.0.0.1:53`, hashes QNAMEs, blocks or forwards |
| Menu Bar UI | Swift | `advoid-menu.swift` | macOS `NSStatusItem` app that toggles DNS and manages the daemon |

For a detailed walkthrough, read [ARCHITECTURE.md](ARCHITECTURE.md).

## Building

```bash
./install.sh
```

This generates the blocklist, compiles the engine, builds the Swift UI, and assembles the `.app` bundle into `/Applications/Advoid.app`.

## Running Tests

```bash
go test ./...
```

Engine-level integration tests use `dig` against the running daemon:
```bash
# After starting the engine:
dig @127.0.0.1 doubleclick.net    # Should return 0.0.0.0
dig @127.0.0.1 github.com         # Should forward normally
```

## Design Constraints

- **Zero heap allocations** on the hot path. The packet engine uses only stack memory (`alloca`) and pre-allocated global arrays.
- **No dynamic blocklist** at runtime. The blocklist is compiled in at build time as an LLVM `switch` statement.
- **Minimal dependencies.** The engine invokes only POSIX syscalls (`socket`, `bind`, `recvfrom`, `sendto`, `poll`).

## Commit Conventions

Commits should be self-contained and descriptive. No strict format enforced, but prefer imperative mood ("Add X" not "Added X").

## Questions?

Open a discussion or issue on GitHub.
