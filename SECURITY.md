# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Advoid intercepts all DNS traffic on your Mac. We take security seriously.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them via email to the project maintainer. You should receive a response within 48 hours. If the issue is confirmed, we will release a patch as soon as possible.

## Scope

Security-relevant areas of concern include:

- **DNS packet parsing** — malformed DNS queries that could crash or subvert the engine
- **Blocklist integrity** — poisoning of the upstream StevenBlack/hosts list
- **Daemon privilege escalation** — the engine runs as a system LaunchDaemon
- **DNS hijacking** — any mechanism that could redirect or leak DNS queries

## Expectations

- Provide a clear description of the vulnerability and steps to reproduce.
- Allow a reasonable window for a fix before public disclosure.
- We will credit you in the release notes (unless you prefer anonymity).
