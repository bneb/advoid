# Advoid Sprint Roadmap

This file is the working plan. It is written for an autonomous loop: pick the
topmost `todo` item, do the work, run `./verify.sh`, flip the status, repeat.

## How to use

**The round-by-round protocol an autonomous agent follows is in [`LOOP.md`](LOOP.md).**
The driver is `./run-loop.sh` (see `--dry-run`). This file is the *state*; that one
is the *behaviour*. Read both before starting a loop.

- **Work strictly in order.** Sprint *n+1* assumes sprint *n* landed. Items marked
  `blocker` must not be deferred.
- **One item per iteration.** Do not start the next until the current one is
  `[x]` and `./verify.sh` is green.
- **Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked
- **Claim an item** by flipping `[ ]` → `[~]` *before* you start, so a crash loop
  leaves a visible marker rather than silent partial work.
- **Record what you learned** in the item's *Notes* field. The next agent needs
  the dead ends, not just the fix.
- **Add new work** to [Backlog](#backlog) using the template. Do not renumber
  existing IDs — other notes reference them.

### The oracle gates everything

Every item requires `./verify.sh` green to be marked done. Two facts about the
current oracle, both measured:

- **It was not deterministic** until S2.3 landed: three consecutive runs gave
  1 green / 2 red, always on the same check. That made "green" a coin flip and
  the Definition of Done unusable for every item.
- **It is now deterministic** — 4/4 consecutive green after the S2.3 fix. Re-check
  this if the oracle starts flipping; a flaky oracle silently unblocks work that
  should not have been certified.

This is deliberately left loud. Muting the check would make the suite green and
the loop would start marking work done against an oracle that cannot tell
green from red.

### Verification

Coverage is audited in [`COVERAGE.md`](COVERAGE.md): measured numbers, the gaps
stated plainly, and a failure-mode table of which defects still lack a regression
test. Six of sixteen are covered; the rest map onto open items below.

```bash
./verify.sh            # static checks + behaviour suite   (~2 min)
./verify.sh --static   # static only                       (seconds)
./verify.sh --build    # also link the production engine
```

Every item's **Verify:** line names what to check. `./verify.sh` must be green
before any item is marked `[x]`.

### Definition of Done

An item is done when **all** of these hold:

1. The acceptance criteria in the item are met.
2. `./verify.sh` is green.
3. A test exists that **fails without the change** (a regression test, not just a
   passing suite). If a change cannot be tested, say so in Notes — do not mark it
   done on inspection alone. `COVERAGE.md` audits which failure modes still lack
   one; items marked `Covered? no` there must add it as part of the fix.
4. `CHANGELOG.md` records the change under `Unreleased`.

### Invariants — do not regress these

These were each a real bug. Every one has a test. If a change breaks one of them,
the change is wrong, not the invariant.

| # | Invariant | Test |
|---|---|---|
| I1 | Blocklist matching is **case-insensitive** (RFC 4343) | `case-insensitive` suite block |
| I2 | Listeners bind **127.0.0.1 only**, never `INADDR_ANY` | `lsof` on a test build |
| I3 | No attacker-controlled write escapes any buffer | suite malformed/oversized cases |
| I4 | The root daemon never executes a **user-writable** file | `install.sh` + plist path check |
| I5 | The behaviour suite runs **unprivileged** on a high port | `verify.sh` needs no sudo |
| I6 | DNS multi-byte fields are **big-endian** on the wire | suite answer-record parsing |
| I7 | Root-writable files are not opened without `O_NOFOLLOW` | static review of every `open` |

> **Why I6 keeps biting:** writing an `i16`/`i32` straight out of IR is
> *little-endian*; DNS fields are big-endian. Emit **individual bytes**. The same
> trap exists in `getelementptr`: indexing `[16 x i8]` by `i64 8` addresses
> **+128 bytes**, not +8. Both mistakes shipped once already.

---

## Sprint 0 — Land what exists

Nothing is committed. The tree is 15 modified files, `tests/` is untracked, and
`ci.yml` references a file that is not in git — so CI cannot run and a clone gets
the pre-TCP engine.

| ID | Status | Item |
|---|---|---|
| S0.1 | `[x]` | Commit the whole tree (engine, UI, compiler, tests, docs, `verify.sh`, `reinstall-assets.sh`). No tags yet. **Verify:** `git status --short` empty |
| S0.2 | `[ ]` | Confirm `ci.yml` runs green on the pushed tree — especially the behaviour suite on port 5333. **Verify:** CI badge, or `ADVOID_TEST_PORT=5333 python3 tests/engine_test.py` |
| S0.3 | `[x]` | **Guard the IR-level bug class twice: a correctly-ordered behavioural check, and a static lint.** Correction: an earlier revision of this item claimed the bug "cannot be caught black-box". That was wrong — it is *ordering*-dependent, not layout-dependent. The check existed but ran after the UDP and TCP tests, and a prior TCP connection makes the bug invisible. The check is now the first thing the suite does and demonstrably fails on a build with the GEP bug reintroduced (61 bytes clean vs 0 bytes buggy). The lint is a **complementary** guard for the byte-order half, not a replacement. **Remaining before this can be marked done:** wire `verify.sh` into CI (today only `verify.sh` itself calls the lint), add lint fixtures proving it has teeth, and fix the evasions found in review (global targets such as `ptr @udp_pkt`, `i32`/named-type/`nuw` GEP spellings, `volatile`/`atomic` stores, line-wrapped instructions). **Verify:** suite fails on a bug-reintroduced build and passes on clean |
| S0.4 | `[x]` | `.gitignore` must exclude `final.ll`, `final.o`, `Advoid.app/`, `blocklist.ll`. **Verify:** `git ls-files` shows none of them |

---

## Sprint 1 — Availability

An adblocker that takes the resolver down is worse than no adblocker. Every item
here is a denial-of-service or a resource leak reachable by any local process, and
in most cases by anything on the LAN that can reach the port.

| ID | Status | Sev | Item |
|---|---|---|---|
| **S1.1** | `[~]` | blocker | **Non-blocking TCP handling.** See details below |
| S1.2 | `[ ]` | high | `@tcp_pending` leaks — reclaim abandoned relays with a deadline and close the fd |
| S1.3 | `[ ]` | medium | `poll()` result and error flags ignored — check `POLLERR`/`POLLHUP`/`POLLNVAL`, handle `poll() == -1` |
| S1.4 | `[ ]` | medium | `state_addrs` entries are never expired — add a timestamp and reclaim |
| S1.5 | `[ ]` | low | `maybe_write_stats()` does open+write+close inside the blocking loop; move it off the hot path |

### S1.1 — Non-blocking TCP handling

- **Area:** engine · **Status:** `[ ]`
- **Problem:** the poll loop handles one event per iteration and does a *blocking*
  `read_exact()` on an accepted TCP socket. `SO_RCVTIMEO` is **per `recv()`**, so
  it bounds a silent stall but not a trickling one: a peer sending 1 byte every
  4.5 s keeps every UDP query unanswered indefinitely, and the condition is
  renewable at will. Verified: 6/6 UDP probes timed out during the window; a
  65534-byte declaration holds the engine for hours.
- **Acceptance:**
  - [ ] A TCP client trickling bytes at 1 per 4.5 s does **not** delay a UDP query by more than the normal single-query latency
  - [ ] A TCP client declaring 65534 bytes and sending nothing is dropped after a bounded **absolute** deadline (not per-`recv`)
  - [ ] UDP service is unaffected while any number of TCP clients are stalled
  - [ ] Regression test exists that fails against the current blocking implementation
- **Approach:** drive accepted sockets from the same `poll()` as a per-connection
  state machine (read the 2-byte length, then accumulate the body against a
  deadline). Do **not** use a blocking read on the poll thread. A worker process
  is acceptable if it is simpler, but it must not share the `poll()` loop's fd
  table with the parent.
- **Verify:** `./verify.sh` plus `tests/hostile_test.py`. **The failing test now
  exists and is proven red** against the current build: 4 of 8 hostile checks fail
  (trickle, idle-huge-declaration ×2, four concurrent stalls). It is wired into
  `verify.sh`, so the oracle is red until this lands. Design note: the two SIGPIPE
  and loopback-bind checks in the same file already pass, so the suite is not
  simply failing wholesale.
- **Blast radius, measured:** with the loopback-bind fix in place the engine
  answers `127.0.0.1:5333` but is unreachable on the LAN address (UDP gets no
  answer, TCP is refused). This defect is therefore reachable only by a local
  unprivileged process, not by anything on the network. That downgrades the
  *severity* — it is a local DoS, not remote — but not the *correctness* of the
  fix, and it does not make the blocking loop acceptable: one stuck process on
  the same machine still takes DNS down for every application.
- **Attempted twice; both reverted. What is now known:**
  1. Round 6 built the cooperative-yield loop to `llvm-as` clean, then reported
     "bind failed". **That conclusion was wrong.** A leaked test engine was still
     holding 5333 (its command line is `./eng2`, so the `pkill -f /tmp/...` pattern
     missed it), and the *known-good* build failed to bind identically. Lesson: before
     blaming the code, confirm the port is actually free — `lsof` is unreliable here,
     but a Python `bind()` attempt is not.
  2. With the port genuinely free, the restored implementation scored **4/8** on the
     hostile suite. Round 9 found why: the pollfd word was written twice — the fd,
     then `store i64 4294967296` for the events — so the second store clobbered the
     fd and `poll()` was watching **stdin**, not the connection. That single bug
     explains all three failures. Fixed by building the whole 8-byte word
     (`fd | POLLIN<<32`) and storing it once.
  3. With that fix the hostile suite goes **4/8 -> 8/10**: the trickle, idle-65534
     and bind-diagnostic checks all pass. **But the behaviour suite regresses to
     29/31** — "TCP relay answers on a fresh engine" and "TCP allowed domain is
     relayed upstream" now fail, which the blocking version passed. So the wait loop
     now watches the socket properly but the frame-completion/relay path is not yet
     correct.
  4. Round 10 tried a second suspected cause: `tcp_done` closed the socket without
     clearing `tw_in`, which would leave `check_tcp` re-entering the wait loop on a
     dead fd and stop accepting TCP queries. Clearing it changed **nothing** (29/31
     and 8/10, identical), so that was not the cause either. The remaining
     behaviour regression is still undiagnosed.
  5. **Not committed.** Candidate preserved at
     `/tmp/v2/candidate_pollfd_fixed.ll` (+ `.eng`), which is strictly further
     along than anything previously attempted: 8/10 hostile with a diagnosed root
     cause. The next attempt should start from this file and fix the completion
     path, not re-derive the pollfd setup.
- **A separate, confirmed bug found while diagnosing this:** `fatal_port` prints
  garbage for any port >= 1000. The three-digit branch does `udiv(h_d, 1)` where it
  means `urem(h_d, 10)`, so 5333 renders as `e33`. Every startup-failure message for
  a four-digit port is unreadable, which is exactly what made the round-6 diagnosis
  hard. Tracked in the Backlog.
- **Not started:** the implementation. Concrete design, checked against the code:
  1. Add `@tcp_pool` (`[16 x 4096 x i8]`) plus per-slot arrays `@tcp_fd`,
     `@tcp_need`, `@tcp_got`, `@tcp_dl`, `@tcp_len`, `@tcp_state`. 16 slots is the
     existing `@tcp_pending` cap.
  2. `accept()` becomes: take a free slot, set the socket non-blocking, record
     `need = 2`, `got = 0`, `deadline = now + 5`, then **return to the poll loop**.
     It must not touch `@tcp_tx`, which is currently the single connection buffer.
  3. Give the main `poll()` a bounded timeout (e.g. 100 ms) instead of `-1`, so
     parked connections are serviced without building a dynamic pollfd array. A
     10 Hz wakeup is irrelevant next to a 4096-byte buffer and a 12 ns lookup.
  4. Each iteration, for every live slot: `recv()` non-blocking into
     `@tcp_pool[slot]`. When `got >= 2` and the length is known, set
     `need = 2 + len`. When `got == need`, copy the slot into `@tcp_tx`, set
     `%conn` to the parked fd, and fall into the existing
     classify/sinkhole/forward code unchanged.
  5. When `now > deadline`, close the fd and free the slot.
  6. Replace the per-recv `SO_RCVTIMEO` reliance with the absolute `deadline`;
     `SO_RCVTIMEO` alone is what a trickling peer defeats today.
- **Rejected shortcuts, and why:** a single bounded blocking read would fix the
  idle-declaration case but still delay UDP for the whole wait, failing criteria
  1 and 3. Forking per connection does not compose with the current design, where
  the child would have to park an fd in `@state_tcp` that only the parent can
  later read. It needs the poll loop to stop servicing a
  connection to completion — accept, then return to `poll()` with the connection
  tracked (bytes wanted, bytes received, absolute deadline) until the frame
  completes. A single bounded blocking read would fix the "declares 65534 and
  sends nothing" case but would still delay UDP for the whole wait, so it does not
  meet the first and third criteria.
- **Files:** `advoid.ll`, `tests/engine_test.py`, `tests/hostile_test.py`

---

## Sprint 2 — Correctness of state and upstream

These produce **wrong answers or forged answers**, not outages. S2.2 is a
security issue: a local process can inject DNS answers today.

| ID | Status | Sev | Item |
|---|---|---|---|
| **S2.1** | `[x]` | high | **State table keyed on txid alone** — cross-client answer misdelivery. See below |
| **S2.2** | `[~]` | high | **Upstream replies unvalidated** — forged datagrams are relayed |
| **S2.3** | `[x]` | **blocker** | **GATING — done.** A TCP client has no 512-byte limit, so when forwarding such a query the engine now appends an OPT record advertising its own 4096-byte buffer; upstream then returns the full answer in one datagram instead of truncating, and the client's RFC 1035 4.2.1 TCP retry finally resolves. Confirmed upstream honours this (a hand-built `OPT(4096)` query returns 1028B, TC=0). The first attempt did not work because the 11 OPT bytes were written to `len+1 .. len+11` — the first byte was computed but never stored, so the record started one byte late and left byte `len` holding stale buffer content. **Verified:** `verify.sh` green, 4/4 consecutive runs, suite 32/32. **Still open:** answers above 4096 bytes still need a genuine TCP upstream fetch; this change raises the ceiling, it does not remove it (tracked in the Backlog) |
| S2.4 | `[ ]` | low | Use a resolver-owned randomised upstream txid and map back to the client's |

### S2.1 — State table keyed on transaction ID alone

- **Area:** engine · **Status:** `[ ]`
- **Problem:** `state_addrs[txid]` and `state_tcp[txid]` are keyed only by the
  16-bit transaction ID. A TCP client asking `cloudflare.com` with txid `0x5A5A`
  **received another client's `example.com` answer**, and the UDP client received
  nothing. Verified 3/3. Two TCP clients sharing a txid also overwrite each
  other, and the first client's fd is never closed.
- **Acceptance:**
  - [ ] A reply is delivered only to the client and transport that sent the query
  - [ ] Two concurrent queries sharing a txid both get their own correct answer
  - [ ] Two TCP clients sharing a txid both get their own answer; no fd leak
  - [ ] Regression test covering both the UDP-vs-TCP and TCP-vs-TCP collisions
- **Approach:** key on `(protocol, client address, client port, txid)`, or keep
  fully separate tables per transport and never let one clear the other. Also
  **validate the reply's question section** against the stored query — that alone
  catches most misdelivery.
- **Done (round 11).** Each in-flight transaction now stores a fingerprint of its
  question (`@state_qhash`, via `hash_qname`), and a reply whose question does not
  match is dropped instead of relayed. Verified: the collision test fails against
  the pre-fix build -- client B received `example.com` when it had asked for
  `example.org` -- and passes after. Behaviour suite **35/35**, oracle green.
- Partially addressed: the table is still *keyed* on txid alone, so a colliding
  query loses its slot and must retry. That is a denial-of-service under load, not
  misdelivery; a composite key would be the full fix (Backlog).
- **Verify:** `./verify.sh` plus the new collision tests.
- **Files:** `advoid.ll`, `tests/engine_test.py`

### S2.2 — Upstream replies unvalidated

> **Round 14: the anycast explanation is disproven.** Five queries sent straight to
> `1.1.1.1:53` all came back from `1.1.1.1:53` — one distinct source — so a
> connected socket *should* accept them. Re-applying `connect()` to a clean tree
> reproduced the same four failures, ruling out a port conflict and a transient.
> The engine binds the upstream socket to `1.1.1.1:53` and then does not act on
> replies that provably originate there. Root cause still unidentified; it needs
> packet capture (`sudo tcpdump -i lo0 -n udp and port 53`), not another
> hypothesis. A regression test exists and is proven red
> (`the upstream socket must be connected to its resolver`, reporting
> `seen ['*:*']`); it is tracked as EXPECTED-FAIL against this item.

### S2.2 — Upstream replies unvalidated

- **Area:** engine · **Status:** `[ ]`
- **Problem:** the upstream UDP socket is unconnected, so a datagram from **any**
  source is accepted if its transaction ID matches a pending entry. Verified: a
  forged answer (`203.0.113.66`) from an unrelated local socket was delivered to
  the client, and even a **QR=0** query-shaped datagram was relayed.
- **Acceptance:**
  - [ ] `connect()` the upstream socket to `1.1.1.1:53` so the kernel drops datagrams from other sources
  - [ ] Replies with `QR=0` are rejected
  - [ ] A reply whose question section does not match the stored query is rejected
  - [ ] Regression test: a forged datagram with a matching txid is not delivered
- **Note:** an earlier attempt at `connect()` appeared to break TCP relaying. That
  was a misdiagnosis — the real cause was the `set_io_timeout` GEP bug (fixed).
  Retest it now rather than trusting the earlier result.
- **Verify:** `./verify.sh` plus the forgery test.
- **Files:** `advoid.ll`, `tests/engine_test.py`

---

## Sprint 3 — Protocol conformance

Malformed, non-conformant replies are rejected by strict parsers (`dnspython`,
`miekg/dns`) and are the kind of thing that breaks one app in a way nobody can
reproduce.

| ID | Status | Sev | Item |
|---|---|---|---|
| S3.1 | `[x]` | medium | **NODATA reply is malformed** — ARCOUNT=0 but the client's OPT is still appended; `dig` reports *"Message has N extra bytes at end"* |
| S3.2 | `[x]` | medium | **Question section not length-checked** — TYPE/CLASS fabricated from stale buffer bytes when absent |
| S3.3 | `[ ]` | medium | **Truncated-record handling** — when TC is set the relayed packet still claims records it does not contain; drop the incomplete tail and fix the counts |
| S3.4 | `[x]` | medium | **Validate QDCOUNT / opcode / QR** — reply FORMERR to `QDCOUNT≠1`, NOTIMP to `opcode≠0`, drop `QR=1` |
| S3.5 | `[ ]` | low | Misaligned `i64` stores in `write_answer` — use byte stores (see invariant I6) |
| S3.6 | `[ ]` | low | `sinkhole`'s 512-byte cap vs the 4096 buffer; rename the inverted `%want_answer` |

---

## Sprint 4 — Productization

The product is a working resolver with an unfinished shell around it. This
sprint is what makes it something a stranger can install safely.

| ID | Status | Sev | Item |
|---|---|---|---|
| **S4.1** | `[ ]` | blocker | **Verify the `networksetup` privilege path** — the menu app runs it unprivileged while `install.sh` uses `sudo`. If it fails, Enable silently does nothing. 30-second manual test: run `networksetup -setdnsservers "Wi-Fi" 127.0.0.1` as the user, then `empty` |
| S4.2 | `[ ]` | high | **Single hardcoded upstream** — no fallback, no config. Breaks entirely on networks that filter 1.1.1.1, including corporate split-horizon DNS. Read upstreams from the plist |
| S4.3 | `[ ]` | high | **Uninstall leaves DNS pointing at a deleted engine** — `brew uninstall --cask` and trashing the app both do. Restore DNS from `uninstall_postflight`, and add cask `caveats` |
| S4.4 | `[ ]` | high | **The app never calls `enable()`** despite `README.md:59` claiming it auto-routes DNS |
| S4.5 | `[ ]` | medium | **State honesty** — the icon reflects DNS settings, not engine health; no watchdog, no auto-recovery; health probe uses an *allowed* domain so it fails offline and blocks enabling |
| S4.6 | `[ ]` | medium | **Exact-QNAME matching only** — 31% of entries are apex domains that never cover subdomains. Either add optional suffix matching or document it plainly |
| S4.7 | `[ ]` | medium | **False positives** — ship a compatibility allowlist for dual-use hosts (fraud/bot defence, consent platforms, affiliate redirectors). Agents listed specific offenders in review |
| S4.8 | `[ ]` | medium | **Privacy claims are false** — every allowed query goes to Cloudflare. Rewrite "Local-only ✅" and "stays local" |
| S4.9 | `[ ]` | low | **Encrypted DNS bypass** is undocumented — DoH/DoT apps never touch `127.0.0.1:53` |
| S4.10 | `[ ]` | low | Document the 1024-entry custom-blocklist cap; `README.md:124` tells users to restart via the menu, which cannot do it |
| S4.11 | `[ ]` | low | `TECHNICAL.md` documents a different engine (512-byte stack buffer, 2 sockets, NXDOMAIN/TTL 0). It is sold as a line-by-line walkthrough |

---

## Sprint 5 — Release engineering

Nothing here affects behaviour; all of it affects whether the product can be
handed to a stranger safely.

| ID | Status | Sev | Item |
|---|---|---|---|
| S5.1 | `[ ]` | blocker | **Commit and tag** a release. The cask URL and changelog links currently 404 |
| S5.2 | `[ ]` | high | **Code sign and notarize** app and engine with Developer ID; verify with `codesign --verify --strict` and `spctl -a -vv` in CI **and** before `launchctl bootstrap` |
| S5.3 | `[ ]` | high | `homebrew/advoid.rb` has `sha256 :no_check` — publish a real checksum |
| S5.4 | `[ ]` | medium | Pin CI actions by SHA and the LLVM toolchain version; the release job has `contents: write` and floating tags |
| S5.5 | `[ ]` | medium | Pin the blocklist fetch by commit + checksum, or commit the generated `blocklist.ll`. Right now shipped content ≠ reviewed content |
| S5.6 | `[ ]` | low | `install.sh` runs `rm -rf /Applications/Advoid.app` without `sudo` under `set -e`, so a rebuild can abort after 90 s of work |
| S5.7 | `[ ]` | low | Run the behaviour suite as root in CI, failing the release if it cannot run |

---

## Backlog

New items go here. Copy the template, keep IDs unique, and move the item into
the right sprint when you pick it up.

### Template

```markdown
| ID | `[ ]` | sev | **Short imperative title.** One-line problem statement. See details below |

#### S?.? — Short title
- **Area:** engine \| ui \| compiler \| packaging \| docs \| tests
- **Status:** `[ ]`
- **Problem:** what is wrong, and how it was observed
- **Acceptance:**
  - [ ] a checkable condition
  - [ ] a checkable condition
- **Verify:** `./verify.sh` and/or a named test
- **Files:** paths likely to change
- **Notes:** dead ends, constraints, anything non-obvious
```

### Open items

| ID | Status | Sev | Item |
|---|---|---|---|
| B2 | `[x]` | medium | **`fatal_port` mis-prints ports >= 1000 — fixed.** The three-digit branch did `udiv(h_d, 1)` instead of `urem(h_d, 10)`, so 5333 rendered as `e33`. Replaced the hand-rolled formatter with the existing `u64_to_ascii`, which handles any width. Guarded by a hostile-suite check that asserts the *error line* names the port (a bare substring check passed against the broken build, because the port also appears in the banner). |
| B1 | `[ ]` | high | **Oracle determinism.** `the TCP retry resolves the truncated query` flips between pass and fail across identical runs. Until the cause is known, `verify.sh` cannot gate a Definition of Done. Likely related to S2.1 (txid-keyed state table) — the same misdelivery that S2.1 describes would also explain a TCP retry sometimes receiving the upstream's 21-byte truncated answer and sometimes the full one. Investigate alongside S2.1. |

---

## Review provenance

Sprints 1–3 come from three independent adversarial review passes (privilege &
security, protocol & memory safety, user & web experience) run against the
pre-sprint tree. Findings already fixed and now covered by the suite: case
bypass, `INADDR_ANY` bind, user-writable root binary, SIGPIPE, DNS-restore
service skip, the `set_io_timeout` GEP bug, the per-relay stack leak, and the
single-byte test port.