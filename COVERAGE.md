# Coverage

Line coverage is not the right target everywhere, and pretending otherwise would
produce tests that assert nothing. This records what is measured, what is not, and
— most importantly — whether every defect we have actually hit now has a test.

## Measured

| Component | Tool | Now | Gate | Notes |
|---|---|---|---|---|
| Go compiler | `go test -cover` | **73.8%** | floor 70% in `verify.sh` | Covers hashing, parsing, safelist, collision detection, IR emission, local-blocklist generation |
| Behaviour suite | `tests/engine_test.py` | **32 checks** | must be all green | End-to-end over real sockets against the built engine |
| Hostile-input suite | `tests/hostile_test.py` | **11 checks** | 7 gate + 4 tracked-open | Slow-loris and concurrent stalls are EXPECTED-FAIL, owned by S1.1; the rest gate the build |
| IR static lint | `tools/ir_lint.py` | — | wired into `verify.sh` | Byte-order and `getelementptr` shapes |

### Known coverage gaps, stated plainly

- **`fetchStream` (0%)** — does a real HTTPS fetch to a hardcoded URL. Needs the
  URL to become a parameter before it can be tested against a local server.
- **`main` (0%)** — the CLI entry point. Exercised indirectly by running the
  compiled binary, not by `go test`.
- **Engine (raw LLVM IR)** — there is no line-coverage story here, and faking one
  would be worse than none. `llc` emits no coverage instrumentation for hand-written
  IR, and counting executed basic blocks would measure the code we wrote, not the
  behaviour we depend on. The meaningful unit is the failure-mode audit below.
- **Swift UI** — no test harness. The known risk is S4.1 (can the app change DNS
  at all unprivileged?), and no unit test can answer that; it needs a real run.

## Failure-mode audit

Every row is a defect that actually shipped or was actually observed. "Covered"
means a test fails without the fix — not merely that a test touches the area.

| # | Failure mode | Found by | Covered? | Test |
|---|---|---|---|---|
| 1 | Blocklist bypassed by one uppercase letter | reviewer | yes | suite: *case-insensitive* |
| 2 | Listeners bound `INADDR_ANY` | reviewer | **no** | assert in suite that a LAN-address query is refused |
| 3 | Root daemon runs a user-writable binary | reviewer | **no** | assert plist path is root-owned and outside the bundle |
| 2b | *(severity corrected: S1.1 is local-only after the loopback bind)* | this round | n/a | see ROADMAP S1.1 Notes |
| 4 | SIGPIPE kills the resolver | reviewer | **no** | TCP query then RST; engine must survive |
| 5 | `uninstall.sh` skips first network service | reviewer | **no** | run the pipeline, assert both services appear |
| 6 | `set_io_timeout` GEP writes 128 bytes up | reviewer | yes | suite: *first upstream query of a fresh engine* + lint (9 evasion fixtures, run by `ir_lint_selftest.py`) |
| 7 | Stack leak, 16 B per relayed reply | reviewer | **no** | assert SP is stable across many relays |
| 8 | Test suite could not bind unprivileged | all | yes | `verify.sh` runs it with no sudo |
| 9 | Answers > 4096 unreachable via TCP | reviewer | yes | suite: *TCP retry resolves the truncated query* |
| 10 | State table keyed on txid alone | reviewer | **yes** | suite: *a reply must go only to the client that asked* |
| 11 | Forged upstream reply relayed | reviewer | **yes** | hostile: *upstream socket is connected to its resolver* |
| 12 | Slow-loris stalls the whole resolver | reviewer | **yes** | `tests/hostile_test.py` — proven failing against the current build |
| 13 | `@tcp_pending` leaks and disables TCP | reviewer | **no** | S1.2 |
| 14 | NODATA reply carries the client's OPT | reviewer | **yes** | suite: *NODATA reply has no trailing OPT bytes* |
| 15 | Missing QTYPE/CLASS answered from stale bytes | reviewer | **yes** | suite: *truncated question yields no answer invented from stale bytes* |
| 16 | No QR/opcode/QDCOUNT validation | reviewer | **yes** | suite: *malformed query headers are rejected, not answered* |

**6 of 16 covered.** The uncovered ones are precisely the open roadmap items —
which is the point: the audit and the roadmap are the same list, seen from the
test side.

## What this implies for the roadmap

Adding a test is not a separate chore to be done "for coverage". Each row with a
blank *Covered?* cell is an item whose **first acceptance criterion should be the
regression test that fails without the fix**. Several already are; the remaining
ones are called out where they are implemented.