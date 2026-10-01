#!/usr/bin/env bash
# verify.sh — one command to prove the tree is sound.
#
# Every roadmap item's "Verify:" line refers to this script. Run it before
# claiming any item is done. It is deliberately fast (~2 min) so an autonomous
# loop can afford to run it after every change.
#
#   ./verify.sh            static checks + build test engine + behaviour suite
#   ./verify.sh --static   static checks only (seconds)
#   ./verify.sh --suite    behaviour suite only
#   ./verify.sh --build    also link the production engine (needs the SDK)
set -uo pipefail

cd "$(dirname "$0")"

export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export GOCACHE="${GOCACHE:-/tmp/gocache}"
SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
[ -d "$SDK" ] || SDK="$(ls -d /Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk 2>/dev/null | sort -V | tail -1)"

PORT="${ADVOID_TEST_PORT:-5333}"
WORK="$(mktemp -d /tmp/advoid-verify.XXXXXX)"

# Fail fast if a leftover test engine still holds the port. Otherwise the suites
# report a scatter of confusing "0 bytes" failures that look exactly like engine
# regressions. This trap has cost four rounds of misdiagnosis; `lsof` is not
# reliable inside the sandbox, so probe the port directly.
port_free() {
  python3 - "$1" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PYEOF
}

if ! port_free "$PORT"; then
  holder="$(lsof -nP -iUDP:"$PORT" 2>/dev/null | awk 'NR>1 {print $1" (pid "$2")"}' | head -1)"
  echo "ABORT: UDP port $PORT is already in use${holder:+ -- held by $holder}."
  echo "       A leftover test engine from an earlier run is the usual cause; kill it and retry."
  echo "       'lsof' may not see it inside a sandbox; try: pkill -9 -f 'advoid.*eng'"
  exit 2
fi
trap 'rm -rf "$WORK"' EXIT

fails=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fails=$((fails+1)); }
run()  { local name="$1"; shift; if "$@" >"$WORK/log" 2>&1; then ok "$name"; else bad "$name"; sed 's/^/        /' "$WORK/log" | tail -6; fi; }

static() {
  echo "── static ──────────────────────────────────────────────"
  run "advoid.ll assembles"        llvm-as advoid.ll -o /dev/null
  run "ir-lint (byte order, GEP)"   python3 tools/ir_lint.py advoid.ll
  # Fixtures prove the lint still has teeth: each must be caught, the control clean.
  run "ir-lint fixtures"            python3 tools/ir_lint_selftest.py
  run "go vet"                     go vet ./...
  run "go tests"                   go test ./...
  # Coverage is a floor, not a goal. It is here so coverage cannot silently
  # regress; the number that matters is the failure-mode audit in ROADMAP.md.
  COV="$(go test -cover ./... 2>/dev/null | grep -oE 'coverage: [0-9.]+' | grep -oE '[0-9.]+' || echo 0)"
  if awk "BEGIN{exit !($COV >= 70)}"; then ok "go coverage ${COV}% (floor 70%)"
  else bad "go coverage ${COV}% is below the 70% floor"; fi
  run "swift typecheck"            swiftc -typecheck -module-cache-path "$WORK/mc" advoid-menu.swift
  run "install.sh syntax"          bash -n install.sh
  run "uninstall.sh syntax"        bash -n uninstall.sh
  # reinstall-assets.sh is deliberately gitignored (a local install helper), so it
  # exists only on the machine that wrote it. Syntax-checking it unconditionally
  # meant this check passed locally and failed in CI on every push -- it asserted
  # something about a file the project does not ship. Reported explicitly rather
  # than dropped, so the situation stays visible.
  if git ls-files --error-unmatch reinstall-assets.sh >/dev/null 2>&1; then
    run "reinstall-assets.sh syntax" bash -n reinstall-assets.sh
  else
    skip "reinstall-assets.sh syntax" "local-only helper, not tracked (see .gitignore)"
  fi
  run "engine_test.py parses"      python3 -c "import ast;ast.parse(open('tests/engine_test.py').read())"
  # Parse the workflows with Ruby rather than Python: macOS runners ship Ruby with
  # a real YAML parser, while their Python is externally managed and refuses
  # `pip install pyyaml`. Fall back to PyYAML only if Ruby is unavailable.
  yaml_ok() {
    if command -v ruby >/dev/null 2>&1; then
      ruby -ryaml -e "YAML.load_file(ARGV[0])" "$1" >/dev/null 2>&1
    else
      python3 -c "import yaml,sys;yaml.safe_load(open(sys.argv[1]))" "$1"
    fi
  }
  run "ci.yml valid"               yaml_ok .github/workflows/ci.yml
  run "release.yml valid"          yaml_ok .github/workflows/release.yml
  run "no build artifacts tracked"  bash -c '! git ls-files --error-unmatch final.ll final.o Advoid.app 2>/dev/null'
}

suite() {
  echo "── behaviour suite (port $PORT) ───────────────────────"
  if [ ! -d "$SDK" ]; then echo "  no macOS SDK found; skipping"; return; fi
  local src="$WORK/advoid_test.ll" all="$WORK/final_test.ll" obj="$WORK/final_test.o"
  # @local_port is a real 16-bit port, so a high port needs no byte packing.
  sed "s/@local_port = global i16 53/@local_port = global i16 $PORT/; s/LLVM Advoid Active on :53/LLVM Advoid Active on :$PORT/" \
      advoid.ll > "$src"
  python3 - "$src" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
pat = re.compile(r'(@\w+ = private (?:unnamed_addr )?constant )\[(\d+) x i8\] c"((?:[^"\\]|\\.)*)"')
s = pat.sub(lambda m: '%s[%d x i8] c"%s"' % (m.group(1),
             len(re.sub(r'\\[0-9A-Fa-f]{2}', 'X', m.group(3))), m.group(3)), s)
open(p, 'w').write(s)
PY
  if ! llvm-link "$src" blocklist.ll -S -o "$all" >"$WORK/log" 2>&1 \
  || ! llc -O2 "$all" -filetype=obj -o "$obj" -mtriple=arm64-apple-macosx14.0.0 >>"$WORK/log" 2>&1 \
  || ! clang -isysroot "$SDK" "$obj" -o "$WORK/engine" 2>>"$WORK/log"; then
    bad "build test engine"; sed 's/^/        /' "$WORK/log" | tail -6; return
  fi
  ok "build test engine"
  # Trust the suite's own exit status: it already separates tracked-open
  # EXPECTED-FAIL checks from real failures. Grepping [FAIL] would count both.
  if ADVOID_TEST_PORT="$PORT" python3 tests/engine_test.py "$WORK/engine" >"$WORK/suite" 2>&1; then
    suite_rc=0
  else
    suite_rc=1
  fi
  local passed failed
  passed=$(grep -c '\[PASS\]' "$WORK/suite" || true)
  failed=$(grep -c '^  FAILED:' "$WORK/suite" || true)
  grep -E '^\s+\[FAIL\]' "$WORK/suite" | sed 's/^/        /' || true
  if [ "$suite_rc" -eq 0 ]; then ok "behaviour suite ($passed passed, tracked-open excluded)"
  else bad "behaviour suite ($passed passed, $failed real failure(s))"; fi

  # Hostile-input suite. Currently RED: it covers S1.1, where a TCP client that
  # trickles bytes holds the single-threaded poll loop and UDP stops answering.
  # It is wired in deliberately. A resolver that can be frozen by one slow client
  # must not sit behind a green oracle, and muting this would be reward hacking.
  local hostile_rc
  if ADVOID_TEST_PORT="$PORT" python3 tests/hostile_test.py "$WORK/engine" >"$WORK/hostile" 2>&1; then
    hostile_rc=0
  else
    hostile_rc=1
  fi
  local hpassed hfailed
  hpassed=$(grep -c '\[PASS\]' "$WORK/hostile" || true)
  hfailed=$(grep -c '\[FAIL\]' "$WORK/hostile" || true)
  grep -E '^\s+\[FAIL\]' "$WORK/hostile" | sed 's/^/        /' || true
  if [ "$hostile_rc" -eq 0 ]; then ok "hostile-input suite ($hpassed passed, tracked-open excluded)"
  else bad "hostile-input suite ($hpassed passed, real failures)"; fi
}

case "${1:-}" in
  --static) static ;;
  --suite)  suite ;;
  --build)  static; suite
            echo "── production link ──────────────────────────────"
            llvm-link advoid.ll blocklist.ll -S -o "$WORK/rel.ll" \
              && llc -O2 "$WORK/rel.ll" -filetype=obj -o "$WORK/rel.o" -mtriple=arm64-apple-macosx14.0.0 \
              && run "link production engine" clang -isysroot "$SDK" "$WORK/rel.o" -o "$WORK/advoid-engine" ;;
  *)       static; suite ;;
esac

echo "────────────────────────────────────────────────────────"
if [ "$fails" -eq 0 ]; then echo "all checks passed"; else echo "$fails check(s) failed"; fi
exit $((fails > 0))