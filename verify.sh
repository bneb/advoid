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
  run "reinstall-assets.sh syntax" bash -n reinstall-assets.sh
  run "engine_test.py parses"      python3 -c "import ast;ast.parse(open('tests/engine_test.py').read())"
  run "ci.yml valid"               python3 -c "import yaml;yaml.safe_load(open('.github/workflows/ci.yml'))"
  run "release.yml valid"          python3 -c "import yaml;yaml.safe_load(open('.github/workflows/release.yml'))"
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
  ADVOID_TEST_PORT="$PORT" python3 tests/engine_test.py "$WORK/engine" >"$WORK/suite" 2>&1
  local passed failed
  passed=$(grep -c '\[PASS\]' "$WORK/suite" || true)
  failed=$(grep -c '\[FAIL\]' "$WORK/suite" || true)
  grep -E '^\s+\[FAIL\]' "$WORK/suite" | sed 's/^/        /' || true
  if [ "$failed" -eq 0 ]; then ok "behaviour suite ($passed/$passed)"
  else bad "behaviour suite ($passed passed, $failed failed)"; fi

  # Hostile-input suite. Currently RED: it covers S1.1, where a TCP client that
  # trickles bytes holds the single-threaded poll loop and UDP stops answering.
  # It is wired in deliberately. A resolver that can be frozen by one slow client
  # must not sit behind a green oracle, and muting this would be reward hacking.
  ADVOID_TEST_PORT="$PORT" python3 tests/hostile_test.py "$WORK/engine" >"$WORK/hostile" 2>&1
  local hpassed hfailed
  hpassed=$(grep -c '\[PASS\]' "$WORK/hostile" || true)
  hfailed=$(grep -c '\[FAIL\]' "$WORK/hostile" || true)
  grep -E '^\s+\[FAIL\]' "$WORK/hostile" | sed 's/^/        /' || true
  if [ "$hfailed" -eq 0 ]; then ok "hostile-input suite ($hpassed/$hpassed)"
  else bad "hostile-input suite ($hpassed passed, $hfailed failed)"; fi
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