#!/usr/bin/env bash
# run-loop.sh — drive the autonomous engineering loop over ROADMAP.md.
#
# Each round is a FRESH headless session: no memory of prior rounds, so the agent
# cannot rationalise from its own earlier claims. Durable state lives in
# ROADMAP.md, CHANGELOG.md and git history.
#
#   ./run-loop.sh              loop until the roadmap has no [ ] items
#   ./run-loop.sh --rounds 5   at most 5 rounds
#   ./run-loop.sh --dry-run    print the round command, run nothing
#   ./run-loop.sh --verify-only  just re-run the verifier, no agent
#
# The loop refuses to run against a dirty tree: an agent's own uncommitted work
# is indistinguishable from a previous round's, and that is how half-finished
# items get silently absorbed into someone else's commit.
set -uo pipefail
cd "$(dirname "$0")"

ROUNDS=9999
DRY=0
VERIFY_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rounds) ROUNDS="${2:?}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$VERIFY_ONLY" = 1 ]; then exec ./verify.sh; fi

if [ -n "$(git status --porcelain)" ]; then
  echo "refusing to start: working tree is dirty."
  echo "commit or stash first — an agent's uncommitted work must not be"
  echo "confused with the previous round's leftovers."
  git status --short | head -20
  exit 1
fi

PROTOCOL="$(cat LOOP.md)"
item_rows()  { grep -E '^\| \*?\*?S[0-9]+\.[0-9]+' ROADMAP.md; }
todo_count() { item_rows | grep -c '\[ \]'; }
blocked_count() { item_rows | grep -c '\[!\]'; }

echo "roadmap: $(todo_count) todo, $(blocked_count) blocked"
[ "$(todo_count)" -eq 0 ] && { echo "nothing to do."; exit 0; }

round=0
while [ "$round" -lt "$ROUNDS" ]; do
  round=$((round + 1))
  left=$(todo_count)
  [ "$left" -eq 0 ] && { echo "roadmap complete after $((round-1)) round(s)."; break; }

  echo
  echo "════════ round $round · $left item(s) todo · $(date '+%H:%M:%S') ════════"

  if [ "$DRY" = 1 ]; then
    echo "would run: dsh --profile headless \"\$(cat LOOP.md)\""
    break
  fi

  head_before="$(git rev-parse HEAD)"

  # One fresh session. Its own commits are the round's output.
  dsh --profile headless "$PROTOCOL" || echo "round $round exited non-zero; continuing"

  # A round that left the tree dirty or the item claimed-but-unfinished is a
  # signal, not a reason to keep going blindly.
  if [ -n "$(git status --porcelain)" ]; then
    echo "⚠ round $round left uncommitted changes — pausing for inspection:"
    git status --short | head -10
    echo "  commit, revert, or amend the roadmap, then re-run."
    exit 1
  fi

  head_after="$(git rev-parse HEAD)"
  if [ "$(todo_count)" -ge "$left" ] && [ "$head_before" = "$head_after" ]; then
    echo "⚠ round $round neither advanced the roadmap nor committed — stopping to avoid a spin."
    exit 1
  fi
  if [ "$(todo_count)" -ge "$left" ]; then
    echo "  note: roadmap did not shrink this round (a claim or a [!] is still progress)."
  fi
done

echo
echo "final verification:"
./verify.sh || echo "⚠ verify.sh is red — the last item is not actually done."
