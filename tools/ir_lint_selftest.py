#!/usr/bin/env python3
"""Prove the IR lint still catches what it is supposed to catch.

A linter that silently stops matching is worse than none, because it reports
"clean". Every evasion class found in review has a fixture here, plus a control
that must stay silent. Run by verify.sh; exits non-zero if any expectation breaks.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ir_lint import lint

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ir_lint_fixtures")
CLEAN = "clean.ll"


def main():
    failures = []
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".ll"):
            continue
        path = os.path.join(HERE, name)
        findings = lint(open(path).read())
        if name == CLEAN:
            if findings:
                failures.append(f"{name}: control fixture must be clean, got {findings}")
        elif not findings:
            failures.append(f"{name}: EVADED the lint (expected a finding)")
    if failures:
        for f in failures:
            print(f"  {f}")
        print(f"ir-lint selftest: {len(failures)} problem(s)")
        return 1
    n = len([x for x in os.listdir(HERE) if x.endswith(".ll")]) - 1
    print(f"ir-lint selftest: {n} evasion fixtures caught, control clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
