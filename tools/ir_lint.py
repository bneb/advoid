#!/usr/bin/env python3
"""Lint advoid.ll for the two IR-level mistakes that have each shipped here.

Both are invisible to behavioural tests:

1. `getelementptr [N x i8], %p, i64 k` addresses `p + k*sizeof(element)` — for
   `[16 x i8]` that is +128 for k=8, not +8. It silently writes into the caller's
   frame. The fix is the two-index form `i64 0, i64 k`, which addresses byte k.

2. DNS multi-byte fields are big-endian. `store i16 <literal>` writes the host's
   byte order, so a literal intended as 0x8180 lands on the wire as 0x8081. Every
   multi-byte DNS field must be emitted a byte at a time.

The lint is deliberately narrow. A general "this IR is suspicious" checker would
generate noise and get ignored; these two rules have a crisp correct form and a
crisp wrong form, and each has already cost days here.
"""
import re
import sys

GEPS = re.compile(
    r"getelementptr\s+(?:inbounds\s+)?\[\s*\d+\s+x\s+\w+\s*\]\s*,\s*ptr\s+%?[\w.]+\s*,\s*i64\s+(-?\d+)\s*$")
STORES = re.compile(
    r"store\s+(i(?:16|32|64))\s+(-?\d+)\s*,\s*ptr\s+(%[\w.]+)")
# Stores of a literal wider than 8 bits that are genuinely host-order and must
# NOT be flagged. Each is listed with its reason so the exception is reviewable
# rather than a blanket suppression.
ALLOW = {
    ("i32", "%u_a4"):      "sin_addr: written little-endian on purpose (0x0100007F == 127.0.0.1)",
    ("i32", "%t_a4"):      "sin_addr: written little-endian on purpose (0x0100007F == 127.0.0.1)",
    ("i32", "%client_len"): "socklen_t for recvfrom: host order, not a wire field",
    ("i32", "%nosig"):     "int option value for setsockopt: host order",
}


def lint(path):
    findings = []
    for lineno, raw in enumerate(open(path), 1):
        line = raw.split(";")[0] if not raw.lstrip().startswith(";") else ""
        if not line.strip():
            continue

        m = GEPS.search(line.rstrip())
        if m:
            idx = int(m.group(1))
            findings.append(
                (lineno, "gep-one-index",
                 f"getelementptr into an array type with a single index {idx}: "
                 f"this addresses k*sizeof(element) bytes, not byte k. "
                 f"Use `i64 0, i64 {idx}` to address byte {idx}."))

        m = STORES.search(line.rstrip())
        if m:
            width, value, ptr = m.group(1), m.group(2), m.group(3)
            if (width, ptr) in ALLOW:
                continue
            # A zero fill is byte-order independent by construction.
            if int(value) == 0:
                continue
            findings.append(
                (lineno, "wire-endianness",
                 f"store i{width} of the literal {value} into {ptr}: DNS fields are "
                 f"big-endian, and an i{width} store emits the host's byte order. "
                 f"Write the bytes individually (store_be16 / store_be32) or two "
                 f"i8 stores."))

    return findings


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "advoid.ll"
    findings = lint(path)
    if not findings:
        print(f"ir-lint: {path} clean")
        return 0
    for lineno, kind, msg in findings:
        print(f"{path}:{lineno}: [{kind}] {msg}")
    print(f"ir-lint: {len(findings)} finding(s) in {path}")
    return 1


if __name__ == "__main__":
    sys.exit(main())