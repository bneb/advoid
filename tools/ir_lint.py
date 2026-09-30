#!/usr/bin/env python3
"""Lint advoid.ll for the two IR-level mistakes that have each shipped here.

Both are invisible to behavioural tests:

1. `getelementptr [N x i8], %p, i64 k` addresses `p + k*sizeof(element)` -- for
   `[16 x i8]` that is +128 for k=8, not +8. It silently writes into the caller's
   frame. The fix is the two-index form `i64 0, i64 k`, which addresses byte k.
2. DNS multi-byte fields are big-endian. `store i16 <literal>` writes the host's
   byte order, so a literal intended as 0x8180 lands on the wire as 0x8081. Every
   multi-byte DNS field must be emitted a byte at a time.

Matching runs over the whole file with whitespace normalised, so an instruction
split across lines, a `nuw` flag, or a `volatile`/`atomic` prefix cannot hide a
mistake. Fixtures under tools/ir_lint_fixtures/ prove each rule fires.
"""
import re
import sys

ALLOW = {
    ("i32", "%u_a4"):       "sin_addr: little-endian on purpose (0x0100007F)",
    ("i32", "%t_a4"):       "sin_addr: little-endian on purpose (0x0100007F)",
    ("i32", "%client_len"): "socklen_t for recvfrom: host order, not a wire field",
    ("i32", "%nosig"):      "int option value for setsockopt: host order",
    ("i64", "%tw_need"):    "local TCP-wait state: host order, never on the wire",
    ("i64", "%p0v"):        "local pollfd scratch: host order, never on the wire",
    ("i64", "%p1v"):        "local pollfd scratch: host order, never on the wire",
}

GEP_ONE_INDEX = re.compile(
    r"getelementptr\s+(?:inbounds\s+)?(?:nuw\s+|nusw\s+|inrange\s+\([^)]*\)\s+)*"
    r"\[\s*\d+\s+x\s+\w+\s*\]\s*,\s*ptr\s+(?:%?[\w.$]+|@[\w.$]+)\s*,\s*i(?:32|64)\s+(-?\d+)"
)

STORE_LITERAL = re.compile(
    r"\bstore\s+(?:volatile\s+|atomic\s+|release\s+|acquire\s+)*"
    r"(?P<w>i(?:16|32|64))\s+(?P<v>-?\d+)\s*,\s*ptr\s+(?P<p>%?[\w.$]+|@[\w.$]+)"
)


def strip_comments(text):
    out = []
    for line in text.split("\n"):
        in_str, cut, i = False, len(line), 0
        while i < len(line):
            c = line[i]
            if c == '"' and (i == 0 or line[i - 1] != "\\"):
                in_str = not in_str
            elif c == ";" and not in_str:
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


def logical_lines(body):
    """Yield (start_lineno, text), joining lines until brackets balance.

    LLVM lets an instruction wrap, and a per-line regex would miss the tail of a
    wrapped one -- which is exactly how a mistake slips past a linter.
    """
    buf, start, depth = "", 0, 0
    for lineno, line in enumerate(body.split("\n"), 1):
        if not buf:
            start = lineno
        buf = (buf + " " + line).strip() if buf else line
        depth = buf.count("(") - buf.count(")") + buf.count("[") - buf.count("]")
        # A trailing comma is how LLVM continues an instruction onto the next line;
        # bracket depth alone is not enough, since `[16 x i8]` balances on one line.
        cont = buf.rstrip().endswith(",")
        if depth <= 0 and not cont and buf.strip():
            yield start, buf
            buf, depth = "", 0
    if buf.strip():
        yield start, buf


def lint(text):
    findings = []
    for lineno, line in logical_lines(strip_comments(text)):
        if not line.strip():
            continue
        m = GEP_ONE_INDEX.search(line)
        if m:
            idx = int(m.group(1))
            if idx != 0:
                findings.append((lineno, "gep-one-index",
                    f"getelementptr into an array type with a single index {idx}: "
                    f"addresses {idx}*sizeof(element) bytes, not byte {idx}. "
                    f"Use `i64 0, i64 {idx}` to address byte {idx}."))
        m = STORE_LITERAL.search(line)
        if m:
            width, value, ptr = m.group("w"), m.group("v"), m.group("p")
            if (width, ptr) in ALLOW:
                continue
            if int(value) == 0:
                continue
            findings.append((lineno, "wire-endianness",
                f"store {width} of the literal {value} into {ptr}: DNS fields are "
                f"big-endian and a store of width {width} emits host byte order. "
                f"Write the bytes individually."))
    return findings


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "advoid.ll"
    findings = lint(open(path).read())
    if not findings:
        print(f"ir-lint: {path} clean")
        return 0
    for lineno, kind, msg in findings:
        print(f"{path}:{lineno}: [{kind}] {msg}")
    print(f"ir-lint: {len(findings)} finding(s) in {path}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
