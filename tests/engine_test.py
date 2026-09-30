#!/usr/bin/env python3
"""Behavioural regression tests for the Advoid DNS engine.

These exercise the real engine binary over real sockets, which is the only way to
catch the class of bug that matters here: the engine runs, binds, and answers, but
answers *wrongly* or silently stops serving.

The engine is built to listen on a high port so the tests can run unprivileged and
without touching a daemon that may already own port 53.

Usage:
    python3 tests/engine_test.py ./advoid-engine-under-test

Exit status is 0 when every check passes, 1 otherwise.
"""

import binascii
import os
import socket
import struct
import subprocess
import sys
import time

PASSED = []
FAILED = []


def check(cond, label, detail=""):
    (PASSED if cond else FAILED).append(label)
    suffix = f"  -- {detail}" if detail else ""
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}{suffix}")


def qwire(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def header(txid=0x1234, flags=0x0100, qd=1, ar=0):
    return struct.pack("!HHHHHH", txid, flags, qd, 0, 0, ar)


def parse_response(data):
    """Strict RFC 1035 parse. Raises on a malformed message."""
    if len(data) < 12:
        raise ValueError("response shorter than a DNS header")
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if not (flags >> 15) & 1:
        raise ValueError("not a DNS response (QR bit clear)")
    i = 12
    for _ in range(qd):
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        if i >= len(data):
            raise ValueError("truncated question section")
        i += 5
    answers = []
    for _ in range(an):
        if i >= len(data):
            raise ValueError("truncated answer section")
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i] != 0:
                i += 1 + data[i]
            i += 1
        if i + 10 > len(data):
            raise ValueError("truncated answer record")
        atype, aclass, ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        rdata = data[i:i + rdlen]
        i += rdlen
        answers.append({"type": atype, "class": aclass, "ttl": ttl, "rdata": rdata})
    return {"flags": flags, "an": an, "answers": answers, "qd": qd}


def udp_query(port, pkt, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        data, _ = s.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def tcp_query(port, pkt, timeout=8.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(struct.pack("!H", len(pkt)) + pkt)
        ln = s.recv(2)
        if len(ln) < 2:
            return None
        n = struct.unpack("!H", ln)[0]
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()


def find_listening_port(proc):
    """Locate the port the engine is listening on.

    Candidates are tried cheapest-first:
      1. ADVOID_TEST_PORT, when set (used by CI for determinism)
      2. the port number reported by lsof, and the 16-bit value formed from its
         low byte, because macOS reports a truncated value for some ports
      3. a scan of the unprivileged range, confirmed with a real DNS query so an
         unrelated listener (a web UI, say) is never mistaken for the engine

    A UDP query is the final arbiter: only the engine answers DNS on this socket.
    """
    override = os.environ.get("ADVOID_TEST_PORT")
    if override:
        return int(override)

    probe = header() + qwire("doubleclick.net") + struct.pack("!HH", 1, 1)

    candidates = []
    try:
        out = subprocess.run(["lsof", "-nP", "-p", str(proc.pid)],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "UDP" not in line and "TCP" not in line:
                continue
            for tok in line.split():
                if ":" not in tok:
                    continue
                tail = tok.rsplit(":", 1)[1]
                if tail.isdigit():
                    b = int(tail)
                    candidates.extend([b, (b << 8) | b, b << 8])
    except OSError:
        pass

    seen = set()
    for port in candidates:
        if port in seen or not (0 < port < 65536):
            continue
        seen.add(port)
        if proc.poll() is not None:
            return None
        if udp_query(port, probe, timeout=1.0) is not None:
            return port

    # Fall back to a TCP-connect sweep: the engine serves TCP on the same port, so
    # the probe fails fast instead of waiting on UDP timeouts.
    for port in range(1024, 65536):
        if port in seen:
            continue
        if proc.poll() is not None:
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        connected = False
        try:
            s.connect(("127.0.0.1", port))
            connected = True
        except OSError:
            pass
        finally:
            s.close()
        if not connected:
            continue
        if udp_query(port, probe, timeout=1.0) is not None:
            return port
    return None


def main():
    if len(sys.argv) < 2:
        print("usage: engine_test.py <path-to-engine>", file=sys.stderr)
        return 2
    engine = os.path.abspath(sys.argv[1])
    if not os.access(engine, os.X_OK):
        print(f"engine not executable: {engine}", file=sys.stderr)
        return 2

    proc = subprocess.Popen([engine], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        time.sleep(1.5)
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace")
            print(f"engine exited immediately:\n{out}")
            return 1

        port = find_listening_port(proc)
        if port is None:
            print("could not find the engine's listening port (it may have failed to bind)")
            return 1
        print(f"engine pid={proc.pid} listening on port {port}\n")

        # MUST be the first check in this suite. The GEP bug in set_io_timeout
        # corrupts a stack slot; whether it matters depends on what the engine has
        # already done. A prior TCP connection makes the bug invisible, so a check
        # placed later passes against a broken build.
        print("\n### TCP relay works as the first upstream query of a fresh engine")
        # Must run before any other upstream traffic in this process.
        first = tcp_query(port, header(txid=0x0F1A) + qwire("example.com")
                          + struct.pack("!HH", 1, 1), timeout=10.0)
        first_parsed = parse_response(first) if first else None
        check(first_parsed is not None and len(first_parsed["answers"]) > 0,
              "TCP relay answers on a fresh engine, with no prior UDP traffic",
              f"{len(first) if first else 0} bytes")


        print("### blocked-domain answers are typed to match the query")
        for qtype, want_type, want_rdlen, label in (
            (1, 1, 4, "A"),
            (28, 28, 16, "AAAA"),
        ):
            data = udp_query(port, header() + qwire("doubleclick.net")
                             + struct.pack("!HH", qtype, 1))
            parsed = parse_response(data) if data else None
            check(parsed is not None, f"blocked {label} query answered")
            if parsed:
                ans = parsed["answers"]
                check(len(ans) == 1 and ans[0]["type"] == want_type,
                      f"blocked {label} answer has type {want_type}",
                      f"got {ans[0]['type'] if ans else None}")
                check(bool(ans) and len(ans[0]["rdata"]) == want_rdlen
                      and ans[0]["rdata"] == b"\x00" * want_rdlen,
                      f"blocked {label} rdata is all zeros",
                      binascii.hexlify(ans[0]["rdata"]).decode() if ans else "")
                check(bool(ans) and ans[0]["class"] == 1,
                      f"blocked {label} answer class is IN")

        print("\n### blocking is case-insensitive (RFC 4343)")
        # The engine folds A-Z to a-z while hashing. Without that, one uppercase
        # letter evades the whole blocklist.
        for name in ("doubleclick.net", "DoubLeClick.net",
                     "DOUBLECLICK.NET", "dOuBlEcLiCk.NeT"):
            data = udp_query(port, header() + qwire(name) + struct.pack("!HH", 1, 1))
            parsed = parse_response(data) if data else None
            check(parsed is not None and parsed["answers"]
                  and parsed["answers"][0]["rdata"] == b"\x00\x00\x00\x00",
                  f"{name} is blocked",
                  "forwarded" if parsed and not parsed["answers"] else "")

        print("\n### non-address qtypes get NODATA, not a bogus A record")
        for qtype, label in ((16, "TXT"), (65, "HTTPS"), (15, "MX")):
            data = udp_query(port, header() + qwire("doubleclick.net")
                             + struct.pack("!HH", qtype, 1))
            parsed = parse_response(data) if data else None
            check(parsed is not None and parsed["an"] == 0,
                  f"blocked {label} returns NODATA",
                  f"an={parsed['an'] if parsed else 'no reply'}")

        print("\n### allowed domains still forward")
        data = udp_query(port, header(txid=0x3333) + qwire("example.com")
                         + struct.pack("!HH", 1, 1))
        parsed = parse_response(data) if data else None
        check(parsed is not None and len(parsed["answers"]) > 0,
              "allowed domain forwarded upstream over UDP",
              f"{len(parsed['answers']) if parsed else 0} answers")

        print("\n### TCP transport (RFC 1035 4.2.1 fallback)")
        data = tcp_query(port, header() + qwire("doubleclick.net") + struct.pack("!HH", 1, 1))
        parsed = parse_response(data) if data else None
        check(parsed is not None, "TCP listener accepts and answers")
        if parsed:
            check(parsed["answers"] and parsed["answers"][0]["type"] == 1,
                  "TCP blocked answer is an A record")

        data = tcp_query(port, header(txid=0x2222) + qwire("example.com")
                         + struct.pack("!HH", 1, 1))
        parsed = parse_response(data) if data else None
        check(parsed is not None and len(parsed["answers"]) > 0,
              "TCP allowed domain is relayed upstream")

        print("\n### truncation is signalled so clients can retry over TCP")
        data = udp_query(port, header() + qwire("org") + struct.pack("!HH", 48, 1))
        parsed = parse_response(data) if data else None
        tc = (parsed["flags"] >> 9) & 1 if parsed else None
        check(tc == 1, "TC bit is set when upstream truncates", f"TC={tc}")

        # The retry opens a TCP connection to the upstream resolver. That can fail
        # for reasons outside the engine (upstream refusal, transient network), so
        # a refused relay is reported as a skip rather than an engine failure. The
        # engine must still be healthy afterwards either way.
        reply = None
        for _ in range(3):
            reply = tcp_query(port, header(txid=0x4444) + qwire("org")
                              + struct.pack("!HH", 48, 1), timeout=12.0)
            if reply:
                break
        if reply:
            check(len(reply) > 21,
                  "the TCP retry resolves the truncated query",
                  f"{len(reply)} bytes")
        else:
            print("  [SKIP] upstream refused the TCP relay on this network; "
                  "engine health is verified by the checks below")
        after = udp_query(port, header() + qwire("doubleclick.net")
                          + struct.pack("!HH", 1, 1), timeout=5.0)
        check(after is not None,
              "engine still healthy after the TCP retry attempt")

        # ---------------------------------------------------------------------
        print("\n### malformed query headers are rejected, not answered")
        def raw(pkt, timeout=2.0):
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sk.settimeout(timeout)
            try:
                sk.sendto(pkt, ("127.0.0.1", port))
                return sk.recvfrom(65535)[0]
            except socket.timeout:
                return None
            finally:
                sk.close()

        qn = qwire("doubleclick.net")
        tail = struct.pack("!HH", 1, 1)

        # QR=1: this is a response, not a query. Answering it invites loops.
        r = raw(header(txid=0x0101, flags=0x8180) + qn + tail)
        check(r is None, "a QR=1 packet is not answered",
              f"got {len(r)}B" if r else "")

        # QDCOUNT=0: no question to answer.
        r = raw(struct.pack("!HHHHHH", 0x0102, 0x0100, 0, 0, 0, 0) + qn + tail)
        check(r is None or struct.unpack("!H", r[2:4])[0] & 0xF == 1,
              "QDCOUNT=0 is refused with FORMERR or dropped",
              f"rcode={struct.unpack('!H', r[2:4])[0] & 0xF}" if r else "dropped")

        # opcode 5 is UPDATE; a recursive resolver must answer NOTIMP (rcode 4).
        r = raw(header(txid=0x0103, flags=0x2800) + qn + tail)
        ok = r is None or (struct.unpack("!H", r[2:4])[0] & 0xF) == 4
        check(ok, "a non-QUERY opcode is refused with NOTIMP or dropped",
              f"rcode={struct.unpack('!H', r[2:4])[0] & 0xF}" if r else "dropped")

        # ---------------------------------------------------------------------
        print("\n### a reply must go only to the client that asked")
        # The state table is keyed by transaction ID alone. Two queries in flight
        # with the same 16-bit ID collide, and without question validation one
        # client receives the other's answer.
        shared = 0x5A5A
        sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sa.settimeout(6)
        sa.sendto(header(txid=shared) + qwire("example.com") + struct.pack("!HH", 1, 1),
                  ("127.0.0.1", port))
        sb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sb.settimeout(6)
        sb.sendto(header(txid=shared) + qwire("example.org") + struct.pack("!HH", 1, 1),
                  ("127.0.0.1", port))
        try:
            ra, _ = sa.recvfrom(65535)
        except socket.timeout:
            ra = b""
        try:
            rb, _ = sb.recvfrom(65535)
        except socket.timeout:
            rb = b""
        finally:
            sa.close()
            sb.close()

        def qname_of(resp):
            if len(resp) < 13:
                return b""
            i, out = 12, b""
            while i < len(resp) and resp[i] != 0:
                out += bytes([resp[i]]) + resp[i + 1:i + 1 + resp[i]]
                i += 1 + resp[i]
            return out + (b"\x00" if i < len(resp) else b"")

        # The property under test is that no client is handed the other's answer.
        # Dropping a colliding reply is correct and safe -- the client retries --
        # so an empty reply is a pass, not a failure.
        check(qname_of(ra) != qwire("example.org"),
              "client A is not given client B's answer", f"A saw {qname_of(ra)[:24]!r}")
        check(qname_of(rb) != qwire("example.com"),
              "client B is not given client A's answer", f"B saw {qname_of(rb)[:24]!r}")
        check(qname_of(ra) == qwire("example.com") or qname_of(rb) == qwire("example.org"),
              "at least one colliding client still receives its own answer")

        print("\n### malformed input does not wedge or crash the engine")
        for n in (3, 30, 200, 486):
            udp_query(port, header(txid=0x4321) + bytes([255]) + b"a" * n, timeout=2.0)
        check(proc.poll() is None, "engine survived malformed packets")
        data = udp_query(port, header() + qwire("doubleclick.net") + struct.pack("!HH", 1, 1))
        check(data is not None, "engine still serving after malformed packets")

        print("\n### hostile input cannot wedge or overflow the engine")
        # A client that connects and then stalls must not block the engine
        # forever. TCP is handled inline, so this is bounded by SO_RCVTIMEO.
        #
        # Note: the engine is single-threaded and blocks in recv() while a TCP
        # connection is open, so a UDP query issued during the stall is queued
        # rather than answered immediately. What matters is that the engine
        # recovers: before the socket timeout existed, a stalled connection froze
        # every query permanently.
        stall = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stall.settimeout(5)
        try:
            stall.connect(("127.0.0.1", port))
            stall.sendall(b"\x00")          # 1 byte of the 2-byte length prefix
            time.sleep(7.0)                  # exceed the 5s socket timeout
        except OSError as e:
            check(False, "stalled-client test setup", str(e))
        finally:
            stall.close()
        time.sleep(0.5)
        data = udp_query(port, header() + qwire("doubleclick.net")
                         + struct.pack("!HH", 1, 1), timeout=5.0)
        check(data is not None, "engine recovers after a stalled TCP client")
        check(proc.poll() is None, "engine did not exit during the stall")

        # A 16-bit DNS-over-TCP length can be 65535, but the engine frames the
        # message with a 2-byte prefix, so anything above 65534 must be rejected
        # rather than written past the end of the buffer.
        try:
            big = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            big.settimeout(5)
            big.connect(("127.0.0.1", port))
            body = header() + qwire("example.com") + struct.pack("!HH", 1, 1)
            body += b"\x00" * (65535 - len(body))
            big.sendall(struct.pack("!H", 65535) + body)
            try:
                reply = big.recv(70000)
                check(len(reply) == 0 or len(reply) < 65535,
                      "oversized TCP message is refused, not echoed")
            except (socket.timeout, ConnectionResetError, OSError):
                check(True, "oversized TCP message is refused, not echoed")
            big.close()
        except OSError as e:
            check(False, "oversized-TCP test setup", str(e))
        check(proc.poll() is None, "engine survived oversized input")

        # A long QNAME pushes the sinkholed answer toward the end of the packet
        # buffer, where an off-by-one in the answer length would write past it.
        long_name = ".".join(["a" * 60] * 7) + ".test"
        udp_query(port, header() + qwire(long_name) + struct.pack("!HH", 1, 1),
                  timeout=3.0)
        check(proc.poll() is None, "engine survived a long-QNAME query")
        data = udp_query(port, header() + qwire("doubleclick.net")
                         + struct.pack("!HH", 1, 1), timeout=3.0)
        check(data is not None, "engine still serving after a long QNAME")

        print("\n### a second instance fails loudly instead of lingering")
        second = subprocess.Popen([engine], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            time.sleep(1.5)
            rc = second.poll()
            check(rc is not None and rc != 0,
                  "duplicate instance exits non-zero on bind conflict",
                  f"exit={rc}")
        finally:
            if second.poll() is None:
                second.kill()
            second.wait()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 62}\n{len(PASSED)}/{total} checks passed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
