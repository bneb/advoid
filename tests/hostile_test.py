#!/usr/bin/env python3
"""Hostile-input regression tests for the Advoid engine.

These are the failure modes that have actually been reported or reasoned about, and
each must FAIL against a build that still has the defect. Run against an engine
built on a high port:

    ADVOID_TEST_PORT=5333 python3 tests/hostile_test.py ./advoid-engine

Exit status 0 means every hostile case is handled.
"""
import os
import socket
import struct
import subprocess
import sys
import time

PORT = int(os.environ.get("ADVOID_TEST_PORT", "5333"))
ADDR = ("127.0.0.1", PORT)

PASS, FAIL = [], []


def check(cond, label, detail=""):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  -- {detail}" if detail else ""))


def qwire(name):
    out = b""
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def hdr(txid=0x1234, flags=0x0100, qd=1, ar=0):
    return struct.pack("!HHHHHH", txid, flags, qd, 0, 0, ar)


def udp_blocked(txid=0x0001, timeout=2.0):
    """A query the engine can answer entirely locally -- no upstream involved.

    Using a blocked name isolates the engine from network conditions: if this does
    not come back promptly, the engine itself is stuck, not the internet.
    """
    pkt = hdr(txid) + qwire("doubleclick.net") + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ADDR)
        d, _ = s.recvfrom(4096)
        return len(d) > 0
    except socket.timeout:
        return False
    finally:
        s.close()


def main():
    if len(sys.argv) < 2:
        print("usage: hostile_test.py <engine>", file=sys.stderr)
        return 2
    engine = os.path.abspath(sys.argv[1])
    if not os.access(engine, os.X_OK):
        print(f"not executable: {engine}", file=sys.stderr)
        return 2

    proc = subprocess.Popen([engine], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        if proc.poll() is not None:
            print("engine exited during startup")
            return 1
        if not udp_blocked():
            print("engine is not answering on the expected port")
            return 1

        # ---------------------------------------------------------------------
        print("\n### a TCP client that trickles bytes must not stall the resolver")
        # SO_RCVTIMEO is per-recv(), so a peer that sends a byte often enough to
        # reset that timer never trips it. Before the fix this held the poll loop
        # for as long as the peer cared to keep it there.
        trickle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        trickle.settimeout(5)
        trickle.connect(ADDR)
        # Announce a large message, then deliver it a byte at a time.
        body = hdr(0x2222) + qwire("example.com") + struct.pack("!HH", 1, 1)
        trickle.sendall(struct.pack("!H", 200) + body[:1])
        time.sleep(0.3)
        for _ in range(3):
            try:
                trickle.sendall(b"\x00")
            except OSError:
                break
            time.sleep(1.6)          # under the 5 s per-recv timeout

        ok = udp_blocked(txid=0x0002, timeout=2.0)
        check(ok, "UDP query still answered while a TCP client trickles bytes",
              "" if ok else "resolver is blocked by the slow client")
        trickle.close()
        time.sleep(0.5)

        # ---------------------------------------------------------------------
        print("\n### a TCP client that declares a huge message and sends nothing")
        # Must be dropped by an absolute deadline, not held until the client
        # disconnects. The declared length is what the client asked for.
        idle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        idle.settimeout(5)
        idle.connect(ADDR)
        idle.sendall(struct.pack("!H", 65534))     # promise 65534 bytes...
        time.sleep(1.0)                            # ...deliver none
        t0 = time.time()
        ok = udp_blocked(txid=0x0003, timeout=2.0)
        took = time.time() - t0
        check(ok, "UDP query answered while a TCP client declares 65534 bytes",
              "" if ok else "blocked")
        check(took < 2.0, "and answered promptly, not after a long stall",
              f"{took:.2f}s")
        idle.close()
        time.sleep(0.5)

        # ---------------------------------------------------------------------
        print("\n### many stalled clients at once")
        socks = []
        try:
            for i in range(4):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(ADDR)
                s.sendall(struct.pack("!H", 400) + b"\x00")
                socks.append(s)
            time.sleep(0.5)
            ok = udp_blocked(txid=0x0004, timeout=2.0)
            check(ok, "UDP unaffected with four stalled TCP clients",
                  "" if ok else "resolver blocked by concurrent stalls")
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

        # ---------------------------------------------------------------------
        print("\n### a client that disconnects mid-query must not kill the engine")
        # Writing the answer to a closed socket raises SIGPIPE unless suppressed.
        for attempt in range(3):
            r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))   # abortive close -> RST
            r.settimeout(5)
            r.connect(ADDR)
            r.sendall(struct.pack("!H", 0) + hdr(0x3333) + qwire("example.com")
                      + struct.pack("!HH", 1, 1))
            time.sleep(0.3)
            r.close()                                 # vanish before the answer
        time.sleep(1.0)
        check(proc.poll() is None, "engine survived abrupt client disconnects",
              "process died" if proc.poll() is not None else "")
        ok = udp_blocked(txid=0x0005, timeout=2.0)
        check(ok, "UDP still answered after abrupt disconnects")

        # ---------------------------------------------------------------------
        print("\n### listener must not accept traffic for the LAN")
        # The engine binds 127.0.0.1 only. Reaching it on a routable address would
        # make the Mac an open resolver on every network it joins.
        lan = None
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("10.255.255.255", 1))
            lan = probe.getsockname()[0]
            probe.close()
        except OSError:
            pass
        if not lan or lan.startswith("127."):
            print("  [SKIP] no non-loopback address available to test with")
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            try:
                s.sendto(hdr(0x4444) + qwire("doubleclick.net")
                         + struct.pack("!HH", 1, 1), (lan, PORT))
                d, _ = s.recvfrom(4096)
                check(False, f"engine does not answer on the LAN address {lan}",
                      f"{len(d)}B returned -- it is an open resolver")
            except socket.timeout:
                check(True, f"engine does not answer on the LAN address {lan}")
            except OSError:
                check(True, f"engine does not answer on the LAN address {lan}")
            finally:
                s.close()

        check(proc.poll() is None, "engine still alive at the end")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    total = len(PASS) + len(FAIL)
    print(f"\n{'=' * 62}\n{len(PASS)}/{total} hostile-input checks passed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())