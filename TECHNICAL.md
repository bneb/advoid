# How Advoid Works: A DNS Adblocker in Pure LLVM IR

The binary that intercepts every DNS query on my Mac is ~550 lines of LLVM Intermediate Representation. No C. No Rust. No standard library. Just raw IR, POSIX syscalls, and a 150,000-case `switch` statement.

Here's how it works — from the socket layer up through FNV-1a hashing to in-place packet mutation — with the actual IR.

## Table of Contents

1. [Why LLVM IR?](#why-llvm-ir)
2. [The Build Pipeline](#the-build-pipeline)
3. [Socket Setup — Building sockaddr_in by Hand](#socket-setup)
4. [The poll() Event Loop](#the-poll-event-loop)
5. [DNS Packet Parsing & FNV-1a Hashing](#dns-packet-parsing)
6. [The 150,000-Case Switch Statement](#the-switch-statement)
7. [Sinkhole: Mutating a DNS Response In-Place](#sinkhole)
8. [Forwarding: State Tracking by Transaction ID](#forwarding)
9. [The Complete Data Flow](#complete-data-flow)

---

## Why LLVM IR?

A DNS adblocker's hot path is simple: read a packet, hash a domain name, check a blocklist, respond. That path should be fast and predictable — no malloc, no GC pauses, no syscalls beyond the socket ops.

You could write this in C. But C gives you the C abstract machine — the compiler is free to optimize within the bounds of the standard, and you don't control exactly what hits the CPU. I wanted to know what instructions were running on every query.

Writing it in IR means every `load`, `store`, and `getelementptr` is intentional.

The IR enforces constraints that C can't express at the source level:

- **No heap.** Every buffer is `alloca` (stack) or a global array. There is no `malloc` anywhere in the binary. If you grep the IR for `malloc`, you get nothing.
- **Fixed memory layout.** The `sockaddr_in` struct for binding is laid out byte by byte. The DNS response is constructed by writing precomputed constants at known offsets. You know exactly what's in memory at every point.
- **No hidden control flow.** The only branches are the ones in the IR. No C++ exceptions, no longjmp, no runtime dispatch.

The obvious tradeoff: it only runs on `arm64-apple-macosx`. That's fine for a tool that only exists for one platform. Portability wasn't a goal — understanding the full stack was.

---

## The Build Pipeline

Before diving into the engine, understand how the pieces fit together:

```
StevenBlack/hosts (HTTP)
        │
        ▼
compile_blocklist.go          ← Go: fetches, parses, hashes, emits
        │
        ▼
blocklist.ll                   ← Auto-generated LLVM IR switch statement
        │
        ├─── advoid.ll ────────┤  (engine)
        │                      │
        ▼                      ▼
    llvm-link → final.ll       ← Linked IR module
        │
        ▼
    llc -O0 → final.o          ← Compiled to object file
        │
        ▼
    clang → advoid-engine      ← Linked binary
```

The blocklist compiler (`compile_blocklist.go`) fetches the StevenBlack unified hosts file, extracts ~150,000 domains, computes their FNV-1a 64-bit hashes, and emits `blocklist.ll` — a single `switch` statement. The engine (`advoid.ll`) declares `@is_blocked(i64)` and calls it. `llvm-link` stitches them together, then `llc` and `clang` produce the final binary.

This means the blocklist is **compiled in** — there's no runtime list loading, no hash table construction at startup, no dynamic allocations for the blocklist at all. The LLVM `switch` becomes a jump table or binary decision tree at the compiler's discretion.

---

## Socket Setup

The engine begins in `@main`. Its first job: create two UDP sockets — one to listen on the loopback interface, one to forward queries upstream to Cloudflare.

### The Local Socket (lines 23–34)

```llvm
%local_sock = call i32 @socket(i32 2, i32 2, i32 17)
```

`socket(2, 2, 17)` is `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`. The constants are used directly — no `#define` needed when you control the IR. This returns a file descriptor.

Next, it builds a `sockaddr_in` on the stack. On macOS (and BSD-derived systems), this is a 16-byte struct:

```
Offset  Size  Field
0       1     sin_len    = 16
1       1     sin_family = AF_INET (2)
2       2     sin_port   = 53 (big-endian)
4       4     sin_addr   = 0.0.0.0 (INADDR_ANY)
8       8     sin_zero   = 0 (padding)
```

In the IR, this is laid out byte by byte:

```llvm
%local_addr = alloca [16 x i8], align 8
store i64 0, ptr %local_addr          ; zero all 16 bytes first
store i8 16, ptr %local_addr          ; sin_len = 16
%fam = getelementptr inbounds i8, ptr %local_addr, i64 1
store i8 2, ptr %fam                  ; sin_family = AF_INET
%port1 = getelementptr inbounds i8, ptr %local_addr, i64 2
store i8 0, ptr %port1               ; port high byte = 0
%port2 = getelementptr inbounds i8, ptr %local_addr, i64 3
store i8 53, ptr %port2              ; port low byte = 53
```

`port = 0 * 256 + 53 = 53` in big-endian. The `store i64 0` at the start zeroes the entire 16-byte struct (since 8 bytes of zeroes at offset 0 and aligned allocation handles the rest), so `sin_addr` is implicitly `0.0.0.0` and `sin_zero` is cleared. Then `bind()` attaches the socket to `127.0.0.1:53`.

### The Upstream Socket (lines 36–52)

The upstream socket is similar, but with a specific IP address:

```llvm
%up_sock = call i32 @socket(i32 2, i32 2, i32 17)
%up_addr = alloca [16 x i8], align 8
store i64 0, ptr %up_addr
store i8 16, ptr %up_addr
; ... family and port as before ...
%u_ip0 = getelementptr inbounds i8, ptr %up_addr, i64 4
store i8 1, ptr %u_ip0    ; 1.
%u_ip1 = getelementptr inbounds i8, ptr %up_addr, i64 5
store i8 1, ptr %u_ip1    ; 1.
%u_ip2 = getelementptr inbounds i8, ptr %up_addr, i64 6
store i8 1, ptr %u_ip2    ; 1.
%u_ip3 = getelementptr inbounds i8, ptr %up_addr, i64 7
store i8 1, ptr %u_ip3    ; 1  → 1.1.1.1 (Cloudflare)
```

This socket isn't `bind()`ed — it doesn't need a local address. It's only used for `sendto` and `recvfrom` to Cloudflare's public DNS resolver.

---

## The poll() Event Loop

The engine uses `poll()` to wait on both sockets simultaneously. poll() takes an array of `struct pollfd`, each of which is two 64-bit values on 64-bit systems:

```
struct pollfd {
    int   fd;      // file descriptor (lower 32 bits of first i64)
    short events;   // requested events (bits 32-47)
    short revents;  // returned events (bits 48-63)
};
```

Advoid packs these manually into an `[2 x i64]` array:

```llvm
%pollfds = alloca [2 x i64], align 8

; Entry 0: local socket
%p0_ptr = getelementptr inbounds [2 x i64], ptr %pollfds, i64 0, i64 0
%p0_fd_64 = zext i32 %local_sock to i64      ; fd in lower 32 bits
%p0_ev = shl i64 1, 32                        ; POLLIN = 1, shifted to events field
%p0_val = or i64 %p0_fd_64, %p0_ev           ; combine fd | (POLLIN << 32)
store i64 %p0_val, ptr %p0_ptr

; Entry 1: upstream socket (same pattern)
%p1_ptr = getelementptr inbounds [2 x i64], ptr %pollfds, i64 0, i64 1
; ...
store i64 %p1_val, ptr %p1_ptr
```

Then the main loop:

```llvm
poll_loop:
    %poll_res = call i32 @poll(ptr %pollfds, i32 2, i32 -1)
    ;                                            nfds=2    timeout=-1 (block forever)
```

After `poll()` returns, the engine checks `revents` (bits 48-63 of each pollfd entry) for `POLLIN` (bit 0 of revents). It extracts the field by shifting right 48 bits and masking:

```llvm
%p0_res = load i64, ptr %p0_ptr
%p0_rev = lshr i64 %p0_res, 48    ; shift revents down to bit 0
%p0_in = and i64 %p0_rev, 1        ; mask POLLIN
```

Then it clears revents (restoring the original fd+events value) so the next `poll()` call sees a clean array:

```llvm
store i64 %p0_val, ptr %p0_ptr
store i64 %p1_val, ptr %p1_ptr
```

If the local socket has data (`%has_local`), it reads and processes a DNS query. If the upstream socket has data (`%has_up`), it relays a response back to the original client. If neither, it loops back to `poll_loop`.

---

## DNS Packet Parsing

### Extracting the Transaction ID

When a DNS query arrives on the local socket, the engine reads it into a 512-byte stack buffer:

```llvm
%buf = alloca [512 x i8], align 8
; ...
%bytes = call i64 @recvfrom(i32 %local_sock, ptr %buf, i64 512, i32 0,
                            ptr %client_addr, ptr %client_len)
```

The first 12 bytes of a DNS message are the header:

```
Offset  Size  Field
0       2     Transaction ID (TXID)
2       2     Flags
4       2     Questions count
6       2     Answer RRs
8       2     Authority RRs
10      2     Additional RRs
```

The transaction ID is extracted later (in the forward path) by loading the first two bytes and reconstructing a 16-bit integer:

```llvm
%tx0 = load i8, ptr %buf              ; low byte of TXID
%tx1_ptr = getelementptr inbounds i8, ptr %buf, i64 1
%tx1 = load i8, ptr %tx1_ptr          ; high byte of TXID
%tx0_16 = zext i8 %tx0 to i16
%tx1_16 = zext i8 %tx1 to i16
%tx1_shl = shl i16 %tx1_16, 8
%txid = or i16 %tx0_16, %tx1_shl      ; reconstruct big-endian u16
```

This TXID is used to track which client made which query, so responses can be routed back correctly.

### FNV-1a Hashing the QNAME

The domain name in a DNS query starts at byte 12 (after the header). DNS encodes names as a sequence of length-prefixed labels: `3www6google3com0` for `www.google.com`. The `@hash_qname` function walks this encoding and computes a 64-bit FNV-1a hash.

FNV-1a works by XORing each byte into the hash, then multiplying by a prime:

```
hash = FNV_offset_basis
for each byte:
    hash ^= byte
    hash *= FNV_prime
```

In the Go blocklist compiler, the hash operates on the DNS wire format — each label is hashed with its length byte prepended, matching exactly what appears in a UDP packet. The LLVM IR implementation mirrors this:

```llvm
define i64 @hash_qname(ptr %buf, i64 %len) {
entry:
    br label %loop

loop:
    %idx = phi i64 [ 12, %entry ], [ %next_idx, %body ]
    %hash = phi i64 [ -3750763034362895579, %entry ], [ %new_hash, %body ]
    ;                     ^-- FNV offset basis (0xcbf29ce484222325) as signed i64
    %is_oob = icmp uge i64 %idx, %len
    br i1 %is_oob, label %end, label %body

body:
    %ptr = getelementptr inbounds i8, ptr %buf, i64 %idx
    %char = load i8, ptr %ptr
    %is_end = icmp eq i8 %char, 0
    %char_ext = zext i8 %char to i64
    %xor = xor i64 %hash, %char_ext
    %new_hash = mul i64 %xor, 1099511628211   ; FNV prime (0x100000001b3)
    %next_idx = add i64 %idx, 1
    br i1 %is_end, label %end_ok, label %loop

end_ok:
    ret i64 %new_hash

end:
    ret i64 0    ; OOB guard: return 0 (will miss the blocklist → allowed)
}
```

The loop starts at byte 12 (past the DNS header), loads each byte, XORs and multiplies, and stops when it hits a null byte (the end of the QNAME). The result is a 64-bit hash that matches exactly what the Go compiler computed for the same domain — enabling a deterministic lookup in the compiled blocklist.

FNV-1a was chosen because it's simple to implement in both Go and LLVM IR (one XOR, one multiply per byte) and the 64-bit output space is large enough that collisions across 150,000 domains aren't a practical concern. No need for a cryptographic hash — this isn't security-sensitive, it's just a lookup key.

---

## The 150,000-Case Switch Statement

`blocklist.ll`, generated by the Go compiler, contains a single function:

```llvm
define i1 @is_blocked(i64 %hash) {
entry:
  switch i64 %hash, label %allow [
    i64 -8573641234567890123, label %block
    i64 2345678901234567890, label %block
    i64 -3456789012345678901, label %block
    ; ... ~150,000 more entries ...
  ]

block:
  ret i1 1     ; true — domain is blocked

allow:
  ret i1 0     ; false — domain is allowed
}
```

This is the entire blocklist. No hash table, no binary search, no trie — just an LLVM `switch` statement.

LLVM's code generator transforms this into whatever is optimal for the target: a jump table for dense clusters of hash values, a balanced binary decision tree for sparse regions, or a hybrid. On ARM64 macOS, `llc` typically produces a combination — jump tables where hash density is high, compare-and-branch chains elsewhere. The result is effectively O(1) or O(log n) lookup with no memory allocations and no pointer chasing beyond the instruction stream itself.

The Go compiler ensures each domain is hashed exactly once — duplicate hashes are collapsed in the `map[uint64]struct{}` before emission. A safelist of critical domains (`localhost`, `github.com`, `apple.com`, `icloud.com`) is also hashed and filtered out, protecting the system from denial-of-service if the upstream StevenBlack list is ever compromised.

---

## Sinkhole: Mutating a DNS Response In-Place

When `@is_blocked` returns `true`, the engine doesn't allocate a new buffer for the response. Instead, it mutates the original query packet in-place, transforming it into a valid DNS response that points the blocked domain to `0.0.0.0`.

Here's what needs to change in the DNS header and body:

```
Original query packet (28+ bytes):
  [0-1]   TXID         (preserved)
  [2-3]   Flags        → set to 0x8085 (standard response, NXDOMAIN)
  [4-5]   QDCOUNT      (preserved = 1)
  [6-7]   ANCOUNT      → set to 1 (we're adding an answer)
  [8-9]   NSCOUNT      (preserved = 0)
  [10-11] ARCOUNT      → set to 0
  [12+]   Question section (preserved — we skip over it)
  ...     Answer section (appended — see below)
```

The mutation in IR:

```llvm
sinkhole:
    ; Write flags + counts as packed stores
    %f16 = getelementptr inbounds i8, ptr %buf, i64 2
    store i16 32897, ptr %f16, align 2
    ; 32897 = 0x8085 (big-endian i16)
    ; Byte 2: 0x80 (QR=1, OPCODE=0, AA=0, TC=0, RD=1)
    ; Byte 3: 0x85 (RA=0, Z=0, RCODE=5 = refused)

    %a32 = getelementptr inbounds i8, ptr %buf, i64 6
    store i32 256, ptr %a32, align 2
    ; 256 = 0x00000100 (big-endian i32)
    ; Byte 6-7: ANCOUNT = 1
    ; Byte 8-9: NSCOUNT = 0

    %ar16 = getelementptr inbounds i8, ptr %buf, i64 10
    store i16 0, ptr %ar16, align 2
    ; ARCOUNT = 0
```

Then it finds the end of the question section (scanning for the null terminator of the QNAME, then skipping the 4-byte QTYPE+QCLASS), and appends an A record pointing to `0.0.0.0`:

```llvm
found_q_end:
    %q_end = add i64 %next_q_i, 4
    ; q_end now points past: QNAME + '\0' + QTYPE(2) + QCLASS(2)

    ; Write a compressed NAME pointer (0xc00c → "pointer to offset 12")
    %tail64_1 = getelementptr inbounds i8, ptr %buf, i64 %q_end
    store i64 1099528408256, ptr %tail64_1, align 8
    ; This writes 8 bytes encoding:
    ;   0xc00c = compressed name pointer (points back to the question's QNAME)
    ;   0x0001 = TYPE A
    ;   0x0001 = CLASS IN
    ;   0x0000 = TTL (high bytes, 0)

    ; Write TTL low bytes, RDLENGTH, and RDATA
    %q_end_8 = add i64 %q_end, 8
    %tail64_2 = getelementptr inbounds i8, ptr %buf, i64 %q_end_8
    store i64 67124224, ptr %tail64_2, align 8
    ; This writes 8 bytes encoding:
    ;   0x0000 = TTL (remaining, total TTL = 0)
    ;   0x0004 = RDLENGTH (4 bytes of RDATA)
    ;   0x0000 = first 2 bytes of 0.0.0.0
    ;   0x0000 = last 2 bytes of 0.0.0.0

    %new_sz = add i64 %q_end, 16
    call i64 @sendto(i32 %local_sock, ptr %buf, i64 %new_sz, i32 0,
                     ptr %client_addr, i32 16)
```

Instead of writing response fields one at a time, the engine packs several fields into each `i64` store. The constants `1099528408256` and `67124224` are precomputed — when stored at the right offsets, they lay out a valid DNS resource record in memory. Six instructions, and the answer section is done.

The resulting packet is a valid DNS response that any resolver will interpret as "this domain resolves to 0.0.0.0." The client gets its answer in microseconds, and the ad is blocked.

---

## Forwarding: State Tracking by Transaction ID

When `@is_blocked` returns `false`, the query is forwarded to Cloudflare (`1.1.1.1`). But when the response comes back, the engine needs to know which client to send it to — it can't just broadcast to everyone who's ever made a query.

Advoid solves this with a fixed-size state table, keyed by the DNS transaction ID:

```llvm
@state_addrs = global [65536 x [16 x i8]] zeroinitializer
```

This is a 1 MB global array (65536 entries × 16 bytes each) mapping TXIDs to client `sockaddr_in` structures. Since DNS TXIDs are 16-bit, the table covers every possible ID.

When forwarding:

```llvm
forward:
    ; Extract TXID (as described above) → %txid
    %txid_64 = zext i16 %txid to i64

    ; Store client address in state_addrs[txid]
    %state_ptr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs,
                 i64 0, i64 %txid_64
    %ca_v1 = load i64, ptr %client_addr          ; first 8 bytes of client addr
    %ca_p2 = getelementptr inbounds i64, ptr %client_addr, i64 1
    %ca_v2 = load i64, ptr %ca_p2                ; next 8 bytes
    store i64 %ca_v1, ptr %state_ptr
    %sp2 = getelementptr inbounds i64, ptr %state_ptr, i64 1
    store i64 %ca_v2, ptr %sp2

    ; Forward the query upstream
    call i64 @sendto(i32 %up_sock, ptr %buf, i64 %bytes, i32 0,
                     ptr %up_addr, i32 16)
```

When the upstream response arrives, the engine extracts the TXID from the response, looks up the original client address, and relays:

```llvm
do_up:
    ; Read response from upstream
    %up_bytes = call i64 @recvfrom(i32 %up_sock, ptr %buf, i64 512, i32 0,
                                    ptr %up_addr, ptr %up_len)

    ; Extract TXID from the response
    ; ... (same pattern as forward path) ...

    ; Look up original client address
    %ustate_ptr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs,
                  i64 0, i64 %utxid_64
    %usa_v1 = load i64, ptr %ustate_ptr
    %usp2 = getelementptr inbounds i64, ptr %ustate_ptr, i64 1
    %usa_v2 = load i64, ptr %usp2

    ; Reconstruct client sockaddr_in on the stack
    %c_addr_tmp = alloca [16 x i8], align 8
    store i64 %usa_v1, ptr %c_addr_tmp
    %ctmp2 = getelementptr inbounds i64, ptr %c_addr_tmp, i64 1
    store i64 %usa_v2, ptr %ctmp2

    ; Send response back to the original client
    call i64 @sendto(i32 %local_sock, ptr %buf, i64 %up_bytes, i32 0,
                     ptr %c_addr_tmp, i32 16)
```

This is a simple but effective state machine. The 65536-entry table is allocated once at program start (in BSS) and never freed. TXID collisions (a new query reusing an ID before the old response arrives) are handled implicitly — the old entry is overwritten, and if the old response arrives late, it goes to the new client, which is harmless (the client ignores unexpected TXIDs).

---

## Complete Data Flow

Putting it all together, here's the path a DNS query takes through the engine:

```
1. macOS sends DNS query to 127.0.0.1:53
       │
       ▼
2. poll() wakes on %local_sock (POLLIN)
       │
       ▼
3. recvfrom() reads raw UDP packet into %buf (512 bytes, stack)
       │
       ▼
4. @hash_qname() walks the QNAME starting at %buf[12],
   computes FNV-1a hash byte by byte
       │
       ▼
5. @is_blocked(hash) — the 150k-case switch statement
       │
       ├── blocked ──────────────────────────────────────┐
       │                                                  │
       │   6a. Mutate %buf in-place:                      │
       │       - Store i16 0x8085 at offset 2 (flags)     │
       │       - Store i32 0x00000100 at offset 6 (counts)│
       │       - Store i16 0x0000 at offset 10 (ARCOUNT)  │
       │       - Find end of question section             │
       │       - Append compressed A record → 0.0.0.0     │
       │   7a. sendto() the modified packet back          │
       │       to the original client                     │
       │                                                  │
       ├── allowed ──────────────────────────────────────┤
       │                                                  │
       │   6b. Store client_addr in state_addrs[TXID]     │
       │   7b. sendto() original query to 1.1.1.1:53      │
       │                                                  │
       │   ... later, when upstream responds ...          │
       │                                                  │
       │   8b. poll() wakes on %up_sock (POLLIN)          │
       │   9b. recvfrom() reads response from 1.1.1.1     │
       │   10b. Extract TXID, load client_addr from       │
       │        state_addrs[TXID]                         │
       │   11b. sendto() response back to original client │
       │                                                  │
       └──────────────────────────────────────────────────┘
       │
       ▼
   poll_loop (wait for next packet)
```

No heap allocations. No dynamic dispatch. No runtime type information. Just syscalls, integer arithmetic, and carefully packed structs on the stack — processing DNS packets at whatever speed the kernel delivers them.

---

## What You End Up With

~550 lines of IR, compiled down to a binary that's a few hundred kilobytes. At runtime: ~1 MB of memory (mostly the `state_addrs` table for tracking DNS transaction IDs). Zero allocations per query. Blocked responses go out in the time it takes to hash a domain name and execute a computed branch.

It's not the most featureful DNS adblocker, or the most portable, or the easiest to modify. But every instruction that executes is something you can point to and explain. For a tool that sees every DNS query your machine makes, I find that reassuring.
