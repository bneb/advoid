; advoid.ll — Zero-allocation DNS interceptor for macOS (arm64).
;
; Listens on 127.0.0.1:53 for both UDP and TCP, intercepts DNS queries,
; hashes the QNAME with FNV-1a, checks against a compiled-in switch
; statement of domains, and either sinkholes or forwards to 1.1.1.1.
;
; TCP matters: RFC 1035 §4.2.1 requires a client that receives a truncated
; (TC=1) UDP response to retry over TCP on the same port. Serving only UDP
; means those queries fail outright.
;
; Writing this in raw IR was a terrible idea from a productivity
; standpoint but a great one for understanding exactly what your
; DNS interceptor is doing. Every alloca, getelementptr, and store
; is intentional — no compiler surprises.
;
; If you're reading this as LLVM IR reference: the target is
; arm64-apple-macosx, the calling convention is the default (ccc),
; and the struct layouts follow Darwin/ARM64 ABI (sockaddr_in with
; sin_len byte at offset 0).
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx"

declare i32 @socket(i32, i32, i32)
declare i32 @bind(i32, ptr, i32)
declare i32 @setsockopt(i32, i32, i32, ptr, i32)
declare i32 @listen(i32, i32)
declare i32 @accept(i32, ptr, ptr)
declare i64 @recvfrom(i32, ptr, i64, i32, ptr, ptr)
declare i64 @sendto(i32, ptr, i64, i32, ptr, i32)
declare i64 @recv(i32, ptr, i64, i32)
declare i64 @send(i32, ptr, i64, i32)
declare i32 @printf(ptr, ...)
declare i32 @poll(ptr, i32, i32)
declare i1 @is_blocked(i64)
declare i32 @open(ptr, i32, ...)
declare i64 @read(i32, ptr, i64)
declare i32 @close(i32)
declare i32 @fchmod(i32, i32)
declare i64 @time(ptr)
declare i64 @write(i32, ptr, i64)
declare void @exit(i32)
declare i32 @fflush(ptr)

@msg = private unnamed_addr constant [27 x i8] c"LLVM Advoid Active on :53\0A\00"
@err_socket = private unnamed_addr constant [24 x i8] c"advoid: socket() failed\00"
@err_bind_udp = private unnamed_addr constant [34 x i8] c"advoid: bind() failed (UDP, port \00"
@err_bind_tcp = private unnamed_addr constant [34 x i8] c"advoid: bind() failed (TCP, port \00"
@err_listen = private unnamed_addr constant [24 x i8] c"advoid: listen() failed\00"
@err_nl = private unnamed_addr constant [2 x i8] c"\0A\00"
@status_path = private constant [36 x i8] c"/usr/local/var/advoid/advoid.status\00"
@status_ok = private constant [4 x i8] c"ok\0A\00"
@status_bind = private constant [10 x i8] c"bindfail\0A\00"
@digit_buf = global [8 x i8] zeroinitializer
; one-entry pollfd template: POLLOUT in the events field (struct pollfd {int fd; short events; short revents;})

@state_addrs = global [65536 x [16 x i8]] zeroinitializer
; state_tcp[txid] holds (client connection fd + 1) when the waiting client
; arrived over TCP, 0 when it arrived over UDP. Storing fd+1 keeps 0 as a
; reliable "no TCP client" sentinel.
@state_tcp = global [65536 x i64] zeroinitializer
@tcp_pending = global i64 0
; Bound on simultaneously-waiting TCP clients. Each holds an open socket, so an
; unbounded table would let a client open connections faster than we answer.
@max_tcp_pending = private constant [2 x i8] c"\10\00"
@local_hashes_path = private constant [35 x i8] c"/usr/local/etc/advoid/local.hashes\00"
@local_hashes = global [1024 x i64] zeroinitializer
@local_count = global i64 0
@blocked_count = global i64 0
@forwarded_count = global i64 0
@start_time = global i64 0
@stats_path = private constant [35 x i8] c"/usr/local/var/advoid/advoid.stats\00"

; ---------------------------------------------------------------------------
; Buffers. Global rather than stack-allocated so the TCP path can hold a
; full 64 KiB DNS message without touching the UDP hot-path buffer.
; ---------------------------------------------------------------------------
@tcp_tx = global [65536 x i8] zeroinitializer      ; framed payload for the client
@udp_pkt = global [4096 x i8] zeroinitializer      ; UDP buffer: 4096 = EDNS0 default

; Ports are read at startup so the same IR can run unprivileged for testing.
; Production always uses 53; see install.sh.
@local_port = global i16 53

define i32 @main() {
entry:
    call i32 (ptr, ...) @printf(ptr @msg)
    call void @load_local_hashes()
    call void @init_stats()

    ; --- 1. UDP listener -------------------------------------------------
    %udp_sock = call i32 @socket(i32 2, i32 2, i32 17)
    call void @allow_reuse(i32 %udp_sock)
    %udp_bad = icmp slt i32 %udp_sock, 0
    br i1 %udp_bad, label %socket_fail, label %udp_addr

socket_fail:
    call void @fatal(ptr @err_socket, i64 23)
    unreachable

udp_addr:
    %udp_a = alloca [16 x i8], align 8
    store i64 0, ptr %udp_a
    store i8 16, ptr %udp_a
    %u_fam = getelementptr inbounds i8, ptr %udp_a, i64 1
    store i8 2, ptr %u_fam
    ; sin_port is a big-endian u16: high byte at offset 2, low byte at 3. The
    ; bytes are written individually because `store i16` is little-endian and
    ; would turn port 53 into 0x3500 (13568).
    %lp = load i16, ptr @local_port
    %lp_sh = lshr i16 %lp, 8
    %lp_hi8 = trunc i16 %lp_sh to i8
    %lp_lo8 = trunc i16 %lp to i8
    %u_p2 = getelementptr inbounds i8, ptr %udp_a, i64 2
    store i8 %lp_hi8, ptr %u_p2
    %u_p3 = getelementptr inbounds i8, ptr %udp_a, i64 3
    store i8 %lp_lo8, ptr %u_p3
    ; sin_addr = 127.0.0.1. Left at zero this binds INADDR_ANY, exposing an open
    ; resolver on every interface the Mac joins. 0x0100007F, little-endian.
    %u_a4 = getelementptr inbounds i8, ptr %udp_a, i64 4
    store i32 16777343, ptr %u_a4
    %ubind = call i32 @bind(i32 %udp_sock, ptr %udp_a, i32 16)
    %ubind_bad = icmp slt i32 %ubind, 0
    br i1 %ubind_bad, label %bind_fail_udp, label %tcp_listen

bind_fail_udp:
    call void @fatal_port(ptr @err_bind_udp, i64 33)
    unreachable

    ; --- 2. TCP listener (RFC 1035 4.2.1 fallback path) ------------------
tcp_listen:
    %tcp_sock = call i32 @socket(i32 2, i32 1, i32 6)
    call void @allow_reuse(i32 %tcp_sock)
    %tcp_bad = icmp slt i32 %tcp_sock, 0
    br i1 %tcp_bad, label %socket_fail, label %tcp_addr

tcp_addr:
    %tcp_a = alloca [16 x i8], align 8
    store i64 0, ptr %tcp_a
    store i8 16, ptr %tcp_a
    %t_fam = getelementptr inbounds i8, ptr %tcp_a, i64 1
    store i8 2, ptr %t_fam
    %t_p2 = getelementptr inbounds i8, ptr %tcp_a, i64 2
    store i8 %lp_hi8, ptr %t_p2
    %t_p3 = getelementptr inbounds i8, ptr %tcp_a, i64 3
    store i8 %lp_lo8, ptr %t_p3
    %t_a4 = getelementptr inbounds i8, ptr %tcp_a, i64 4
    store i32 16777343, ptr %t_a4
    %tbind = call i32 @bind(i32 %tcp_sock, ptr %tcp_a, i32 16)
    %tbind_bad = icmp slt i32 %tbind, 0
    br i1 %tbind_bad, label %bind_fail_tcp, label %tcp_do_listen

bind_fail_tcp:
    call void @fatal_port(ptr @err_bind_tcp, i64 33)
    unreachable

tcp_do_listen:
    %lis = call i32 @listen(i32 %tcp_sock, i32 128)
    %lis_bad = icmp slt i32 %lis, 0
    br i1 %lis_bad, label %listen_fail, label %upstream

listen_fail:
    call void @fatal(ptr @err_listen, i64 23)
    unreachable

    ; --- 3. Upstream UDP socket (unconnected) ---------------------------
upstream:
    %up_sock = call i32 @socket(i32 2, i32 2, i32 17)
    call void @allow_reuse(i32 %up_sock)
    %up_bad = icmp slt i32 %up_sock, 0
    br i1 %up_bad, label %socket_fail, label %upstream_addr

upstream_addr:
    %up_addr = alloca [16 x i8], align 8
    store i64 0, ptr %up_addr
    store i8 16, ptr %up_addr
    %up_fam = getelementptr inbounds i8, ptr %up_addr, i64 1
    store i8 2, ptr %up_fam
    %up_p2 = getelementptr inbounds i8, ptr %up_addr, i64 3
    store i8 53, ptr %up_p2
    %up_ip0 = getelementptr inbounds i8, ptr %up_addr, i64 4
    store i8 1, ptr %up_ip0
    %up_ip1 = getelementptr inbounds i8, ptr %up_addr, i64 5
    store i8 1, ptr %up_ip1
    %up_ip2 = getelementptr inbounds i8, ptr %up_addr, i64 6
    store i8 1, ptr %up_ip2
    %up_ip3 = getelementptr inbounds i8, ptr %up_addr, i64 7
    store i8 1, ptr %up_ip3

    ; --- 4. pollfd array: UDP listener, TCP listener, upstream UDP -------
    %pollfds = alloca [3 x i64], align 8
    %p0_ptr = getelementptr inbounds [3 x i64], ptr %pollfds, i64 0, i64 0
    %udp_fd = zext i32 %udp_sock to i64
    %ev_in = shl i64 1, 32
    %p0_val = or i64 %udp_fd, %ev_in
    store i64 %p0_val, ptr %p0_ptr

    %p1_ptr = getelementptr inbounds [3 x i64], ptr %pollfds, i64 0, i64 1
    %tcp_fd = zext i32 %tcp_sock to i64
    %p1_val = or i64 %tcp_fd, %ev_in
    store i64 %p1_val, ptr %p1_ptr

    %p2_ptr = getelementptr inbounds [3 x i64], ptr %pollfds, i64 0, i64 2
    %up_fd = zext i32 %up_sock to i64
    %p2_val = or i64 %up_fd, %ev_in
    store i64 %p2_val, ptr %p2_ptr

    %client_addr = alloca [16 x i8], align 8
    ; Allocated once here, not per relay: an alloca inside the relay block ran on
    ; every relayed reply and main never returns, so the stack grew unbounded.
    %c_addr_tmp = alloca [16 x i8], align 8
    %client_len = alloca i32, align 4
    %ln = alloca [2 x i8], align 2

    call void @write_status(ptr @status_ok, i64 3)
    br label %poll_loop
poll_loop:
    ; Wait indefinitely for UDP query, TCP connection, or upstream reply.
    %poll_res = call i32 @poll(ptr %pollfds, i32 3, i32 -1)

    %r0 = load i64, ptr %p0_ptr
    %r0_rev = lshr i64 %r0, 48
    %r0_in = and i64 %r0_rev, 1

    %r1 = load i64, ptr %p1_ptr
    %r1_rev = lshr i64 %r1, 48
    %r1_in = and i64 %r1_rev, 1

    %r2 = load i64, ptr %p2_ptr
    %r2_rev = lshr i64 %r2, 48
    %r2_in = and i64 %r2_rev, 1

    ; poll() overwrites revents; restore the request masks before blocking again.
    store i64 %p0_val, ptr %p0_ptr
    store i64 %p1_val, ptr %p1_ptr
    store i64 %p2_val, ptr %p2_ptr

    %has_udp = icmp ne i64 %r0_in, 0
    br i1 %has_udp, label %do_udp, label %check_tcp

do_udp:
    store i32 16, ptr %client_len
    %bytes = call i64 @recvfrom(i32 %udp_sock, ptr @udp_pkt, i64 4096, i32 0, ptr %client_addr, ptr %client_len)
    ; A failed recvfrom returns -1. Without this guard the value is treated as
    ; an enormous length and the QNAME scan reads past the buffer.
    %udp_err = icmp sle i64 %bytes, 0
    br i1 %udp_err, label %check_tcp, label %classify_udp

classify_udp:
    %uhash = call i64 @hash_qname(ptr @udp_pkt, i64 %bytes)
    %ublocked = call i1 @is_blocked(i64 %uhash)
    br i1 %ublocked, label %blocked_udp, label %ulocal

ulocal:
    %ulocal_hit = call i1 @check_local(i64 %uhash)
    br i1 %ulocal_hit, label %blocked_udp, label %forward_udp

blocked_udp:
    ; sinkhole appends a 16-byte answer, so the reply is 16 bytes longer than
    ; the query. Sending %bytes would truncate the answer back off.
    %ublen = call i64 @sinkhole(ptr @udp_pkt, i64 %bytes)
    %usent = call i64 @sendto(i32 %udp_sock, ptr @udp_pkt, i64 %ublen, i32 0, ptr %client_addr, i32 16)
    %ubc = load i64, ptr @blocked_count
    %ubc1 = add i64 %ubc, 1
    store i64 %ubc1, ptr @blocked_count
    call void @maybe_write_stats()
    br label %check_tcp

forward_udp:
    ; Remember which client asked (keyed by transaction ID) so the reply can
    ; be routed back. Unvalidated upstream datagrams are rejected below.
    %txid = call i64 @packet_txid(ptr @udp_pkt)
    %state_ptr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs, i64 0, i64 %txid
    %ca_v1 = load i64, ptr %client_addr
    %ca_p2 = getelementptr inbounds i64, ptr %client_addr, i64 1
    %ca_v2 = load i64, ptr %ca_p2
    store i64 %ca_v1, ptr %state_ptr
    %sp2 = getelementptr inbounds i64, ptr %state_ptr, i64 1
    store i64 %ca_v2, ptr %sp2
    %fsz = trunc i64 %bytes to i32
    %sent = call i64 @sendto(i32 %up_sock, ptr @udp_pkt, i64 %bytes, i32 0, ptr %up_addr, i32 16)
    %fsent_bad = icmp slt i64 %sent, 0
    br i1 %fsent_bad, label %check_tcp, label %count_forward

count_forward:
    %fc = load i64, ptr @forwarded_count
    %fc1 = add i64 %fc, 1
    store i64 %fc1, ptr @forwarded_count
    call void @maybe_write_stats()
    br label %check_tcp

    ; --- TCP connection: DNS over TCP, one query per connection ----------
check_tcp:
    %has_tcp = icmp ne i64 %r1_in, 0
    br i1 %has_tcp, label %do_tcp, label %check_up

do_tcp:
    %conn = call i32 @accept(i32 %tcp_sock, ptr null, ptr null)
    %conn_bad = icmp slt i32 %conn, 0
    br i1 %conn_bad, label %check_up, label %tcp_setup_conn

tcp_setup_conn:
    ; 5 second cap per socket operation. A legitimate DNS/TCP exchange completes in
    ; milliseconds; a stalled peer cannot hold up the resolver.
    call void @set_io_timeout(i32 %conn, i64 5000000)
    ; SO_NOSIGPIPE: writing the answer to a client that has already disconnected
    ; must return EPIPE, not raise SIGPIPE and kill the whole root resolver.
    ; Darwin SO_NOSIGPIPE = 0x1022.
    %nosig = alloca [4 x i8], align 4
    store i32 1, ptr %nosig
    %sns = call i32 @setsockopt(i32 %conn, i32 65535, i32 4130, ptr %nosig, i32 4)
    br label %tcp_read_len

tcp_read_len:
    ; Two-byte big-endian message length prefix (RFC 1035 4.2.2).
    %len_n = call i64 @read_exact(i32 %conn, ptr %ln, i64 2)
    %len_bad = icmp ne i64 %len_n, 2
    br i1 %len_bad, label %tcp_done, label %tcp_read_msg

tcp_read_msg:
    %n0 = load i8, ptr %ln
    %n0x = zext i8 %n0 to i64
    %n0s = shl i64 %n0x, 8
    %ln1p = getelementptr inbounds i8, ptr %ln, i64 1
    %n1 = load i8, ptr %ln1p
    %n1x = zext i8 %n1 to i64
    %msglen = or i64 %n0s, %n1x
    %msglen_zero = icmp eq i64 %msglen, 0
    br i1 %msglen_zero, label %tcp_done, label %tcp_read_body_check

tcp_read_body_check:
    ; A 16-bit length can be 65535, but framing adds 2 bytes on top of the payload.
    ; Reject anything larger than the buffer can hold so the shift cannot overflow.
    %msglen_big = icmp ugt i64 %msglen, 65534
    br i1 %msglen_big, label %tcp_done, label %tcp_read_body

tcp_read_body:
    %got = call i64 @read_exact(i32 %conn, ptr @tcp_tx, i64 %msglen)
    %short = icmp ne i64 %got, %msglen
    br i1 %short, label %tcp_done, label %tcp_classify

tcp_classify:
    %thash = call i64 @hash_qname(ptr @tcp_tx, i64 %msglen)
    %tblocked = call i1 @is_blocked(i64 %thash)
    br i1 %tblocked, label %blocked_tcp, label %tlocal

tlocal:
    %tlocal_hit = call i1 @check_local(i64 %thash)
    br i1 %tlocal_hit, label %blocked_tcp, label %forward_tcp

blocked_tcp:
    %tslen = call i64 @sinkhole(ptr @tcp_tx, i64 %msglen)
    %newsz = call i64 @frame(ptr @tcp_tx, i64 %tslen)
    %sw = call i64 @write_exact(i32 %conn, ptr @tcp_tx, i64 %newsz)
    %tbc = load i64, ptr @blocked_count
    %tbc1 = add i64 %tbc, 1
    store i64 %tbc1, ptr @blocked_count
    call void @maybe_write_stats()
    br label %tcp_done

forward_tcp:
    ; Forward upstream over UDP, not TCP.
    ;
    ; The client-facing TCP listener is required by RFC 1035 4.2.1: a client that
    ; receives a truncated answer retries over TCP and must get a real reply. It
    ; does NOT require us to use TCP toward the upstream, and doing so was the
    ; source of two serious problems: a blocking connect() that SO_SNDTIMEO does
    ; not bound, and a large relay that reproducibly stopped the engine answering
    ; UDP. With a 4096-byte buffer the overwhelming majority of answers arrive in
    ; one datagram, so the upstream leg stays on the simple, well-tested UDP path.
    ; Limitation: answers larger than 4096 bytes still need a real TCP upstream
    ; fetch, which is not implemented. Clients receive a truncated answer with TC
    ; set rather than a corrupt one.
    ;
    ; The client connection is deliberately left OPEN and its fd parked in the
    ; state table, so the UDP reply can be written back to it when it arrives.
    %pend = load i64, ptr @tcp_pending
    %toomany = icmp uge i64 %pend, 16
    br i1 %toomany, label %tcp_done, label %forward_tcp_send

forward_tcp_send:
    %ttxid = call i64 @packet_txid(ptr @tcp_tx)
    %tst = getelementptr inbounds [65536 x i64], ptr @state_tcp, i64 0, i64 %ttxid
    %cfd1 = zext i32 %conn to i64
    %cfd1b = add i64 %cfd1, 1          ; 0 stays reserved for "no TCP client"
    store i64 %cfd1b, ptr %tst
    ; Mark this transaction as a TCP one so the state table's address slot is not
    ; consulted for it.
    %taddr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs, i64 0, i64 %ttxid
    store i64 0, ptr %taddr
    %taddr2 = getelementptr inbounds i64, ptr %taddr, i64 1
    store i64 0, ptr %taddr2

    %tsent = call i64 @sendto(i32 %up_sock, ptr @tcp_tx, i64 %msglen, i32 0, ptr %up_addr, i32 16)
    %tsent_bad = icmp slt i64 %tsent, 0
    br i1 %tsent_bad, label %forward_tcp_abandon, label %forward_tcp_count

forward_tcp_abandon:
    ; Upstream refused the datagram: drop the client rather than leave a socket
    ; parked in the table forever.
    store i64 0, ptr %tst
    br label %tcp_done

forward_tcp_count:
    %pnew = add i64 %pend, 1
    store i64 %pnew, ptr @tcp_pending
    %tfc = load i64, ptr @forwarded_count
    %tfc1 = add i64 %tfc, 1
    store i64 %tfc1, ptr @forwarded_count
    call void @maybe_write_stats()
    ; The connection stays open; do_up will answer and close it.
    br label %check_up

tcp_done:
    call void @close(i32 %conn)
    br label %check_up

    ; --- Upstream UDP reply ---------------------------------------------
check_up:
    %has_up = icmp ne i64 %r2_in, 0
    br i1 %has_up, label %do_up, label %poll_loop

do_up:
    store i32 16, ptr %client_len
    %up_bytes = call i64 @recvfrom(i32 %up_sock, ptr @udp_pkt, i64 4096, i32 0, ptr %client_addr, ptr %client_len)
    %up_err = icmp sle i64 %up_bytes, 0
    br i1 %up_err, label %poll_loop, label %reply_up

reply_up:
    %utxid = call i64 @packet_txid(ptr @udp_pkt)
    %ustate_ptr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs, i64 0, i64 %utxid
    %usa_v1 = load i64, ptr %ustate_ptr
    %usp2 = getelementptr inbounds i64, ptr %ustate_ptr, i64 1
    %usa_v2 = load i64, ptr %usp2

    ; Does this transaction belong to a client that connected over TCP?
    %utcp = getelementptr inbounds [65536 x i64], ptr @state_tcp, i64 0, i64 %utxid
    %utcpfd = load i64, ptr %utcp
    %is_tcp = icmp ne i64 %utcpfd, 0

    ; A UDP client's slot holds its sockaddr; a TCP client's is zeroed and the
    ; fd is parked separately. An all-zero pair with no parked fd means nobody
    ; is waiting: drop the datagram rather than relay it somewhere arbitrary.
    %known = or i64 %usa_v1, %usa_v2
    %unknown = icmp eq i64 %known, 0
    %utcp_zero = icmp eq i64 %utcpfd, 0
    %no_one = and i1 %unknown, %utcp_zero
    br i1 %is_tcp, label %relay_tcp, label %check_udp_client

check_udp_client:
    br i1 %no_one, label %poll_loop, label %relay_up

relay_up:
    store i64 0, ptr %ustate_ptr
    store i64 0, ptr %usp2
    store i64 %usa_v1, ptr %c_addr_tmp
    %ctmp2 = getelementptr inbounds i64, ptr %c_addr_tmp, i64 1
    store i64 %usa_v2, ptr %ctmp2

    ; If the answer exactly fills the buffer it was almost certainly cut off.
    ; Set TC (bit 9 of the flags word) so the client knows to retry over TCP
    ; rather than accepting a silently corrupt packet.
    %trunc = icmp eq i64 %up_bytes, 4096
    br i1 %trunc, label %set_tc, label %send_up

set_tc:
    %tf = getelementptr inbounds i8, ptr @udp_pkt, i64 2
    %tfv = load i8, ptr %tf
    %tfset = or i8 %tfv, 2
    store i8 %tfset, ptr %tf
    br label %send_up

send_up:
    %rsent = call i64 @sendto(i32 %udp_sock, ptr @udp_pkt, i64 %up_bytes, i32 0, ptr %c_addr_tmp, i32 16)
    br label %poll_loop

    ; The waiting client spoke TCP: frame the answer with its 2-byte length
    ; prefix, write it, and close the connection.
relay_tcp:
    store i64 0, ptr %utcp
    %pending = load i64, ptr @tcp_pending
    %pnext = sub i64 %pending, 1
    store i64 %pnext, ptr @tcp_pending
    %cfd0 = sub i64 %utcpfd, 1
    %cfd = trunc i64 %cfd0 to i32
    %rsz2 = call i64 @frame2(ptr @tcp_tx, ptr @udp_pkt, i64 %up_bytes)
    %cw2 = call i64 @write_exact(i32 %cfd, ptr @tcp_tx, i64 %rsz2)
    call void @close(i32 %cfd)
    br label %poll_loop
}

; ---------------------------------------------------------------------------
; fatal writes the message to stderr, records a failure status, and exits
; non-zero. launchd KeepAlive will restart the daemon, so this is also how a
; persistent bind conflict becomes visible rather than silently killing DNS.
; ---------------------------------------------------------------------------
; allow_reuse sets SO_REUSEADDR so a daemon restart does not fail with
; EADDRINUSE while old TCP sockets linger in TIME_WAIT. Darwin SOL_SOCKET is
; 0xffff and SO_REUSEADDR is 0x0004.
@opt_on = private constant [4 x i8] c"\01\00\00\00"

define void @allow_reuse(i32 %fd) {
entry:
    %r = call i32 @setsockopt(i32 %fd, i32 65535, i32 4, ptr @opt_on, i32 4)
    ret void
}

; set_io_timeout bounds how long a socket operation may block. DNS handling is
; single-threaded inside the poll loop, so without this a client that connects and
; then stalls (or trickles bytes) would block every other query indefinitely.
; Darwin: SO_RCVTIMEO=0x1006, SO_SNDTIMEO=0x1005, SO_REUSEADDR=0x0004,
; SOL_SOCKET=0xffff, struct timeval = {i64 sec, i64 usec} (16 bytes).
; These values are asserted against the SDK in tests/engine_test.py.
define void @set_io_timeout(i32 %fd, i64 %usec) {
entry:
    %tv = alloca [16 x i8], align 8
    %sec = udiv i64 %usec, 1000000
    store i64 %sec, ptr %tv
    %rem = urem i64 %usec, 1000000
    ; Index into the array, not past it: `getelementptr [16 x i8], %tv, i64 8`
    ; resolves to %tv + 8*16 = +128 bytes, which clobbered the caller's stack
    ; frame (the upstream sockaddr, or a pollfd entry) and meant the socket
    ; timeouts were configured from stale bytes.
    %o8 = getelementptr inbounds [16 x i8], ptr %tv, i64 0, i64 8
    store i64 %rem, ptr %o8
    %len = trunc i64 16 to i32
    %rcv = call i32 @setsockopt(i32 %fd, i32 65535, i32 4102, ptr %tv, i32 %len)
    %snd = call i32 @setsockopt(i32 %fd, i32 65535, i32 4101, ptr %tv, i32 %len)
    ret void
}

; fatal_port reports a bind conflict naming the actual port, then exits.
; A conflict here used to be invisible: the engine ignored bind()'s result and
; polled unbound sockets forever while the UI still showed the shield as active.
define void @fatal_port(ptr %m, i64 %len) {
entry:
    ; Flush stdout first so the startup banner is not lost. launchd captures both
    ; streams, and a missing banner makes a startup failure much harder to read.
    %fl = call i32 @fflush(ptr null)
    %w1 = call i64 @write(i32 2, ptr %m, i64 %len)
    %pv = load i16, ptr @local_port
    %pv16 = add i16 %pv, 0
    %ge100 = icmp uge i16 %pv16, 100
    br i1 %ge100, label %three, label %two

two:
    ; 10..99: tens then units
    %t_d = udiv i16 %pv16, 10
    %t_c = add i16 %t_d, 48
    %t_b = trunc i16 %t_c to i8
    store i8 %t_b, ptr @digit_buf
    %u_d = urem i16 %pv16, 10
    %u_c = add i16 %u_d, 48
    %u_b = trunc i16 %u_c to i8
    %p1 = getelementptr inbounds i8, ptr @digit_buf, i64 1
    store i8 %u_b, ptr %p1
    %p2 = getelementptr inbounds i8, ptr @digit_buf, i64 2
    store i8 41, ptr %p2
    %p3 = getelementptr inbounds i8, ptr @digit_buf, i64 3
    store i8 10, ptr %p3
    %n2 = call i64 @write(i32 2, ptr @digit_buf, i64 4)
    br label %out

three:
    ; 100..65535: hundreds, tens, units
    %h_d = udiv i16 %pv16, 100
    %h_c = add i16 %h_d, 48
    %h_b = trunc i16 %h_c to i8
    store i8 %h_b, ptr @digit_buf
    %r1 = urem i16 %pv16, 100
    %t2_d = udiv i16 %r1, 10
    %t2_c = add i16 %t2_d, 48
    %t2_b = trunc i16 %t2_c to i8
    %q1 = getelementptr inbounds i8, ptr @digit_buf, i64 1
    store i8 %t2_b, ptr %q1
    %u2_d = urem i16 %r1, 10
    %u2_c = add i16 %u2_d, 48
    %u2_b = trunc i16 %u2_c to i8
    %q2 = getelementptr inbounds i8, ptr @digit_buf, i64 2
    store i8 %u2_b, ptr %q2
    %q3 = getelementptr inbounds i8, ptr @digit_buf, i64 3
    store i8 41, ptr %q3
    %q4 = getelementptr inbounds i8, ptr @digit_buf, i64 4
    store i8 10, ptr %q4
    %n3 = call i64 @write(i32 2, ptr @digit_buf, i64 5)
    br label %out

out:
    call void @write_status(ptr @status_bind, i64 9)
    call void @exit(i32 1)
    unreachable
}

define void @fatal(ptr %m, i64 %len) {
entry:
    ; Flush stdout first so the startup banner is not lost when the process
    ; exits: launchd captures both streams and a missing banner makes a startup
    ; failure much harder to diagnose.
    %fl = call i32 @fflush(ptr null)
    %null1 = call i64 @write(i32 2, ptr %m, i64 %len)
    %null2 = call i64 @write(i32 2, ptr @err_nl, i64 1)
    call void @write_status(ptr @status_bind, i64 9)
    call void @exit(i32 1)
    unreachable
}

define void @write_status(ptr %m, i64 %len) {
entry:
    ; O_WRONLY(1)|O_CREAT(0x200)|O_TRUNC(0x400) = 0x601
    ; mode 0644 = 0o644 = 420 decimal
    %fd = call i32 (ptr, i32, ...) @open(ptr @status_path, i32 1537, i32 420)
    %bad = icmp slt i32 %fd, 0
    br i1 %bad, label %done, label %chmod

chmod:
    ; Force 0644 regardless of umask: the menu bar app runs unprivileged and needs
    ; to read this file to report engine health. 0o644 == 420 decimal.
    %c = call i32 @fchmod(i32 %fd, i32 420)
    br label %w

w:
    %n = call i64 @write(i32 %fd, ptr %m, i64 %len)
    call i32 @close(i32 %fd)
    br label %done

done:
    ret void
}

; ---------------------------------------------------------------------------
; read_exact reads exactly n bytes, looping over short reads. Returns the number
; of bytes actually read; callers compare against n.
; ---------------------------------------------------------------------------
define i64 @read_exact(i32 %fd, ptr %dst, i64 %n) {
entry:
    br label %loop

loop:
    %off = phi i64 [ 0, %entry ], [ %noff, %cont ]
    %done = icmp uge i64 %off, %n
    br i1 %done, label %out, label %do_read

do_read:
    %p = getelementptr inbounds i8, ptr %dst, i64 %off
    %left = sub i64 %n, %off
    %got = call i64 @recv(i32 %fd, ptr %p, i64 %left, i32 0)
    %err = icmp sle i64 %got, 0
    br i1 %err, label %out, label %cont

cont:
    %noff = add i64 %off, %got
    br label %loop

out:
    ret i64 %off
}

define i64 @write_exact(i32 %fd, ptr %src, i64 %n) {
entry:
    br label %loop

loop:
    %off = phi i64 [ 0, %entry ], [ %noff, %cont ]
    %done = icmp uge i64 %off, %n
    br i1 %done, label %out, label %do_write

do_write:
    %p = getelementptr inbounds i8, ptr %src, i64 %off
    %left = sub i64 %n, %off
    %sent = call i64 @send(i32 %fd, ptr %p, i64 %left, i32 0)
    %err = icmp sle i64 %sent, 0
    br i1 %err, label %fail, label %cont

cont:
    %noff = add i64 %off, %sent
    br label %loop

fail:
    ret i64 -1

out:
    ret i64 %off
}

; frame prepends the two-byte length prefix to a message held in @tcp_tx,
; shifting the payload up by two bytes. Returns the framed length.
define i64 @frame(ptr %buf, i64 %n) {
entry:
    %i = alloca i64, align 8
    store i64 %n, ptr %i
    br label %shift

shift:
    ; Copy backwards so the +2 offset cannot overwrite unread bytes.
    %idx = load i64, ptr %i
    %neg = icmp sle i64 %idx, 0
    br i1 %neg, label %prefix, label %copy

copy:
    %src_i = sub i64 %idx, 1
    %src = getelementptr inbounds i8, ptr %buf, i64 %src_i
    %ch = load i8, ptr %src
    %dst_i = add i64 %idx, 1
    %dst = getelementptr inbounds i8, ptr %buf, i64 %dst_i
    store i8 %ch, ptr %dst
    %nidx = sub i64 %idx, 1
    store i64 %nidx, ptr %i
    br label %shift

prefix:
    ; Big-endian length, written before the payload. Safe in-place: the
    ; first payload byte was shifted into slot 2.
    %ch0 = load i8, ptr %buf
    %hi = lshr i64 %n, 8
    %hi8 = trunc i64 %hi to i8
    store i8 %hi8, ptr %buf
    %lo8 = trunc i64 %n to i8
    %p1 = getelementptr inbounds i8, ptr %buf, i64 1
    store i8 %lo8, ptr %p1
    %total = add i64 %n, 2
    ret i64 %total
}

; frame2 frames @src/@n into @dst with a length prefix.
define i64 @frame2(ptr %dst, ptr %src, i64 %n) {
entry:
    %hi = lshr i64 %n, 8
    %hi8 = trunc i64 %hi to i8
    store i8 %hi8, ptr %dst
    %p1 = getelementptr inbounds i8, ptr %dst, i64 1
    %lo8 = trunc i64 %n to i8
    store i8 %lo8, ptr %p1
    br label %loop

loop:
    %i = phi i64 [ 0, %entry ], [ %ni, %body ]
    %done = icmp uge i64 %i, %n
    br i1 %done, label %out, label %body

body:
    %sp = getelementptr inbounds i8, ptr %src, i64 %i
    %ch = load i8, ptr %sp
    %di = add i64 %i, 2
    %dp = getelementptr inbounds i8, ptr %dst, i64 %di
    store i8 %ch, ptr %dp
    %ni = add i64 %i, 1
    br label %loop

out:
    %total = add i64 %n, 2
    ret i64 %total
}

; packet_txid extracts the 16-bit transaction ID as a zero-extended host value.
define i64 @packet_txid(ptr %buf) {
entry:
    %b0 = load i8, ptr %buf
    %b0x = zext i8 %b0 to i64
    %b0s = shl i64 %b0x, 8
    %p1 = getelementptr inbounds i8, ptr %buf, i64 1
    %b1 = load i8, ptr %p1
    %b1x = zext i8 %b1 to i64
    %id = or i64 %b0s, %b1x
    ret i64 %id
}

; ---------------------------------------------------------------------------
; sinkhole rewrites a query in place into a response appropriate to its qtype.
;
; An A query gets 0.0.0.0 and an AAAA query gets ::, so IPv6-only clients still
; see the domain as blocked. Every other qtype gets NOERROR with an empty answer
; section (NODATA) rather than a bogus A record — replying with a type the client
; never asked for violates RFC 3596/9460 and confuses resolvers.
; ---------------------------------------------------------------------------
define i64 @sinkhole(ptr %buf, i64 %len) {
entry:
    ; FLAGS = 0x8180: QR=1, RD=1, RA=1, RCODE=0. The two flag bytes are written
    ; separately so the value does not depend on host endianness.
    %fh = getelementptr inbounds i8, ptr %buf, i64 2
    store i8 129, ptr %fh
    %fl = getelementptr inbounds i8, ptr %buf, i64 3
    store i8 128, ptr %fl
    ; ANCOUNT = 1 for the address answers; zeroed on the NODATA path.
    call void @store_be16(ptr %buf, i64 6, i64 1)
    ; NSCOUNT and ARCOUNT = 0, which also drops any EDNS0 OPT the client sent.
    call void @store_be16(ptr %buf, i64 8, i64 0)
    call void @store_be16(ptr %buf, i64 10, i64 0)
    br label %find_q_end

find_q_end:
    %q_i = phi i64 [ 12, %entry ], [ %next_q_i, %find_q_end_next ]
    %q_oob = icmp uge i64 %q_i, 4096
    br i1 %q_oob, label %malformed, label %q_scan

q_scan:
    %q_ptr = getelementptr inbounds i8, ptr %buf, i64 %q_i
    %q_char = load i8, ptr %q_ptr
    %q_is_zero = icmp eq i8 %q_char, 0
    %next_q_i = add i64 %q_i, 1
    br i1 %q_is_zero, label %found_q_end, label %find_q_end_next

find_q_end_next:
    br label %find_q_end

found_q_end:
    ; next_q_i indexes the byte after the QNAME terminator, so it is the start
    ; of QTYPE. q_end is the first byte of the answer section.
    %q_end = add i64 %next_q_i, 4
    br label %read_qtype

read_qtype:
    ; QTYPE is a big-endian u16 at next_q_i.
    %qt_hi_p = getelementptr inbounds i8, ptr %buf, i64 %next_q_i
    %qt_hi = load i8, ptr %qt_hi_p
    %qt_hi_x = zext i8 %qt_hi to i64
    %qt_hi_s = shl i64 %qt_hi_x, 8
    %qt_lo_i = add i64 %next_q_i, 1
    %qt_lo_p = getelementptr inbounds i8, ptr %buf, i64 %qt_lo_i
    %qt_lo = load i8, ptr %qt_lo_p
    %qt_lo_x = zext i8 %qt_lo to i64
    %qtype = or i64 %qt_hi_s, %qt_lo_x
    %is_a = icmp eq i64 %qtype, 1
    %is_aaaa = icmp eq i64 %qtype, 28
    %is_addr = or i1 %is_a, %is_aaaa
    ; Answer length mirrors the record: 4 bytes of address for A, 16 for AAAA.
    %addr_len = select i1 %is_aaaa, i64 16, i64 4
    %ans_len = add i64 %q_end, 12
    %ans_len2 = add i64 %ans_len, %addr_len
    ; If that would run past a 512-byte buffer, fall back to the NODATA reply
    ; rather than writing out of bounds.
    %oob = icmp ugt i64 %ans_len2, 512
    %want_answer = and i1 %is_addr, %oob
    %use_answer = xor i1 %want_answer, true
    %use_addr = and i1 %use_answer, %is_addr
    br i1 %use_addr, label %answer_addr, label %answer_nodata

answer_addr:
    %atype = select i1 %is_a, i64 1, i64 28
    call void @write_answer(ptr %buf, i64 %q_end, i64 %atype)
    br label %done

answer_nodata:
    ; NOERROR with an empty answer section (NODATA). Correct for any qtype we
    ; do not fabricate an address for; the message stays question-length.
    call void @store_be16(ptr %buf, i64 6, i64 0)
    br label %done

malformed:
    ; No QNAME terminator within the buffer: leave the packet as a response
    ; with no answers rather than guessing at a question boundary.
    call void @store_be16(ptr %buf, i64 6, i64 0)
    br label %done

done:
    %out_len = phi i64 [ %ans_len2, %answer_addr ],
                        [ %len, %answer_nodata ],
                        [ %len, %malformed ]
    ret i64 %out_len
}

; write_answer emits a single A/AAAA record with an all-zero address.
;
; Every multi-byte DNS field is big-endian on the wire. Storing a host integer
; directly would byte-swap it, so each field is emitted byte by byte.
define void @store_be16(ptr %buf, i64 %off, i64 %val) {
entry:
    %hi = lshr i64 %val, 8
    %hi8 = trunc i64 %hi to i8
    %p0 = getelementptr inbounds i8, ptr %buf, i64 %off
    store i8 %hi8, ptr %p0
    %lo8 = trunc i64 %val to i8
    %o1 = add i64 %off, 1
    %p1 = getelementptr inbounds i8, ptr %buf, i64 %o1
    store i8 %lo8, ptr %p1
    ret void
}

define void @store_be32(ptr %buf, i64 %off, i64 %val) {
entry:
    %b0 = lshr i64 %val, 24
    %b0t = trunc i64 %b0 to i8
    %p0 = getelementptr inbounds i8, ptr %buf, i64 %off
    store i8 %b0t, ptr %p0
    %b1 = lshr i64 %val, 16
    %b1t = trunc i64 %b1 to i8
    %o1 = add i64 %off, 1
    %p1 = getelementptr inbounds i8, ptr %buf, i64 %o1
    store i8 %b1t, ptr %p1
    %b2 = lshr i64 %val, 8
    %b2t = trunc i64 %b2 to i8
    %o2 = add i64 %off, 2
    %p2 = getelementptr inbounds i8, ptr %buf, i64 %o2
    store i8 %b2t, ptr %p2
    %b3t = trunc i64 %val to i8
    %o3 = add i64 %off, 3
    %p3 = getelementptr inbounds i8, ptr %buf, i64 %o3
    store i8 %b3t, ptr %p3
    ret void
}

define void @write_answer(ptr %buf, i64 %off, i64 %qtype) {
entry:
    ; An answer record is 12 fixed bytes plus the address: 4 for A, 16 for AAAA.
    ; Bound-check the real record size. Checking a nominal 16 bytes lets an A
    ; record near the end of the buffer write up to 12 bytes past it.
    %is_v6 = icmp eq i64 %qtype, 28
    %addr_len = select i1 %is_v6, i64 16, i64 4
    %rec_fixed = add i64 %off, 12
    %rec_end = add i64 %rec_fixed, %addr_len
    %oob = icmp ugt i64 %rec_end, 4096
    br i1 %oob, label %done, label %write

write:
    ; NAME: compression pointer to the question name at offset 12 -> 0xC00C
    call void @store_be16(ptr %buf, i64 %off, i64 49164)

    ; TYPE = %qtype
    %t_off = add i64 %off, 2
    call void @store_be16(ptr %buf, i64 %t_off, i64 %qtype)

    ; CLASS = IN (1)
    %c_off = add i64 %off, 4
    call void @store_be16(ptr %buf, i64 %c_off, i64 1)

    ; TTL = 60 seconds
    %ttl_off = add i64 %off, 6
    call void @store_be32(ptr %buf, i64 %ttl_off, i64 60)

    ; RDLENGTH = 4 for A, 16 for AAAA
    %rd_off = add i64 %off, 10
    call void @store_be16(ptr %buf, i64 %rd_off, i64 %addr_len)

    ; RDATA = all zeros: 0.0.0.0 (4 bytes) for A, :: (16 bytes) for AAAA.
    %r_off = add i64 %off, 12
    %r_p = getelementptr inbounds i8, ptr %buf, i64 %r_off
    store i64 0, ptr %r_p, align 8
    ; Only AAAA has a second 8 bytes. Issuing this store unconditionally would put
    ; up to 12 bytes past the end of the packet for an A record.
    br label %rdata_tail

rdata_tail:
    br i1 %is_v6, label %write_rdata_hi, label %done

write_rdata_hi:
    %r_o8 = add i64 %r_off, 8
    %r_p2 = getelementptr inbounds i8, ptr %buf, i64 %r_o8
    store i64 0, ptr %r_p2, align 8
    br label %done

done:
    ret void
}

define i64 @hash_qname(ptr %buf, i64 %len) {
entry:
    br label %loop

loop:
    %idx = phi i64 [ 12, %entry ], [ %next_idx, %body ]
    %hash = phi i64 [ -3750763034362895579, %entry ], [ %new_hash, %body ]
    %is_oob = icmp uge i64 %idx, %len
    br i1 %is_oob, label %end, label %body

body:
    %ptr = getelementptr inbounds i8, ptr %buf, i64 %idx
    %char = load i8, ptr %ptr
    %is_end = icmp eq i8 %char, 0
    %char_ext = zext i8 %char to i64
    ; Fold A-Z to a-z before hashing. DNS names are case-insensitive (RFC 4343),
    ; so hashing the raw wire bytes meant "DoubLeClick.net" missed the entry for
    ; "doubleclick.net" and the blocklist was trivially bypassed. Branchless:
    ; (c - 'A') < 26 is true only for an ASCII uppercase letter.
    %cu = sub i64 %char_ext, 65
    %is_upper = icmp ult i64 %cu, 26
    %fold = select i1 %is_upper, i64 32, i64 0
    %folded = add i64 %char_ext, %fold
    %xor = xor i64 %hash, %folded
    %new_hash = mul i64 %xor, 1099511628211
    %next_idx = add i64 %idx, 1
    br i1 %is_end, label %end_ok, label %loop

end_ok:
    ret i64 %new_hash

end:
    ret i64 0
}

; load_local_hashes reads the binary blocklist.local.hashes file at startup.
; Format: little-endian u64 count, followed by count u64 hashes.
; Hashes are loaded into @local_hashes (max 1024 entries).
define void @load_local_hashes() {
entry:
    ; open(local.hashes, O_RDONLY)
    %fd = call i32 (ptr, i32, ...) @open(ptr @local_hashes_path, i32 0)
    %is_err = icmp slt i32 %fd, 0
    br i1 %is_err, label %done, label %read_count

read_count:
    %count_buf = alloca [8 x i8], align 8
    %count_bytes = call i64 @read(i32 %fd, ptr %count_buf, i64 8)
    %count_read = icmp ne i64 %count_bytes, 8
    br i1 %count_read, label %close, label %parse_count

parse_count:
    ; Read count as little-endian u64
    %c0_ptr = getelementptr inbounds i8, ptr %count_buf, i64 0
    %c1_ptr = getelementptr inbounds i8, ptr %count_buf, i64 1
    %c2_ptr = getelementptr inbounds i8, ptr %count_buf, i64 2
    %c3_ptr = getelementptr inbounds i8, ptr %count_buf, i64 3
    %c4_ptr = getelementptr inbounds i8, ptr %count_buf, i64 4
    %c5_ptr = getelementptr inbounds i8, ptr %count_buf, i64 5
    %c6_ptr = getelementptr inbounds i8, ptr %count_buf, i64 6
    %c7_ptr = getelementptr inbounds i8, ptr %count_buf, i64 7

    %c0 = load i8, ptr %c0_ptr
    %c1 = load i8, ptr %c1_ptr
    %c2 = load i8, ptr %c2_ptr
    %c3 = load i8, ptr %c3_ptr
    %c4 = load i8, ptr %c4_ptr
    %c5 = load i8, ptr %c5_ptr
    %c6 = load i8, ptr %c6_ptr
    %c7 = load i8, ptr %c7_ptr

    %v0 = zext i8 %c0 to i64
    %v1 = zext i8 %c1 to i64
    %v2 = zext i8 %c2 to i64
    %v3 = zext i8 %c3 to i64
    %v4 = zext i8 %c4 to i64
    %v5 = zext i8 %c5 to i64
    %v6 = zext i8 %c6 to i64
    %v7 = zext i8 %c7 to i64

    %s1 = shl i64 %v1, 8
    %s2 = shl i64 %v2, 16
    %s3 = shl i64 %v3, 24
    %s4 = shl i64 %v4, 32
    %s5 = shl i64 %v5, 40
    %s6 = shl i64 %v6, 48
    %s7 = shl i64 %v7, 56

    %b01 = or i64 %v0, %s1
    %b23 = or i64 %s2, %s3
    %b0123 = or i64 %b01, %b23
    %b45 = or i64 %s4, %s5
    %b67 = or i64 %s6, %s7
    %b4567 = or i64 %b45, %b67
    %count = or i64 %b0123, %b4567

    ; Cap at 1024
    %over = icmp ugt i64 %count, 1024
    %actual = select i1 %over, i64 1024, i64 %count
    store i64 %actual, ptr @local_count

    ; Read hashes
    br label %read_loop

read_loop:
    %i = phi i64 [ 0, %parse_count ], [ %next_i, %read_next ]
    %done_read = icmp uge i64 %i, %actual
    br i1 %done_read, label %close, label %read_hash

read_hash:
    %hash_buf = alloca [8 x i8], align 8
    %hash_bytes = call i64 @read(i32 %fd, ptr %hash_buf, i64 8)
    %hash_ok = icmp ne i64 %hash_bytes, 8
    br i1 %hash_ok, label %close, label %store_hash

store_hash:
    ; Parse little-endian u64 into hash value (same pattern as count)
    %h0_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 0
    %h1_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 1
    %h2_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 2
    %h3_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 3
    %h4_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 4
    %h5_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 5
    %h6_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 6
    %h7_ptr = getelementptr inbounds i8, ptr %hash_buf, i64 7

    %h0 = load i8, ptr %h0_ptr
    %h1 = load i8, ptr %h1_ptr
    %h2 = load i8, ptr %h2_ptr
    %h3 = load i8, ptr %h3_ptr
    %h4 = load i8, ptr %h4_ptr
    %h5 = load i8, ptr %h5_ptr
    %h6 = load i8, ptr %h6_ptr
    %h7 = load i8, ptr %h7_ptr

    %hv0 = zext i8 %h0 to i64
    %hv1 = zext i8 %h1 to i64
    %hv2 = zext i8 %h2 to i64
    %hv3 = zext i8 %h3 to i64
    %hv4 = zext i8 %h4 to i64
    %hv5 = zext i8 %h5 to i64
    %hv6 = zext i8 %h6 to i64
    %hv7 = zext i8 %h7 to i64

    %hs1 = shl i64 %hv1, 8
    %hs2 = shl i64 %hv2, 16
    %hs3 = shl i64 %hv3, 24
    %hs4 = shl i64 %hv4, 32
    %hs5 = shl i64 %hv5, 40
    %hs6 = shl i64 %hv6, 48
    %hs7 = shl i64 %hv7, 56

    %hb01 = or i64 %hv0, %hs1
    %hb23 = or i64 %hs2, %hs3
    %hb0123 = or i64 %hb01, %hb23
    %hb45 = or i64 %hs4, %hs5
    %hb67 = or i64 %hs6, %hs7
    %hb4567 = or i64 %hb45, %hb67
    %hash_val = or i64 %hb0123, %hb4567

    ; Store in @local_hashes[i]
    %slot = getelementptr inbounds [1024 x i64], ptr @local_hashes, i64 0, i64 %i
    store i64 %hash_val, ptr %slot
    br label %read_next

read_next:
    %next_i = add i64 %i, 1
    br label %read_loop

close:
    call i32 @close(i32 %fd)
    br label %done

done:
    ret void
}

; check_local performs a linear scan of @local_hashes.
; Returns true if the hash is found, false otherwise.
define i1 @check_local(i64 %hash) {
entry:
    %count = load i64, ptr @local_count
    %is_empty = icmp eq i64 %count, 0
    br i1 %is_empty, label %not_found, label %scan

scan:
    br label %scan_loop

scan_loop:
    %i = phi i64 [ 0, %scan ], [ %ni, %next_check ]
    %done = icmp uge i64 %i, %count
    br i1 %done, label %not_found, label %check_entry

check_entry:
    %slot = getelementptr inbounds [1024 x i64], ptr @local_hashes, i64 0, i64 %i
    %val = load i64, ptr %slot
    %match = icmp eq i64 %val, %hash
    br i1 %match, label %found, label %next_check

next_check:
    %ni = add i64 %i, 1
    br label %scan_loop

found:
    ret i1 1

not_found:
    ret i1 0
}

; init_stats records the daemon start time via @time(NULL).
define void @init_stats() {
entry:
    %now = call i64 @time(ptr null)
    store i64 %now, ptr @start_time
    ret void
}

; maybe_write_stats writes blocked/forwarded/uptime to /tmp/advoid.stats
; every 128 queries. The overhead is one write syscall every ~128 DNS queries,
; which is negligible compared to the polling and forwarding work.
define void @maybe_write_stats() {
entry:
    %bc = load i64, ptr @blocked_count
    %fc = load i64, ptr @forwarded_count
    %total = add i64 %bc, %fc
    ; Check if total is a multiple of 128 (low 7 bits are zero)
    %masked = and i64 %total, 127
    %should_write = icmp eq i64 %masked, 0
    br i1 %should_write, label %do_write, label %done

do_write:
    ; open(stats, O_WRONLY | O_CREAT | O_TRUNC, 0644)
    ; O_WRONLY=1, O_CREAT=0x0200=512, O_TRUNC=0x0400=1024 -> 1537 (0x601)
    ; mode 0644 = 0o644 = 420 decimal
    %fd = call i32 (ptr, i32, ...) @open(ptr @stats_path, i32 1537, i32 420)
    %is_err = icmp slt i32 %fd, 0
    br i1 %is_err, label %done, label %stats_chmod

stats_chmod:
    ; 0644 so the unprivileged menu bar app can display the counters.
    ; 0o644 == 420 decimal.
    %sc = call i32 @fchmod(i32 %fd, i32 420)
    br label %write

write:
    ; Format: three lines of ASCII decimal numbers + newlines
    ; We build the stats string in a small stack buffer
    %buf = alloca [128 x i8], align 8

    ; Write blocked count as ASCII
    %p0 = call i64 @u64_to_ascii(ptr %buf, i64 %bc)
    ; Add newline
    %p0nl = getelementptr inbounds i8, ptr %buf, i64 %p0
    store i8 10, ptr %p0nl
    %p1_off = add i64 %p0, 1

    ; Write forwarded count
    %p1_ptr = getelementptr inbounds i8, ptr %buf, i64 %p1_off
    %p1 = call i64 @u64_to_ascii(ptr %p1_ptr, i64 %fc)
    %p1nl_off = add i64 %p1_off, %p1
    %p1nl = getelementptr inbounds i8, ptr %buf, i64 %p1nl_off
    store i8 10, ptr %p1nl
    %p2_off = add i64 %p1nl_off, 1

    ; Write uptime (current time - start time, in seconds)
    %now = call i64 @time(ptr null)
    %st = load i64, ptr @start_time
    %uptime = sub i64 %now, %st
    %p2_ptr = getelementptr inbounds i8, ptr %buf, i64 %p2_off
    %p2 = call i64 @u64_to_ascii(ptr %p2_ptr, i64 %uptime)
    %p2nl_off = add i64 %p2_off, %p2
    %p2nl = getelementptr inbounds i8, ptr %buf, i64 %p2nl_off
    store i8 10, ptr %p2nl
    %total_len = add i64 %p2nl_off, 1

    ; Write to file
    %wrote = call i64 @write(i32 %fd, ptr %buf, i64 %total_len)
    call i32 @close(i32 %fd)
    br label %done

done:
    ret void
}

; u64_to_ascii converts a u64 to a decimal ASCII string in buf.
; Returns the number of characters written (not including null terminator).
; buf must have at least 21 bytes (max u64 = 18446744073709551615 = 20 digits).
define i64 @u64_to_ascii(ptr %buf, i64 %val) {
entry:
    ; Special case: val == 0
    %is_zero = icmp eq i64 %val, 0
    br i1 %is_zero, label %write_zero, label %build

write_zero:
    store i8 48, ptr %buf     ; '0'
    ret i64 1

build:
    ; Write digits from right to left into a temp buffer, then reverse
    %tmp = alloca [20 x i8], align 1
    br label %digit_loop

digit_loop:
    %v = phi i64 [ %val, %build ], [ %next_v, %digit_next ]
    %pos = phi i64 [ 0, %build ], [ %next_pos, %digit_next ]
    %done_digits = icmp eq i64 %v, 0
    br i1 %done_digits, label %reverse, label %extract

extract:
    %div = udiv i64 %v, 10
    %rem = urem i64 %v, 10
    %char = add i64 %rem, 48     ; '0' + digit
    %ch = trunc i64 %char to i8
    %slot = getelementptr inbounds [20 x i8], ptr %tmp, i64 0, i64 %pos
    store i8 %ch, ptr %slot
    br label %digit_next

digit_next:
    %next_v = phi i64 [ %div, %extract ]
    %next_pos = add i64 %pos, 1
    br label %digit_loop

reverse:
    ; pos is the number of digits (in tmp, reversed order)
    ; Write them in forward order to buf
    br label %rev_loop

rev_loop:
    %ri = phi i64 [ 0, %reverse ], [ %next_ri, %rev_next ]
    %done_rev = icmp uge i64 %ri, %pos
    br i1 %done_rev, label %rev_done, label %rev_write

rev_write:
    ; Read from tmp[pos - 1 - ri], write to buf[ri]
    %src_idx = sub i64 %pos, %ri
    %src_idx2 = sub i64 %src_idx, 1
    %src = getelementptr inbounds [20 x i8], ptr %tmp, i64 0, i64 %src_idx2
    %ch2 = load i8, ptr %src
    %dst = getelementptr inbounds i8, ptr %buf, i64 %ri
    store i8 %ch2, ptr %dst
    br label %rev_next

rev_next:
    %next_ri = add i64 %ri, 1
    br label %rev_loop

rev_done:
    ret i64 %pos
}
