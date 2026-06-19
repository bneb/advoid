; advoid.ll — Zero-allocation DNS interceptor for macOS (arm64).
;
; Binds to 127.0.0.1:53, intercepts UDP DNS queries, hashes the QNAME
; with FNV-1a, checks against a compiled-in switch statement of ~150k
; domains, and either sinkholes (0.0.0.0) or forwards to 1.1.1.1.
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
declare i64 @recvfrom(i32, ptr, i64, i32, ptr, ptr)
declare i64 @sendto(i32, ptr, i64, i32, ptr, i32)
declare i32 @printf(ptr, ...)
declare i32 @poll(ptr, i32, i32)
declare i1 @is_blocked(i64)
declare i32 @open(ptr, i32, ...)
declare i64 @read(i32, ptr, i64)
declare i32 @close(i32)
declare i64 @time(ptr)
declare i64 @write(i32, ptr, i64)

@msg = private unnamed_addr constant [27 x i8] c"LLVM Advoid Active on :53\0A\00"
@state_addrs = global [65536 x [16 x i8]] zeroinitializer
@local_hashes_path = private constant [35 x i8] c"/usr/local/etc/advoid/local.hashes\00"
@local_hashes = global [1024 x i64] zeroinitializer
@local_count = global i64 0
@blocked_count = global i64 0
@forwarded_count = global i64 0
@start_time = global i64 0
@stats_path = private constant [18 x i8] c"/tmp/advoid.stats\00"

define i32 @main() {
entry:
    call i32 (ptr, ...) @printf(ptr @msg)
    call void @load_local_hashes()
    call void @init_stats()

    ; 1. Local socket
    %local_sock = call i32 @socket(i32 2, i32 2, i32 17)
    %local_addr = alloca [16 x i8], align 8
    store i64 0, ptr %local_addr
    store i8 16, ptr %local_addr
    %fam = getelementptr inbounds i8, ptr %local_addr, i64 1
    store i8 2, ptr %fam
    %port1 = getelementptr inbounds i8, ptr %local_addr, i64 2
    store i8 0, ptr %port1
    %port2 = getelementptr inbounds i8, ptr %local_addr, i64 3
    store i8 53, ptr %port2
    call i32 @bind(i32 %local_sock, ptr %local_addr, i32 16)

    ; 2. Upstream socket
    %up_sock = call i32 @socket(i32 2, i32 2, i32 17)
    %up_addr = alloca [16 x i8], align 8
    store i64 0, ptr %up_addr
    store i8 16, ptr %up_addr
    %u_fam = getelementptr inbounds i8, ptr %up_addr, i64 1
    store i8 2, ptr %u_fam
    %u_port2 = getelementptr inbounds i8, ptr %up_addr, i64 3
    store i8 53, ptr %u_port2
    %u_ip0 = getelementptr inbounds i8, ptr %up_addr, i64 4
    store i8 1, ptr %u_ip0
    %u_ip1 = getelementptr inbounds i8, ptr %up_addr, i64 5
    store i8 1, ptr %u_ip1
    %u_ip2 = getelementptr inbounds i8, ptr %up_addr, i64 6
    store i8 1, ptr %u_ip2
    %u_ip3 = getelementptr inbounds i8, ptr %up_addr, i64 7
    store i8 1, ptr %u_ip3

    ; 3. pollfd array
    %pollfds = alloca [2 x i64], align 8
    
    %p0_ptr = getelementptr inbounds [2 x i64], ptr %pollfds, i64 0, i64 0
    %p0_fd_64 = zext i32 %local_sock to i64
    %p0_ev = shl i64 1, 32
    %p0_val = or i64 %p0_fd_64, %p0_ev
    store i64 %p0_val, ptr %p0_ptr

    %p1_ptr = getelementptr inbounds [2 x i64], ptr %pollfds, i64 0, i64 1
    %p1_fd_64 = zext i32 %up_sock to i64
    %p1_ev = shl i64 1, 32
    %p1_val = or i64 %p1_fd_64, %p1_ev
    store i64 %p1_val, ptr %p1_ptr

    %buf = alloca [512 x i8], align 8
    %client_addr = alloca [16 x i8], align 8
    %client_len = alloca i32, align 4

    br label %poll_loop

poll_loop:
    ; Wait indefinitely
    %poll_res = call i32 @poll(ptr %pollfds, i32 2, i32 -1)
    
    ; Reset pollfds revents to 0 before processing
    %p0_res = load i64, ptr %p0_ptr
    %p0_rev = lshr i64 %p0_res, 48
    %p0_in = and i64 %p0_rev, 1
    
    %p1_res = load i64, ptr %p1_ptr
    %p1_rev = lshr i64 %p1_res, 48
    %p1_in = and i64 %p1_rev, 1
    
    ; Clear revents from array so poll doesn't break
    store i64 %p0_val, ptr %p0_ptr
    store i64 %p1_val, ptr %p1_ptr

    %has_local = icmp ne i64 %p0_in, 0
    br i1 %has_local, label %do_local, label %check_up

do_local:
    store i32 16, ptr %client_len
    %bytes = call i64 @recvfrom(i32 %local_sock, ptr %buf, i64 512, i32 0, ptr %client_addr, ptr %client_len)
    %hash = call i64 @hash_qname(ptr %buf, i64 %bytes)
    %blocked = call i1 @is_blocked(i64 %hash)
    br i1 %blocked, label %sinkhole, label %check_local_lbl

check_local_lbl:
    %blocked_local = call i1 @check_local(i64 %hash)
    br i1 %blocked_local, label %sinkhole, label %forward

sinkhole:
    %f16 = getelementptr inbounds i8, ptr %buf, i64 2
    store i16 32897, ptr %f16, align 2
    %a32 = getelementptr inbounds i8, ptr %buf, i64 6
    store i32 256, ptr %a32, align 2
    %ar16 = getelementptr inbounds i8, ptr %buf, i64 10
    store i16 0, ptr %ar16, align 2
    br label %find_q_end

find_q_end:
    %q_i = phi i64 [ 12, %sinkhole ], [ %next_q_i, %find_q_end_next ]
    ; Bounds check: stop scanning at 512 bytes (DNS UDP max)
    %q_oob = icmp uge i64 %q_i, 512
    br i1 %q_oob, label %check_up, label %q_scan

q_scan:
    %q_ptr = getelementptr inbounds i8, ptr %buf, i64 %q_i
    %q_char = load i8, ptr %q_ptr
    %q_is_zero = icmp eq i8 %q_char, 0
    %next_q_i = add i64 %q_i, 1
    br i1 %q_is_zero, label %found_q_end, label %find_q_end_next

find_q_end_next:
    br label %find_q_end

found_q_end:
    %q_end = add i64 %next_q_i, 4
    %tail64_1 = getelementptr inbounds i8, ptr %buf, i64 %q_end
    store i64 1099528408256, ptr %tail64_1, align 8
    %q_end_8 = add i64 %q_end, 8
    %tail64_2 = getelementptr inbounds i8, ptr %buf, i64 %q_end_8
    store i64 67124224, ptr %tail64_2, align 8
    
    %new_sz = add i64 %q_end, 16
    call i64 @sendto(i32 %local_sock, ptr %buf, i64 %new_sz, i32 0, ptr %client_addr, i32 16)
    %bc = load i64, ptr @blocked_count
    %bc_next = add i64 %bc, 1
    store i64 %bc_next, ptr @blocked_count
    call void @maybe_write_stats()
    br label %check_up

forward:
    %tx0 = load i8, ptr %buf
    %tx1_ptr = getelementptr inbounds i8, ptr %buf, i64 1
    %tx1 = load i8, ptr %tx1_ptr
    %tx0_16 = zext i8 %tx0 to i16
    %tx1_16 = zext i8 %tx1 to i16
    %tx1_shl = shl i16 %tx1_16, 8
    %txid = or i16 %tx0_16, %tx1_shl
    %txid_64 = zext i16 %txid to i64
    
    %state_ptr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs, i64 0, i64 %txid_64
    %ca_v1 = load i64, ptr %client_addr
    %ca_p2 = getelementptr inbounds i64, ptr %client_addr, i64 1
    %ca_v2 = load i64, ptr %ca_p2
    store i64 %ca_v1, ptr %state_ptr
    %sp2 = getelementptr inbounds i64, ptr %state_ptr, i64 1
    store i64 %ca_v2, ptr %sp2
    
    call i64 @sendto(i32 %up_sock, ptr %buf, i64 %bytes, i32 0, ptr %up_addr, i32 16)
    %fc = load i64, ptr @forwarded_count
    %fc_next = add i64 %fc, 1
    store i64 %fc_next, ptr @forwarded_count
    call void @maybe_write_stats()
    br label %check_up

check_up:
    %has_up = icmp ne i64 %p1_in, 0
    br i1 %has_up, label %do_up, label %poll_loop

do_up:
    %up_len = alloca i32
    store i32 16, ptr %up_len
    %up_bytes = call i64 @recvfrom(i32 %up_sock, ptr %buf, i64 512, i32 0, ptr %up_addr, ptr %up_len)
    
    %utx0 = load i8, ptr %buf
    %utx1_ptr = getelementptr inbounds i8, ptr %buf, i64 1
    %utx1 = load i8, ptr %utx1_ptr
    %utx0_16 = zext i8 %utx0 to i16
    %utx1_16 = zext i8 %utx1 to i16
    %utx1_shl = shl i16 %utx1_16, 8
    %utxid = or i16 %utx0_16, %utx1_shl
    %utxid_64 = zext i16 %utxid to i64
    
    %ustate_ptr = getelementptr inbounds [65536 x [16 x i8]], ptr @state_addrs, i64 0, i64 %utxid_64
    %usa_v1 = load i64, ptr %ustate_ptr
    %usp2 = getelementptr inbounds i64, ptr %ustate_ptr, i64 1
    %usa_v2 = load i64, ptr %usp2
    
    %c_addr_tmp = alloca [16 x i8], align 8
    store i64 %usa_v1, ptr %c_addr_tmp
    %ctmp2 = getelementptr inbounds i64, ptr %c_addr_tmp, i64 1
    store i64 %usa_v2, ptr %ctmp2
    
    call i64 @sendto(i32 %local_sock, ptr %buf, i64 %up_bytes, i32 0, ptr %c_addr_tmp, i32 16)
    br label %poll_loop
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
    %xor = xor i64 %hash, %char_ext
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
    ; open(blocklist.local.hashes, O_RDONLY)
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
    ; open("/tmp/advoid.stats", O_WRONLY | O_CREAT | O_TRUNC, 0644)
    ; O_WRONLY=1, O_CREAT=0x0200=512, O_TRUNC=0x0400=1024 → 1537 (0x601)
    %fd = call i32 (ptr, i32, ...) @open(ptr @stats_path, i32 1537, i32 420)
    %is_err = icmp slt i32 %fd, 0
    br i1 %is_err, label %done, label %write

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
