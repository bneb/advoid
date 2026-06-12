; mac-hole.ll
; advoid.ll implements the zero-allocation packet interceptor.
; It binds to loopback port 53, intercepts raw UDP datagrams, extracts the QNAME,
; and invokes the external is_blocked hash function for real-time traffic filtering.
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx"

declare i32 @socket(i32, i32, i32)
declare i32 @bind(i32, ptr, i32)
declare i64 @recvfrom(i32, ptr, i64, i32, ptr, ptr)
declare i64 @sendto(i32, ptr, i64, i32, ptr, i32)
declare i32 @printf(ptr, ...)
declare i32 @poll(ptr, i32, i32)
declare i1 @is_blocked(i64)

@msg = private unnamed_addr constant [29 x i8] c"LLVM Mac-Hole Active on :53\0A\00"
@state_addrs = global [65536 x [16 x i8]] zeroinitializer

define i32 @main() {
entry:
    call i32 (ptr, ...) @printf(ptr @msg)
    
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
    br i1 %blocked, label %sinkhole, label %forward

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
