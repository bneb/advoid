define void @f() {
    %o = getelementptr inbounds [16 x i8], ptr @udp_pkt, i64 8
    ret void
}
