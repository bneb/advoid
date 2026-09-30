; the shipped bug: +128 bytes, not +8
define void @f(ptr %tv) {
    %o8 = getelementptr inbounds [16 x i8], ptr %tv, i64 8
    ret void
}
