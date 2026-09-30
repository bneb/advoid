define void @good(ptr %tv, ptr %buf) {
    ; correct: two-index form addresses byte 8
    %o8 = getelementptr inbounds [16 x i8], ptr %tv, i64 0, i64 8
    ; correct: zero fill is byte-order independent
    store i64 0, ptr %buf
    ; correct: bytes emitted individually
    store i8 129, ptr %buf
    %p1 = getelementptr inbounds i8, ptr %buf, i64 1
    store i8 128, ptr %p1
    ; index 0 into an array is the base address either way
    %z = getelementptr inbounds [16 x i8], ptr %tv, i64 0
    ret void
}
