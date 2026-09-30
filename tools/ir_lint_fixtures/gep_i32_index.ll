define void @f(ptr %tv) {
    %o = getelementptr inbounds [16 x i8], ptr %tv, i32 8
    ret void
}
