define void @f(ptr %p) {
    store volatile i16 33152, ptr %p, align 2
    ret void
}
