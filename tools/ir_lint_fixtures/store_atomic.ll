define void @f(ptr %p) {
    store atomic i16 33152, ptr %p seq_cst, align 2
    ret void
}
