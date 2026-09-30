# Design references

Executable sketches for roadmap items that have not been ported yet. These are
**not** part of `verify.sh` and are not compiled by CI; they exist so the next
attempt starts from working code rather than from prose.

## `s11_wait_loop_model.c` — S1.1 cooperative TCP wait loop

The intended fix for S1.1: stop servicing an accepted connection to completion
inside the poll loop. Instead poll the connection and the UDP listener together
in short slices, read the connection non-blocking, and drop it on an absolute
deadline.

This is the third rewrite of this area. The first two are at
`/tmp/v2/candidate_pollfd_fixed.ll` (8/10 hostile but regressing behaviour) and
`/tmp/v2/s34_partial.ll`. **Porting this model to IR is the next step for S1.1,
not starting a fourth design.**

Method note: replicating the engine's exact syscall sequence in C and running it
outside the engine is what found S2.2's root cause (Darwin returns EISCONN when
`sendto()` is given a destination on a connected socket). Do the same here before
writing IR.
