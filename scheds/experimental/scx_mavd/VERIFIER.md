# Verifier constraints in scx_mavd

scx_mavd is scx_lavd converted to the cid form of sched_ext, with its CPU
masks and contexts in a BPF arena. Two verifier limits shaped the code.
This file records the measurements behind the resulting `__noinline`
boundaries and behind the loops that stay on `bpf_for()`, so the choices
can be checked rather than trusted.

Environment: kernel branch `mavd-debug` in the sched_ext tree, which is
sched_ext/for-next f6e1fb3c45b3 plus "bpf: Keep generic __uninit kfunc
arguments live" (bpf-next has fc670d4b6c31 for the same problem, not yet
in for-next); clang 22.1.8; libbpf 1.7.0; loaded in a 16-CPU QEMU guest
with two threads per core.

## The combined stack limit

check_max_stack_depth() walks every call chain of a program, adds each
subprog's stack depth rounded up to 16 bytes under the JIT, and rejects
the program when a chain exceeds MAX_BPF_STACK, 512 bytes:

    combined stack size of 5 calls is 528. Too large

A subprog's depth is the deepest stack access the verifier saw in it.
Scratch whose lifetime ended before a deeper call still counts: the frame
is a per-subprog maximum, not a per-path one.

## The picker chain

The idle picker runs from both ops.select_cid() and ops.enqueue(). Its
deepest chain reaches the distributed mask scan six frames down:

    lavd_select_cid         152 -> 160
    pick_idle_cpu           136 -> 144
    migrate_to_neighbor      80 ->  80
    pick_idle_cpu_at_cpdom    8 ->  16
    pick_idle_cid             8 ->  16
    scan_idle_cids           96 ->  96
                                   512

The left column is the deepest r10 offset in the emitted object, the right
one the rounded frame the verifier adds. From lavd_enqueue() the same chain
models at 528 because that program's own frame is 176, yet it loads; see
"Model versus verifier" below.

## Why the boundaries exist

lavd declares its picker helpers `static __always_inline`. In the cid form
their bodies are arena word loops that need more scratch, and with every
helper inlined the verifier rejected lavd_select_cid with the message
quoted above: five frames, 528 bytes. A plain `static` function with one
caller is inlined by clang at the optimization level used, so dropping
the annotation is the same as `__always_inline` here. `__noinline` is the
only way to keep a frame boundary.

Three boundaries hold the chain at 512. Removing any one of them from the
current object, by the model in tools/stack-chains.py:

- The four mask preparation helpers in pick_idle_cpu(): init_idle_i_mask,
  init_ao_masks, repartition_masks_for_latency and init_idle_ato_masks.
  Inlined, pick_idle_cpu()'s frame grows from 136 to 152 bytes, rounded
  to 160, and the chain is 528.
- scan_idle_cids() in pick_idle_cid(), a wrapper around the distributed
  scan. Inlined, pick_idle_cid() carries the scan's 96 bytes while it
  calls claim_idle_cid(), and the chain is 576.
- init_cpdom_mask() in pick_idle_cpu_at_cpdom(), three mask intersections.
  Open-coded, that frame grows from 8 to 88 bytes, and the chain is 592.

Out of line, these helpers are leaves or shallow, so their frames never
stack with the scan's and the chain's maximum does not see them.

## Model versus verifier

tools/stack-chains.py reads `llvm-objdump -dr` output, takes each
function's deepest r10 offset, rounds it to 16, resolves call edges from
relocations and relative calls, and prints the deepest chains from a root:

    python3 tools/stack-chains.py target/debug/build/scx_mavd-*/out/bpf.bpf.o \
        lavd_select_cid lavd_enqueue

It is an upper bound. The verifier derives a subprog's depth from the
accesses it actually verifies, so code it never reaches or prunes does not
count, which is why lavd_enqueue() models at 528 and loads. The model
reproduced the two rejections seen during the conversion, 528 and 544
bytes, and the 512 of the accepted layout. It is the tool for
re-measuring after a compiler change or a port from lavd.

## The instruction budget

Every loop the conversion added uses `bpf_arena_for()`. Six scans that
lavd wrote with `bpf_for()` keep it: the two neighbor-domain scans in
migrate_to_neighbor(), the preemption victim scan, the two core-compaction
scans and the load-balance classification loop. With those converted too,
lavd_select_cid exceeded the one-million-instruction budget:

    BPF program is too large. Processed 1000001 insn

Each site carries a comment saying so.

## Reproducing

1. Boot the kernel branch, or any kernel with the cid-form sched_ext API
   and the `__uninit` liveness fix.
2. `cargo build -p scx_mavd` in the scx tree. The BPF object is
   target/debug/build/scx_mavd-*/out/bpf.bpf.o.
3. Run the model as above, then load target/debug/scx_mavd. A rejected
   load prints the verifier log on stdout.
4. To see a rejection, change one `__noinline` in src/bpf/idle.bpf.c or
   src/bpf/cid.bpf.c to `__always_inline`, remove the crate's directory
   under target/debug/build so the BPF objects rebuild, and repeat.

## Open questions

- Whether the per-subprog maximum is the intended accounting, or whether
  scratch that is dead before a call could be excluded, which would remove
  boundaries whose only purpose is stack budgeting.
- Whether `__noinline` is the recommended way to shape the combined stack,
  or an attribute or libbpf convention exists for it.
- Whether the arena loop form is expected to cost this much more
  verification than `bpf_for()` on scans of a few hundred elements.
