# scx_mavd with cpu.max fails verification after the arena-scalar conversion

## Summary

After the conversion of scx_mavd to arena-scalar objects (#3880, main at
931db7597560), `scx_mavd --enable-cpu-bw` fails to load: `lavd_dispatch`
runs past the verifier's 1M instruction limit. Without cpu.max it verifies at
622k, and the pre-conversion scheduler verifies at 734k with cpu.max.

The budget goes to `consume_task()`, a static helper holding the neighbor
stealing loops, which costs about 50k instructions per verification. The
verifier verifies it once per path that reaches the `consume_out` join of
`lavd_dispatch()` and is not covered by a path verified earlier. The
pre-conversion scheduler gets 8 such visits, the converted one 12 without
cpu.max and 20 with it. Two things cause the growth, neither of them a
property of arena-scalar semantics:

1. At the join, the converted code leaves r5 holding a dead value on one
   path (the affinitized-prev check used it as a scratch register for
   `taskc_prev`) and untouched on every other path. The verifier's liveness
   analysis treats a BPF-to-BPF call as reading r1 through r5 regardless of
   the callee's arity, and a state recorded with an initialized register
   never covers an arrival with that register uninitialized. So the
   arrivals of the other kind are never pruned. In the pre-conversion code
   r5 is untouched on every path into the join.

2. With cpu.max, `scx_cgroup_bw_reenqueue()` is called at the top of
   `lavd_dispatch()`. Its return resets the verifier's checkpoint heuristic
   (a state is recorded at a prune point only after at least 2 jumps and 8
   instructions since the previous checkpoint), so no state is recorded at
   the `is_lock_holder_running()` call a few instructions later. Without
   cpu.max a state is recorded there and the verifier-only path "prev set,
   cpu invalid, cpuc NULL" is pruned against the valid path. With cpu.max
   the path survives and doubles the arrivals at every later point: 17
   versus 30 at the join. By then cpu has been marked precise, so those
   arrivals fail on its range as well as on r5.

Workaround (in main after this analysis): `try_to_steal_task()` and
`force_to_steal_task()` become global functions, verified once each, so a
`consume_task()` visit costs about 3k instead of 50k. `lavd_dispatch` then
verifies at 148k without cpu.max and 180k with it. The visit multiplication
itself is untouched.

A verifier improvement is possible: letting liveness use a static
subprogram's declared arity removes every r5 miss (20 visits become 14) but
does not by itself bring the program under the limit.

## Setup and symptom

- Kernel: sched_ext for-next a8acb152ff95 merged with bpf-next for-next
  e1d84a37cba9 (arena-scalar objects need bpf-next 4c651a91bdfc, "bpf:
  Treat load and store through a number as arena access"). The branch
  `mavd-verifier-repro` in the sched_ext tree
  (<https://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git/log/?h=mavd-verifier-repro>)
  is that merge plus the three probe commits described under Reproduction.
- scx: this branch, `htejun/mavd-verifier-repro`, is main 931db7597560 with
  this document and the scripts under `veristat/cpu-max/` added. The
  pre-conversion comparison point is main 068453f9994c, the commit before
  #3880 merged.
- Toolchain: clang 22.1.8, bpftool 7.8.0. Instruction indexes below are
  from objects built with that clang and shift with any other.
- Machine: an 8-cpu, 1-LLC VM. The failure does not depend on the machine
  size.

```
$ scx_mavd                                   # loads
$ scx_mavd --enable-cpu-bw --cpu-bw-max-cgroups 2048
libbpf: prog 'lavd_dispatch': BPF program load failed: -E2BIG
...
processed 1000001 insns (limit 1000000) max_states_per_insn 42 total_states 38638 peak_states 3315 mark_read 0
```

The same command on main 068453f9994c loads.

## Reproduction

### The kernel branch

Three commits on top of the merge, none for merging:

- `veristat`: two environment hooks. `VERISTAT_ARENA_SCALAR=1` sets
  `BPF_F_ARENA_SCALAR` on every program so the converted objects load at
  all, and `VERISTAT_RODATA=<blob>` replaces the `.rodata` map's initial
  value with a dumped blob before `-G` presets are applied.
- `bpf/states.c`: a pruning diagnostic. With
  `echo <insn> > /sys/module/kernel/parameters/bpf_prune_dbg_insn` and a
  level-2 log, every pruning miss at that instruction prints the checks that
  fail (each live register with both sides' type, precision and id, stack,
  references, callsite) and both full states, as `PRUNE_DBG` lines.
- `bpf/liveness.c`: the experiment. A call to a static subprogram reads only
  the registers its BTF prototype declares, instead of r1 through r5.
  Measure with and without this commit.

Build the kernel as usual and `make -C tools/testing/selftests/bpf veristat`.

### veristat with the loader's rodata

veristat verifies with the object's source defaults for every `const
volatile`, which are not what the loader sets. The compat enum values
(`__SCX_ENQ_*`, `__SCX_DSQ_*`, ...), the lib feature bits and the
bandwidth library's admission flags are all rodata set at open time, and
with their zero defaults the verifier constant-folds whole paths away:
`lavd_dispatch` with cpu.max shows 529k instead of failing. Feed the real
rodata instead:

```
# as root, on the target kernel; the scheduler must load in this configuration
veristat/cpu-max/dump-rodata.sh rodata.bin target/debug/scx_mavd
# bpf.bpf.o is the linked object: ls -t target/debug/build/scx_mavd-*/out/bpf.bpf.o | head -1
veristat/cpu-max/veristat-cpu-max.sh VERISTAT bpf.bpf.o rodata.bin 1 out/
```

`veristat-cpu-max.sh` runs the object twice, without cpu.max and with the
rodata that `--enable-cpu-bw --cpu-bw-max-cgroups 2048` sets, and prints the
`lavd_dispatch` row plus the `consume_task` line of the per-subprogram table
that bpf-next's stats log ends with. Pass `0` instead of `1` for a
pre-conversion object, built from 068453f9994c with its own blob (the rodata
layouts differ). With the live rodata the numbers match the real load:

| lavd_dispatch, live rodata | cpu.max off | cpu.max on |
|---|---|---|
| main 068453f9994c (pre-conversion) | 719,550 | 734,126 |
| main 931db7597560 | 622,067 | fails at 1,000,001 |
| 931db7597560, source defaults | 516,003 | 529,036 (wrong) |

### Visits and pruning

`level2-log.sh` writes the level-2 log of `lavd_dispatch` (500 MB to 800
MB, a guest with a few GB). `calls.py LOG consume_task` counts the visits
to every call target and lists the distinct caller states at the
`consume_task` call; `grep -c '^598: safe'` counts the arrivals pruned
there (598 is the call's index in the converted object, 611 in the
pre-conversion one). With `bpf_prune_dbg_insn` set, `prune-summary.py LOG`
tallies the failing checks and the old/new register pairs.

## Analysis

### Where the budget goes

The per-subprogram table (`insns_self` is the instructions verified in that
function's own frame, over all its visits):

| object | configuration | lavd_dispatch total | consume_task insns_self |
|---|---|---|---|
| pre-conversion | cpu.max off | 716,127 | 696,735 |
| pre-conversion | cpu.max on | 728,010 | 696,735 |
| converted | cpu.max off | 618,648 | 599,254 |
| converted | cpu.max on | cut off at 1,000,001 | 961,438 |

`consume_task()` is a static function: it is verified inline on every path
that calls it and is not pruned. Its body is cheap; `try_to_steal_task()`
and `force_to_steal_task()` inside it walk the neighbor domains in nested
bounded loops (`LAVD_CPDOM_MAX_DIST` by `LAVD_CPDOM_MAX_NR`) and account for
nearly all of it. In the converted object a visit costs about 50k
instructions, in the pre-conversion one about 87k, so the converted code is
cheaper per visit and only loses on the number of visits.

### Visits at the join

Every path through `lavd_dispatch()` that wants a task ends at one call,
`consume_task(cpuc->cpdom_id)` at `consume_out`: the `use_full_cpus()`
shortcut, the active and overflow cmask tests, the per-cpu DSQ fast path,
the pinned, migration-disabled and affinitized prev checks, and the two
`scan_dsq_for_ovflw_ext()` calls returning true. An arrival is pruned when a
state recorded there earlier covers it.

| object | configuration | arrivals | pruned | consume_task visits |
|---|---|---|---|---|
| pre-conversion | cpu.max off | 17 | 9 | 8 |
| pre-conversion | cpu.max on | 17 | 9 | 8 |
| converted | cpu.max off | 17 | 5 | 12 |
| converted | cpu.max on | 30 (cut off) | 10 | 20 (cut off) |

Two things to explain: why the converted object prunes 5 of 17 where the
pre-conversion one prunes 9, and why cpu.max raises the arrivals to 30 in
the converted object only.

### Why arrivals are not pruned: r5

The pruning diagnostic at the call, every failing check per (recorded
state, arrival) comparison:

| object | configuration | misses | r5 | r7 (cpu) | r6 (prev) |
|---|---|---|---|---|---|
| pre-conversion | cpu.max off | 4 | 0 | 0 | 4 |
| converted | cpu.max off | 8 | 7 | 0 | 6 |
| converted | cpu.max on | 33 | 27 | 21 | 9 |

Every r5 miss is the same pair: the recorded state has `R5=scalar()`, the
arrival has r5 uninitialized. In the converted object r6 is `prev`, r7 the
32-bit copy of `cpu`, r8 `cpuc`, and r5 is a scratch register: the
affinitized-prev path reloads `taskc_prev` into it for the inlined cmask
checks and jumps to the join without touching it again, while every other
path into the join never writes it. The pre-conversion object keeps the
arena pointer elsewhere and goes through `addr_space_cast`, and r5 is
untouched on all of its paths into the join; its four misses are prev NULL
against a pointer, which is a real difference.

Two verifier rules turn the dead register into a miss:

- Liveness. Since the switch to the instruction-level dataflow analysis
  (14c8552db644, "bpf: simple DFA-based live registers analysis", v6.15;
  state comparison uses it since 0fb3cf6110a5), the registers an
  instruction reads are computed statically before verification. For a
  helper or kfunc the prototype gives the arity. For a call into another
  BPF function nothing is consulted, and the analysis takes the ABI's worst
  case, r1 through r5 (`compute_insn_live_regs()`, case `BPF_CALL`;
  `bpf_get_call_summary()` has no subprogram case). `consume_task()`
  declares one argument. The previous scheme was precise here: the caller's
  r1 to r5 were copied into the callee frame with their parent pointers, so
  a read inside the callee marked exactly the caller register it read.
- Equivalence. `regsafe()` accepts an uninitialized recorded register
  against anything, and rejects an initialized recorded register against an
  uninitialized arrival, by type. Pruning reuses the recorded path's
  verification of the callee; if the callee did read r5, the recorded path
  was fine and the arrival would be reading an undefined register, so with
  r5 marked as read the verdict has to be conservative.

Exploration order recorded the stale-r5 state first, so every r5-free
arrival misses and pays for `consume_task()` again.

### Why cpu.max doubles the arrivals: a displaced checkpoint

The verifier explores a path that cannot happen at runtime: `prev` set and
`cpu` out of range, so `get_cpu_ctx_id()` returns NULL. In the converted
object without cpu.max that path reaches the `is_lock_holder_running()`
call (instruction 31) and is pruned there against the valid-cpu path: one
visit, one `safe`. With cpu.max, `scx_cgroup_bw_reenqueue()` is called at
instruction 12, and no state is recorded at 31 at all: two visits, no
comparison attempted. `bpf_is_state_visited()` records a state at a prune
point only when at least 2 jumps and 8 instructions were processed since
the previous checkpoint, and the previous checkpoint is now the return from
the bandwidth call six instructions earlier. The pre-conversion object
records one in both configurations (at its instruction 29 with cpu.max, 31
without).

The surviving path then doubles everything after it: 6 against 8 arrivals
at the instruction after `use_full_cpus()`, 7 against 12 at `consume_out`,
17 against 30 at the call. By the time it gets there, the cmask code has
marked `cpu` precise in the recorded states (precision is applied to
recorded states retroactively, by backtracking from later uses), so the
negative-range arrivals fail on r7's range too. That is the r7 column
above.

### Experiments that narrowed it down

All on the converted object with live rodata, `lavd_dispatch` instructions
without and with cpu.max:

| change | cpu.max off | cpu.max on | note |
|---|---|---|---|
| none | 622,067 | fails | |
| `barrier_var()` on `cpuc` and `cpuc_cur` after the lookups | 622,341 | fails | the NULL-vs-valid cpuc distinction is not it: a known 0 is covered by an unknown scalar |
| plus `barrier_var()` on `cpu` | 378,294 | 633,729 | cheaper visits (24 and 31 of them), since the caller frames now match inside `consume_task()` too |
| `veristat -t`, a checkpoint at every prune point | 482,956 | 878,870 | the states differ; it is not missing checkpoints at the join |
| liveness with the subprogram's arity (kernel commit 3) | 621,795 | fails, 14 visits | r5 misses gone, r7 and r6 remain |
| steal functions global (the workaround) | 148,102 | 179,878 | each global 58k to 66k, verified once |

The pre-conversion object under `-t`: 549,057 and 560,201.

### Why the pre-conversion object is fine

Same join, same real differences in `prev`, but r5 is untouched on every
path into it, and the checkpoint before the lock-holder call lands, so the
invalid-cpu path is pruned early in both configurations. 9 of its 17
arrivals prune, cpu.max adds 15k.

## Workaround

`try_to_steal_task()` and `force_to_steal_task()` in `balance.bpf.c` are
global functions (`__attribute__((noinline))`, non-static, `struct cpdom_ctx
__arg_arena *`), the form `pick_most_loaded_dsq()` in the same file already
has. A global function is verified once per program with opaque arguments
and its call is a single instruction on the caller's path, so the visits to
`consume_task()` still happen but cost about 3k each. `lavd_dispatch` drops
to 148k without cpu.max and 180k with it, and the scheduler loads with
cpu.max on the 8-cpu VM. The pre-conversion object was already at 73
percent of the limit with cpu.max for the same reason.

The verifier-side fix in kernel commit 3 is worth pursuing separately: it
restores the precision the old liveness scheme had for subprogram calls and
removes every r5 miss here, but this program still needs the workaround.
