# Cake instruction and kernel-service research — 2026-10-02

The strongest new experiment is an existing sched_ext DSQ comparison patch,
backported and built here. It removes generic comparison work from kernel
services that Cake already calls. Separately, a verifier mutation test proves
that the scalar return-bounds patch needs its precision dependency: deleting
it causes two unsafe programs to pass verification.

**Evidence level:** kernel build, actual kernel/BPF disassembly, VM correctness,
and analysis of archived profiles. No new hardware latency, frame-time, or
input-latency result. The installed kernel, ordinary release, and Cake source
were not changed. All kernel candidates remain under `target/`.

## 1. Primary research and applicability

Usama Arif's September 21 patch supplies a typed comparator for the existing
DSQ hash table. Tejun Heo reports applying it to `sched_ext/for-7.4`, with the
function signature joined. The retained CachyOS 7.2.8 source lacks it. The
author's reported 2.9× result is a same-kernel **DSQ lookup microbenchmark using
scx_layered queue IDs**, not a Cake or whole-scheduler speedup.
[Original submission](https://lists.openwall.net/linux-kernel/2026/09/21/2444),
[maintainer acceptance](https://lists.openwall.net/linux-kernel/2026/09/21/2516).

The June 23 **Kops/EInsn preprint** proposes compiler-recognized native
operations with explicit operand metadata and BPF proof sequences. Native
emitters remain trusted and require equivalence to those sequences. Its
application results concern packet processing, not Cake. Its older illustrative
rotate sequence uses Linux 6.1; our JIT already emits BMI2 shifts. Its policy
experiments also show that enabling more operation families can worsen results.
The useful research direction is preserving verifier semantics while improving
operand placement, with selective adoption. We have not built or reproduced
Kops, and this review did not establish a usable public implementation artifact.
[Preprint, sections 4–7](https://arxiv.org/html/2606.24213v1).

The [official kfunc documentation](https://docs.kernel.org/bpf/kfuncs.html)
describes registration and interface constraints. The
[sched_ext documentation](https://docs.kernel.org/scheduler/sched-ext.html)
provides the scheduling contract. Exact behavior below was checked against the
local 7.2.8 source; current online documentation is not a substitute for it.
Retrieved HTML, dates, and SHA-256 hashes are archived in the candidate's
`sources/manifest.json`.

## 2. Implemented DSQ backport and actual assembly

The [attributed backport](0004-sched-ext-typed-dsq-compare-cachyos-7.2.8.patch)
changes only `kernel/sched/ext/ext.c`. It adds the typed comparator and selects
it through `dsq_hash_params.obj_cmpfn`.

Local audit:

- Lookup keys are addresses of `u64 dsq_id`; insertion keys are the aligned
  `scx_dispatch_q.id` field. The compile-time size assertion enforces eight bytes.
- Hash-table consumers inspect equal versus unequal, not comparison ordering.
- Existing hash computation, collision traversal, resize retries, RCU lifetime,
  destruction locks, and deferred freeing remain in place.
- Custom-queue count, peek, and move operations reach `find_user_dsq`.
  Local built-in DSQ counts take a separate path and do not gain this comparison.

Both compared kernels use the same LLVM build configuration and scalar bounds
patch. Actual `vmlinux` disassembly:

| `find_user_dsq` property | Bounds baseline | With typed DSQ comparison |
|---|---:|---:|
| Function bytes | 301 | 297 |
| Static instructions in function body | 82 | 91 |
| Saved registers | 6 | 4 |
| Own stack use, excluding return address/callees | 96 bytes | 32 bytes |
| Generic comparison | Call to `bcmp` | Inline 64-bit `cmp` |
| Hash calculation | Call to `jhash2` | Inlined calculation |
| Stack-canary call site | Present | Absent |

The larger instruction count in the function body reflects hash inlining;
the baseline count excludes its callees. This is another concrete reason to
avoid using one function's static instruction count as a latency score. On the
ordinary non-nested bucket path, the generated candidate has no outgoing call.
The uncommon nested-bucket lookup still calls `rht_bucket_nested`.

The comparison loop also loses runtime key-length/key-offset loads. A runtime
hash-node offset load remains. The change does not remove queue migration,
locking, scheduler association, RCU, or accounting costs. The standalone
comparator also occupies code for generic hash-table callers; 301→297 is not
a claim about total kernel text size.

The backport applies with zero fuzz and produces a byte-identical copy of the
built source file. `checkpatch.pl --strict --no-tree --no-signoff` reports zero
errors/warnings. `--no-signoff` is deliberate: this is a locally attributed
research backport, not a newly signed mailing-list submission.

## 3. VM correctness and remaining validation

The normal candidate retains the precision dependency. Three main QEMU TCG
configurations passed:

| Configuration | Scalar differential executions | Positive bounds loads | Unsafe bounds rejected | Cake inspection loads | Activation/restoration checks |
|---|---:|---:|---:|---:|---:|
| 2 CPUs, native scalar features | 6,562 | 17 | 13 | 19 | 3 |
| 8 cores / 16 threads | 6,562 | 17 | 13 | 19 | 3 |
| `qemu64`, BMI1/POPCNT/ABM disabled | 6,562 | 17 | 13 | 4 | 1 |
| Main matrix total | 19,686 | 51 | 39 | 42 | 7 |

Each configuration also passes six legacy scalar positive tests and the
expected MULHI clobber rejection. Specialized builds reject missing required
mode flags, and the feature-disabled guest rejects the native specialization.
The fallback guest uses genuinely disabled userspace CPU features.

A separate 16-thread follow-up activates the archived unmasked candidate in
default and bitops modes: **two more clean activation/restoration checks** and
6,562 additional differential executions passed. This investigates a JIT
address-encoding difference, not a reason to prefer the unmasked build.

Across 328 matched BPF programs in the main 16-thread inspection matrix,
instruction counts, BPF slots, stack accesses, and scalar-op counts match the
previous bounds kernel. Four unmasked dispatch dumps grow by three bytes:
their per-CPU private-stack address now needs a 10-byte `movabs` instead of a
7-byte sign-extended immediate load. The instruction count is unchanged.
This is address materialization variation, not added scheduler logic.

These are short correctness checks. The worker smoke pins four workers across
two logical CPUs even in the 16-thread guest. It does not establish saturated
16-thread performance, multi-LLC fairness, hotplug safety under stress, or game
latency. Hardware A/B requires booting the candidate kernel; no kernel was
installed or booted on the host during this pass.

## 4. Precision mutation: a detected verifier failure

An isolated disposable kernel starts from the previous bounds baseline and
removes only `mark_chain_precision(env, BPF_REG_1)` and its error handling from
the nonzero CTZ/CLZ return-bound refinement. It does not carry the DSQ patch.

The existing forced-pruning tests then produce:

| Negative test | Retained bounds patch | Deliberately weakened kernel |
|---|---|---|
| `bad_ctz_pruning` | Reject | Incorrectly accepts |
| `bad_clz_pruning` | Reject | Incorrectly accepts |
| Other 11 unsafe cases | Reject | Reject |

The verifier first explores a nonzero input and learns a result upper bound
of 63. Without preserving the input dependency, it later reuses that state
for the path with a zero input. Zero returns 64 and exceeds the 64-element
array. The weakened verifier log ends the merge with `15: safe`.

The harness records failure and closes an accepted negative program without
executing it. It stops before Cake activation. The mutation image is labeled
test-only and is not packaged as a recommended patch.

This demonstrates that the test detects this particular missing-dependency
bug; it is not a proof of complete verifier correctness. Precision marking is
**load-time analysis**, not per-dispatch work. Removing it cannot save a
runtime scheduler instruction. Keep it in every return-bounds variant.

## 5. Corrected historical profile attribution

The September 27 `perfmap.py` selected every `bpf_prog_*` frame while labeling
the denominator “Cake time.” Its reports include unrelated system BPF programs
such as `restrict_filesystems`. The [corrected analysis copy](perfmap-cake-only.py)
restricts frames to `cake_` names and exports all leaf counts, not just rounded
top-50 rows. The archived originals remain unchanged.

| Archived workload | Unrelated share of old BPF denominator | `find_user_dsq` self, corrected | `bcmp` under Cake, corrected |
|---|---:|---:|---:|
| `h0_release` | 4.376% | 13.102% | 4.022% |
| `h16_release` | 2.138% | 5.488% | 3.038% |
| `appsim_fix` | 0.731% | 2.340% | 1.556% |

The last two columns are sampled kernel leaf time as percentages of the
corrected Cake-name denominator, not wall-clock fractions or kfunc prices.
`bcmp` is aggregated across Cake call paths, not attributed exclusively to DSQs.
These old kernels/builds differ from today's candidate. The original nearest-
symbol resolver also remains approximate: it does not prove exact symbol bounds.
Use this as historical prioritization evidence, not a current latency model.

Under the archived appsim load, `psi_task_change` is 11.077% and queued spinlock
slowpath is 10.003% of that denominator. The DSQ comparison cannot eliminate
either. A faster lookup may be worthwhile, but lookup microbenchmark ratios
cannot be applied to the whole callback or to FPS.

## 6. Remaining instruction and API opportunities

Actual specialized release `cake_select_cpu` JIT still has three CTZ sites
with this operand arrangement:

```asm
mov    %rsi,%rdi
tzcnt  %rdi,%rax
mov    %rax,%r14       # one site uses %rbx
```

Its POPCNT site already computes its input in `%rdi` but copies the result
from `%rax`. That is seven surrounding register moves across four static sites
in this loaded program, including its subprograms. It is not seven moves on
every selection invocation, and not seven cycles of proven savings.

An operand-aware lowering could theoretically emit TZCNT directly from the
original input into the final destination. The implementation must preserve
every still-live BPF register, fallback CPU behavior, zero semantics, branch
targets, exceptions, and verifier-visible state. A textual peephole that erases
the two moves without liveness proof is insufficient. Adding another ordinary
kfunc name preserves the same fixed call-register problem.

Ranked follow-up experiments:

| Priority | Experiment | Expected mechanism | Required evidence / stop condition |
|---|---|---|---|
| 1 | Hardware test typed DSQ comparator | Remove generic lookup interpretation and associated calls/spills | Same Cake release and flags across kernels; callback cost separately from accounting-off frame/wake latency; stop promotion on liveness/tail regression |
| 2 | Operand-aware unary scalar lowering | Remove proven redundant fixed-register moves | Native/fallback differential and clobber tests, actual Cake JIT, then hardware timing; retain only sites with complete-path benefit |
| 3 | Conditional DSQ count/head snapshot | Reuse one lookup when both observations are needed | Preserve typed RCU task lifetime and scalar-output validation; benchmark extra head loads versus existing conditional peeks; lockless results remain advisory |
| 4 | Better known-bit scalar bounds | Use known input bits to narrow count ranges further | Precision dependencies plus negative/pruning tests; first show a remaining Cake bound/mask it can remove |
| 5 | Kernel IRQ/capacity observation | Reuse existing accounting instead of adding hot-path tracing work | Explicit units, freshness and support contract; measure placement success and wake tails, not only getter cost |

Known-bit bounds are a potential verifier improvement, not automatically a
runtime win after the current masks are gone. Likewise, the maintainer mentions
typed comparators for task-ID and sub-scheduler tables, but this Cake source
does not call `scx_bpf_tid_to_task`. Those are lower-priority for this workload.

The queue-head refresh after failed moves in `cake_dispatch_search()` is
intentional: a competing CPU may have changed the head. Its unconditional
second move is also a documented healing path. Do not remove either merely
because the lookup appears repeated. `move_to_local` additionally flushes the
dispatch buffer and performs migration/accounting. Kick handling deliberately
defers work to avoid nested runqueue locking.

For visibility, the local kernel's `irq_time_read()` excludes softirq time
charged to `ksoftirqd`; its semantics must be preserved. `scx_bpf_cpuperf_cur()`
already exposes frequency-relative capacity, which is not an IRQ-occupancy
signal. GPU completion and input activity remain event-to-task policy research;
they do not follow from adding scalar instructions or bypassing device drivers.

## 7. Artifacts and next hardware gate

Candidate:
`target/cake_deep_research_20261002T101516Z/`

Evidence:
`../scx_cake_bench/runs/cake_deep_research_20261002T101516Z/`

- `final-validation.json`: identities, VM outcomes, preserved host/source state.
- `kernel-disassembly-summary.json`, `baseline-*.asm`, `typed-*.asm`:
  kernel function comparison.
- `cake-jit-shape-comparison.json`, `cake-byte-length-analysis.json`:
  loaded BPF comparison and the private-stack immediate difference.
- `native/`, `smt16/`, `fallback-v8/`, `smt16-private-stack/`: VM commands,
  complete serial logs, verifier logs, loaded BPF/JIT bytes, status files.
- `mutation/bounds/bad_{ctz,clz}_pruning.verifier.log`: detected missing-
  precision behavior; negative programs never executed.
- `*-full-profile.json`, `*-filtered-profile.txt`: corrected historical analysis.
- Candidate `sources/`, `compile_commands.json`, `build.log`,
  `patch-validation.json`: primary-source archive and build attribution.

The typed-comparison kernel SHA-256 is
`156b4e1b5dac3bfc31988cba8a1be6cc6b3f0e5d3fa476521b79e12b52c30387`.
Its version label is inherited from the prior test build; identify it by hash.
The separate mutation image must never be installed as a performance candidate.

The DSQ backport is an additional independent patch on the previously retained
scalar/fastcall/bounds kernel; it does not replace the scalar patch bundle.
No installation is performed here. When a candidate is booted, use the maintained
Cake benchmark path, hold release artifacts and feature flags fixed, and retain
wall-clock completion, wake/frame tails, CPU accounting, and interference data
as separate endpoints. There is no new ns saving to enter in the cost chart yet.
