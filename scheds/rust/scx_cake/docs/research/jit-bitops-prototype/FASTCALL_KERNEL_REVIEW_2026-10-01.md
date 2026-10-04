# Unary fastcall kernel patch and Cake release audit

Prepared October 1, 2026, America/Chicago; artifacts use October 2 UTC.

**Implemented and VM-verified, not hardware-performance accepted.** The kernel
can now truthfully preserve BPF R2–R5 across CTZ, POPCNT and CLZ. An annotated
release Cake build has smaller select_cpu code, but annotation also produces
regressions in other configurations. Ordinary Cake source/defaults are unchanged
by this experiment, and its ordinary release binary was restored byte-for-byte.
No host kernel was installed or rebooted.

Follow-up: [five-block VM simulation and instruction-model review](FASTCALL_SIMULATION_2026-10-01.md)
completed 20/20 slots. It extends the correctness evidence; it establishes no
hardware or emulator speedup.

## Deliverables

- [Combined CachyOS 7.2.8 patch, including unary fastcall](0001-bpf-x86-inline-all-scalar-ops-fastcall-cachyos-7.2.8.patch):
  an alternative to the preceding combined scalar patch, for fresh matching
  sources. It contains all four scalar operations and their selftests.
- [Incremental unary fastcall patch](0002-bpf-x86-unary-scalar-fastcall-cachyos-7.2.8.patch):
  only for sources already containing exactly
  [the previous combined patch](0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch).
  **Choose the new combined patch OR the old combined patch plus this increment.**
  Never apply both alternatives together.
- [Compiler annotation header](fastcall-decls.bpf.h): isolated opt-in build
  experiment for all three unary declarations. It preserves the weak `.ksyms`
  declarations and deliberately excludes MULHI.
- [Standalone test runner](fastcall-run.c): six positive programs, one expected
  verifier rejection, translated BPF/JIT exports, and assertions about retained
  versus removed stack accesses. This runner replaces `selftest-run.c` when
  testing the fastcall version of `scalar_bitops.bpf.o`.

Both patch application checks pass, and both routes reproduce all five affected
source files exactly. The incremental patch has zero checkpatch errors and one
reviewed `volatile` warning: mutable BPF map data deliberately prevents the
verifier from folding register-preservation checks into constants.

## Contract and implementation

`KF_FASTCALL` is registered only with `CONFIG_X86_64 && CONFIG_BPF_JIT`.
Other architectures retain the ordinary kfunc ABI. Kfunc use itself requires
JIT support. Unary operations may clobber R0 and R1; R2–R5 must survive.
Their existing five-byte native x86 sequences already satisfy that contract.

When the relevant CPU feature is absent, the x86 JIT wraps the ordinary C call
in saves/restores of RSI, RDX, RCX and R8, which hold BPF R2–R5. Four pushes keep
the existing stack alignment. RAX remains the result; existing private-frame
and call-depth handling remains in place. This fallback has eight additional
native instructions even for an unannotated caller: correctness is its purpose,
not a claim of improved performance on unsupported CPUs.

MULHI remains an ordinary call because its native `MUL` sequence clobbers RDX,
which is BPF R3. Marking the current two-argument implementation fastcall would
promise preservation that it does not provide. Its negative selftest must fail
with `R3 !read_ok`.

Clang's annotation changes allocation and emits protective spill/fill pairs;
the kernel may remove matching pairs when its contract permits. Older kernels
keep them. Annotation does not eliminate argument/result registers, range masks,
or surviving flag loads. See [Clang's attribute contract](https://clang.llvm.org/docs/AttributeReference.html#bpf-fastcall)
and [kernel kfunc registration](https://docs.kernel.org/bpf/kfuncs.html#registering-the-kfuncs).
The implementation was checked against the actual retained kernel verifier and
JIT, rather than assuming all compiler output qualifies for removal.

## Validation completed

LLVM 22.1.8 built a complete isolated 7.2.8 test kernel, with BTF, sched_ext,
function tracing and the fastcall patch. Its compile database is retained.
An additional `CONFIG_BPF_SYSCALL=n` x86 JIT object build passed. The first VM
configuration lacked `CONFIG_FUNCTION_TRACER`: scalar tests passed, Cake refused
to load, and the configuration was fixed and rebuilt. Failed attempts remain in
the artifact directory and are not counted as successful validation.

Three final QEMU TCG boots passed:

| Kernel / instruction path | Scalar programs | Cake inspection loads | Annotated Cake activation |
|---|---|---|---|
| Installed kernel image, ordinary ABI | 6 pass; expected negative rejection | 8/8 | portable and bitops pass |
| New kernel, native instructions | 6 pass; expected negative rejection | 8/8 | portable and bitops pass |
| New kernel, forced C fallbacks | 6 pass; expected negative rejection | 2/2 portable | portable passes |

Each scalar run covers zeros, all ones, every single-bit position, 1,024
deterministic random values, R6–R9 preservation, and dedicated R2–R5 preservation
for each unary operation. Preservation values come from mutable map data, and
the actual comparisons remain in the exported JIT. There are 18 successful
positive program executions across the three boots, plus three expected
negative rejections; these are not 18 independent performance samples.

Fallback boot parameters clear `bmi1,popcnt,abm`; their absence was checked in
the guest's `/proc/cpuinfo`. Each unary fallback dump has one C call and the
four matching pushes/pops. Native dumps have the scalar instruction and no
such call. In the focused fastcall tests:

| Evidence | Existing ordinary-ABI kernel | New fastcall kernel |
|---|---:|---:|
| BPF stack saves/reloads per unary test | 8 | 0 |
| CTZ/CLZ native program bytes | 137 | 97 |
| POPCNT native program bytes | 139 | 99 |

The focused programs retain their result and all four register comparisons.
The new C-fallback programs are 107/109/107 bytes and preserve the same state.

Activation checks observed sched_ext enabled, ran four short affinity-pinned
workers using computation, yield and sleep on two guest CPUs, verified Cake
remained alive, then sent SIGINT to that owned child and observed exit 0 and
sched_ext disabled. All five checks passed. No kernel warning, panic, soft
lockup or watchdog failure was found in final logs. This is bounded VM liveness
evidence, not a contention, fairness or long-duration stress result.

## Actual release Cake assembly

Same kernel, two guest CPUs, same runtime configuration within every pair.
Both binaries are normal optimized Cargo **release** builds; the candidate adds
only the forced-include annotation header. Counts include each dumped callback's
referenced subprograms. They are static counts, not executed work per callback.

| Mode / callback | Before → annotated native instructions | JIT byte delta | BPF stack-access delta |
|---|---:|---:|---:|
| Native bitops / select_cpu | 1,423 → 1,415 | −28 | −9 |
| Native bitops / enqueue | 1,952 → 1,950 | −3 | −2 |
| Native bitops / dispatch | 1,163 → 1,161 | −3 | −2 |
| Native bitops / stopping, probe off | 306 → 306 | 0 | 0 |
| Bitops + ring + quotient / select_cpu | 1,758 → 1,752 | −21 | −4 |
| Bitops + ring + quotient / enqueue | 2,507 → 2,509 | +11 | +3 |
| Bitops + ring + quotient / dispatch | 1,225 → 1,224 | −5 | −2 |
| Native histogram, probe on / stopping | 493 → 499 | +24 | +6 |

Portable default also shrinks select_cpu by eight instructions: compiler
allocation/layout changes affect the whole object before the verifier prunes
disabled branches. Thus the complete bitops improvement cannot be attributed
solely to kernel spill removal. In the old-kernel comparison, annotated bitops
select_cpu retains two more BPF stack accesses than in the new-kernel comparison,
consistent with removal of one additional pair. Old and new VM kernel configs
differ; cross-kernel native byte totals are not controlled performance evidence.

### Why the histogram did not benefit

The actual stopping JIT still saves two registers around one LZCNT and one
register around another. Its BPF patterns use slots `-32,-40` at the first call,
but only `-32` at the second. The retained verifier's
`mark_fastcall_pattern_for_call()` starts matching from the subprogram's lowest
spill offset. `check_fastcall_stack_contract()` disables rewriting if other
accesses touch the reserved region outside a recognized pattern.

That source rule and the emitted layouts explain a concrete compiler/verifier
compatibility limitation: a fastcall declaration is insufficient to remove
every save. This attribution is based on code and disassembly, not an instrumented
verifier trace. A minimized mixed-layout reproducer is the next useful test
before changing recognition rules. Any relaxation needs negative tests for
aliased stack slots, unmatched reloads and control-flow entry into patterns.
Do not bypass that check or blindly remove the spills.

The all-unary annotation experiment therefore remains archived, not integrated
into Cake's ordinary build. A CTZ/POPCNT-only annotation variant is a separate
useful comparison; CLZ annotation should not be presumed beneficial because the
CLZ machine instruction itself is fast.

## Further Cake and kernel opportunities

The following audit used the isolated CachyOS source under
`target/cake_fastcall_20261002T033139Z/linux`. These are proposed independent
experiments, not additional features included in this patch.

| Priority / mechanism | Current work that might be avoided | Contract and falsifying test |
|---|---|---|
| 1. Compile-time native/portable BPF variants | Actual JIT still materializes flag addresses and reads flags after their branches are pruned | Loader must select a matching object and reject unavailable instructions; compare complete release JIT, load both configurations, then measure callback ns and frames |
| 2. DSQ lookup optimization | `find_user_dsq()` performs an rhashtable lookup; Cake repeatedly counts, peeks and moves from CPU-numbered user DSQs | Prototype a bounded dense-ID table or typed handle, retain scheduler ownership and RCU lifetime, test concurrent destroy/recreate, draining, teardown and ID reuse |
| 3. CPU/current-task snapshot reuse | `cake_cpu_curr()` is a noinline compatibility wrapper used in several placement/admission checks | Reuse only within the same valid decision interval; preserve deliberate retakes after idle claims and exact queue-head checks; compare reads/spills and adversarial wakeups |
| 4. Context-aware kick path | `scx_kick_cpu()` normally sets masks and queues irq_work before the real reschedule | Direct handling only in proven unlocked contexts; preserve IRQ state, rq lock order, idle race protection, PREEMPT/WAIT behavior and bypass; measure wake-to-run p99.9 and stalled work |
| 5. Read-only cpumask specialization | `bpf_cpumask_test_cpu()` validates CPU then calls the bit test | Keep the out-of-range-false contract, task affinity and pointer lifetime; a BT instruction alone is not the complete API; compare current full JIT against a range-proven inline path |
| 6. Callback/subprogram layout | `cake_dsq_insert_vtime()` and `cake_cpu_curr()` are noinline; scalar annotation changes register pressure across disabled branches | Compare selective inlining and shorter live ranges with unchanged policy; code growth, verifier complexity and spills are guardrails |

Kernel details that constrain these ideas:

- `kernel/sched/ext/ext.c:find_user_dsq()` uses the scheduler's DSQ hash.
  `destroy_dsq()` takes the DSQ lock, refuses a nonempty queue, removes the hash
  entry, invalidates its ID, then frees through irq_work and an RCU grace period.
  A cache filled concurrently with destruction must not republish a freed queue.
  Existing local/builtin queue-count paths already avoid the user-DSQ hash;
  optimize the paths Cake actually uses.
- The kick implementation explicitly defers work to avoid nested rq locks.
  Its idle path already attempts a remote rq trylock to skip unnecessary work.
  Removing all deferred kicks or trusting a stale idle bit can lose progress.
- `kernel/bpf/cpumask.c:bpf_cpumask_test_cpu()` returns false for an invalid CPU.
  `scx_bpf_test_and_clear_cpu_idle()` additionally validates scheduler/CPU state
  and claims idle atomically. These operations are not interchangeable.
- Kernel runqueue time already accounts for IRQ/steal time; Cake charges task
  execution runtime. Improved IRQ-capacity visibility must avoid double charging.
  GPU fence/input-wakeup dependency interfaces remain separate proposals from
  the [assembly and signal review](ASSEMBLY_PIPELINE_REVIEW_2026-10-01.md).

The [operation-cost guide](../../AUDIT_OPERATION_COST_2026-09-15.md) now notes
that feature checks are not universally free: observed flag loads survive.

## Reproduction and next live gate

Archived compiler experiment, from the repository root:

```bash
BPF_EXTRA_CFLAGS_PRE_INCL="-include $PWD/scheds/rust/scx_cake/docs/research/jit-bitops-prototype/fastcall-decls.bpf.h" \
  cargo build --locked --release -p scx_cake -j4
```

This temporarily replaces `target/release/scx_cake` with an experimental build.
An ordinary `cargo build --locked --release -p scx_cake -j4` restores the normal
configuration. Both candidate binary and its exact embedded BPF object must be
archived before changing builds. The header requires Clang's `bpf_fastcall`
attribute and was tested with Clang 22.1.8.

The next hardware screen needs the new kernel booted, the archived annotated
release reloaded, and five balanced measurement blocks using the maintained
Cake harness. Keep BPF/probe timing disabled for frame/wall-clock comparisons;
collect callback cost separately. Record fixed-work completion wall time and
throughput alongside frame p99/p99.9, lows, jitter and wake-to-run latency.
Start with native bitops and its annotated counterpart; keep quotient off.
Promotion still requires the maintained confirmation and regression gates.
The VM runs establish no nanosecond, throughput, FPS or latency improvement.

### Retained evidence

- Candidate/build source and commands:
  `/home/ritz/Documents/Repo/scx/target/cake_fastcall_20261002T033139Z/`.
- VM logs, complete native/translated dumps, assertions and reproducible analysis:
  `/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_fastcall_20261002T033139Z/`.
  `native-final/`, `fallback-final/`, `old-final/` are the accepted correctness
  runs. `analyze.py` writes `assembly-validation.json` and checks CPU flags,
  expected rejections, spill removal and fallback save/restore instructions.
- Kernel configuration/image, build logs, `compile_commands.json`,
  no-syscall object build, `patch-validation.json`, compiler inputs and the
  selftest object are retained in the candidate directory.
- Annotated binary SHA-256:
  `9d0140ab824c15152e6e37f554efcabb6d2ba08516b33ad507c3387c33bdada2`.
  Embedded BPF SHA-256:
  `459328fc9e48968cf07b7f66ff328cf41bf0898f8ce9e828111d689bb8e61232`.
- Restored ordinary release SHA-256:
  `238869478389fceceb64ffe681eebce1025c9c848ec050aa5b0606d5ed6d3723`.
  Embedded BPF SHA-256:
  `889948f8cf0dff94238379fc9b39664314d9c2cc511cbcee89cba79c129d9b2c`.
  `restoration.json` verifies byte identity and unchanged Cake Rust/BPF source.

Artifact pairing is diagnostic, not a score-bearing v5 receipt or promotion.
