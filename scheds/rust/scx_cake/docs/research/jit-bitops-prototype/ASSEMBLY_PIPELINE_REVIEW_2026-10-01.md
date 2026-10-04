# Cake release assembly, instruction overhead, and scheduling signals

Engineering question: can the installed scalar patch reduce normal-release
scheduler overhead and improve frame latency without changing fairness,
affinity, queue ordering, or forward progress?

The installed kernel really emits native TZCNT, POPCNT, LZCNT and MUL in
Cake. They do not make the entire surrounding expression one instruction.
This review removes one observed layer of redundant work, separates CTZ
from POPCNT for attribution, and identifies the next compiler/kernel changes.
The CPU/GPU/input/IRQ interfaces below are proposals, not installed features.

## Implemented and measured

- Added independent `--native-ctz` and `--native-popcnt` selections. The
  existing `--native-bitops` still selects both. Requested CPU features and
  kfunc symbols are checked before load, with failure instead of silent fallback.
- Folded option combinations into effective per-operation rodata flags in
  Rust. Removed repeated `bpf_ksym_exists()` checks inside four wrappers:
  startup already validates each enabled native path. Kept CTZ/CLZ masks.
- Added `--inspect-bpf NEW_DIRECTORY`. It loads the real configured release
  object, records translated BPF and visible native bytes, and exits before
  attaching IRQ tracepoints or the scheduler. Hidden JIT bytes are recorded
  as unavailable, not as a fabricated zero-filled instruction stream.
- Added exact archived binary/BPF/source identity validation to the maintained
  diagnostic cost harness so old and new dirty-tree builds can be compared.
  This does not manufacture a score-bearing artifact receipt.

All instruction experiments remain opt-in. No kernel or scheduler was installed.

## What the actual native code says

Captured six mode configurations before and after the wrapper change on the
running kernel. Every verifier load passed. Temporarily used the provisioned
kernel-pointer setting, restoring `kernel.kptr_restrict=2` in `finally`.

These are static counts for each dumped program including its referenced
subprograms, not the instructions executed on every callback.

| Native CTZ + POPCNT | Before bytes / instructions | After bytes / instructions |
|---|---:|---:|
| select_cpu | 6,389 / 1,533 | 6,361 / 1,529 |
| enqueue | 8,433 / 2,029 | 8,419 / 2,027 |
| dispatch | 4,942 / 1,213 | 4,935 / 1,212 |
| stopping, probe off | 1,271 / 308 | 1,271 / 308 |

The removed instruction at each site materialized the kfunc address for the
redundant existence check. With native paths disabled, select_cpu also shrank
from 6,710 to 6,545 bytes (1,595 to 1,565 static instructions); compiler layout
and simplification depend on the whole set of gates.

The remaining real native CTZ sequence still contains:

```asm
movabs $native_ctz_flag_address, %rsi
movzbq (%rsi), %rsi
tzcnt  %rdi, %rax
mov    %rax, %rbx
and    $0x3f, %ebx
```

The flag's conditional branch was pruned, but its volatile read survived.
The input must already be ready in RDI. RAX is the kfunc result register.
The mask supplies the bound needed by subsequent BPF indexing. This is why
"native instruction present" and "minimum surrounding cost" differ.

### Removing each remaining kind of cost

| Cost | Appropriate change | Required proof |
|---|---|---|
| Repeated feature/symbol tests | Validate once in loader; effective gates | Implemented; actual JIT captures and live slots |
| Dead immutable-flag reads | Compile-time specialized BPF variants, or a verifier/JIT pass that can safely remove now-dead immutable loads | Relocation, observability, bounds and fallback semantics; compare full JIT, not just C |
| Unnecessary caller saves | Compiler `bpf_fastcall` plus truthful kernel `KF_FASTCALL` support | Preserved R2–R5 for unary ops on every allowed backend/fallback |
| `&63` bound | Teach verifier the intrinsic's return range, including input-dependent nonzero facts | Zero CTZ/CLZ returns 64; never declare an unconditional 0..63 range |
| RDI/RAX argument/result shuffles | A real BPF operation/intrinsic with flexible operands, or a proven register-aware JIT fusion | LLVM lowering, verifier, JIT, interpreter/backend semantics and liveness |
| Repeated data loads | Reduce register pressure, keep values live, combine mask work and reuse snapshots | Cache traffic and register spills under the full callback |

A compile-only Clang 22 probe confirmed the fastcall issue: its ordinary call
keeps the live sum in R6; the annotated call uses R2 and emits a recognizable
spill/call/reload sequence. The current scalar registrations have no
`KF_FASTCALL`, so annotation alone does not earn spill removal. The inspected
kernel already contains the general fastcall rewrite machinery. Clang documents
the attribute, and kernel build tooling emits the matching BTF tag from
`KF_FASTCALL`. [Clang attributes](https://clang.llvm.org/docs/AttributeReference.html#bpf-fastcall),
[BPF kfunc registration](https://docs.kernel.org/bpf/kfuncs.html#registering-the-kfuncs).

The first candidate is the three unary operations, gated so that every
supported JIT implementation preserves the promised registers. An ordinary C
fallback must not inherit that promise without a preserving implementation.
MULHI needs separate treatment: the present x86 sequence uses RDX for the high
product, which is BPF R3 and would be promised preserved by a two-argument
fastcall. Merely marking all four functions fastcall would be wrong.

Even ideal register allocation cannot remove required input acquisition,
affinity checks, synchronization, or zero-input semantics. Fewer static
instructions also do not guarantee lower latency or fewer CPU micro-operations.

## Release frame results

Normal optimized release, thin LTO, BPF `-O2 -mcpu=v3`, explicit `probe=0`,
BPF runtime accounting disabled and zero counters verified before/after every
slot. Two predeclared screens, 15 seconds per slot, four observations per arm.
All **24 slots and 748,484 simulated frames** retained without trimming.

| Mode, wrapper change included | p99 ns | p99.9 ns | 0.1% low FPS | Mean adjacent-frame jitter ns |
|---|---:|---:|---:|---:|
| Portable default | 635,125 | 678,675 | 1,435.00 | 85,598 |
| CTZ only | 644,350 | 931,175 | 928.64 | 89,310 |
| POPCNT only | 653,175 | 730,200 | 1,287.36 | 90,461 |
| CTZ + POPCNT | 631,200 | 664,925 | 1,414.79 | 84,091 |

Order: `ABCDDCBADCBAABCD`. Both operations together versus portable: p99
**-3,925 ns**, p99.9 **-13,750 ns**, mean jitter **-1,508 ns**; 0.1% lows
**-1.41%** and mean slot maximum **+288,625 ns**. The two p99 block effects
were -1,500 and -6,350 ns. Individual-operation arms did worse in this screen;
these data do not establish that their interaction is the cause.

Separate before/after wrapper comparison, both with native CTZ+POPCNT,
order `ABBABAAB`:

| Metric | Before | After | Change |
|---|---:|---:|---:|
| p99 frame ns | 655,150 | 633,300 | **-21,850 (-3.34%)** |
| p99.9 frame ns | 722,950 | 668,975 | **-53,975 (-7.47%)** |
| 0.1% low FPS | 1,341.28 | 1,458.15 | **+8.71%** |
| Mean adjacent-frame jitter ns | 91,333 | 84,902 | **-6,431 (-7.04%)** |
| Mean slot maximum ns | 828,700 | 823,100 | -5,600 |

The two p99 block effects were **-22,950 and -20,750 ns**. This is a positive
short screen worth following up. It does not prove that four fewer static
instructions directly caused a 21.85 microsecond frame difference.

Estimated non-appsim CPU busy ranged 49.02–50.09% in the ablation and
48.89–49.22% in the wrapper comparison; wrapper arm means were 49.12% and
49.08%. Host busy was about 82–83%. Desktop work was left running. Non-appsim
busy includes harness and kernel work; it is not isolated external-process
accounting. Quantiles are equally weighted slot means. Frames are correlated,
and this fixed-cadence simulator is not uncapped game FPS, input-to-photon,
EEVDF comparison, or a default-promotion result. BPF cost was deliberately
unmeasured in these screens; disabled counters must not be reported as zero cost.

### Division-free: what wall time was actually measured?

The earlier five-block experiment measured callback elapsed runtime, not only
host CPU utilization: select_cpu **+11.01 ns/call**, enqueue **+9.40 ns/call**,
aggregate BPF CPU **+5.81%** for division-free alone. That callback work was
slower. Its frame p99 difference was **+920 ns**, with uncertainty including
zero. Fixed-duration appsim does not supply the wall-clock completion time of
a fixed amount of useful work. That endpoint was not measured, so there is
no supported claim that the application finished sooner or later.

The actual native select_cpu dump with quotient mode contains nine MUL and
three LZCNT instructions and no DIV, versus three DIV in the corresponding
non-quotient mode. Reciprocal setup is being repeated for changing divisors.
Cache/reuse is only attractive if the divisor and all overflow/rounding
conditions really remain valid long enough to amortize setup. The compiler
already handles many constant divisors. Leave division-free off by default.

## More accurate scheduling: close the visibility gaps

Cake is not completely blind to interrupts. `cake_irq_live[]` receives four
handler entry/exit tracepoints, `cpu_irq_hot_words/cores` uses `/proc/stat`
IRQ+softirq time, and `cake_cpu_tick_soon()` can use the next clock event.
The sink monitor runs at 1–4 second intervals with confirmation/hysteresis.
`CLK_TCK=100` on this host means exported proc counters have 10 ms units,
despite finer internal IRQ accounting. A depth bit gives no remaining duration.

Device-handler tracepoints are not the complete IRQ boundary: local APIC
timers and IPIs have architecture paths/tracepoints. NMIs, preemption-disabled
regions, higher scheduling classes, and firmware stalls need separate treatment.
Firmware SMI time cannot be turned into precise Linux handler attribution by
adding an ordinary scheduler callback. Preserve an unknown/stale category.

The kernel already removes accounted IRQ/steal time from `rq->clock_task`.
Cake charges `p->se.sum_exec_runtime` deltas in stopping, so do not subtract
IRQ time again. `irq_time_read()` excludes ksoftirqd execution because that is
scheduled thread runtime. Threaded IRQs and kworkers are tasks too, even when
a higher class prevents Cake from selecting them. The improvement sought is
placement information and causal attribution, not inventing a second charge.

Suggested first kernel API, **proposed name and fields only**:

```c
/* Bounded read-only snapshot; validity and freshness are part of the contract. */
scx_bpf_cpu_interference(cpu, &snapshot, sizeof(snapshot));
/* snapshot: accounted non-task ns, recent IRQ load, sample time/generation,
 * effective capacity, and explicit validity flags; optionally live IRQ state
 * only if maintained at the complete architecture boundary. */
```

Reuse existing IRQ/rq accounting, CPU performance/capacity helpers and
cpu_acquire/release or replacement notifications before adding new writers.
Avoid global locks, full-system scans, per-pick device queries and unbounded
sequence-counter retries. Per-CPU fields still create remote cache traffic;
read one snapshot for a shortlist, or export an amortized noisy-CPU bitmap.
Unknown/offline/changed CPUs must fall back to current safe selection.
Do not assume one instantaneous remote snapshot reserves the CPU.

Local review anchors: Cake `cake_irq_edge`, `SinkMonitor`, `cake_pick_idle_clean`,
`cake_stopping`; kernel `kernel/sched/cputime.c:irqtime_account_irq`,
`kernel/sched/sched.h:irq_time_read`, `kernel/sched/core.c:update_rq_clock_task`,
and x86 `DEFINE_IDTENTRY_SYSVEC`. These Linux source paths are reference trees;
only the captured program bytes establish what this installed Cake JIT emitted.
The kernel also offers IRQ delay accounting for observation, not a substitute
for a cheap scheduling-path snapshot. [Delay accounting](https://docs.kernel.org/accounting/delay-accounting.html).

## How to turn instructions and signals into better decisions

| Experiment, in recommended order | Expected mechanism | Success measurement |
|---|---|---|
| Unary fastcall and semantic verifier bounds | Reduce call-surrounding saves/masks without changing CPU order | Full native path cost, same outputs, lower ns/callback and BPF ms/s |
| Fresh non-task occupancy/capacity hints | Avoid an apparently idle CPU consumed by IRQ work | Fewer successful claims followed by long waits; wake p99/p99.9 and frame tails |
| Mask eligibility and rank before CTZ | Intersect affinity/online/idle first, prefer warm whole cores and quieter capacity, then enumerate candidates | Fewer failed claims and retries per placement at equal locality/fairness |
| Sparse queue enumeration | CTZ + clear-lowest-set-bit skips empty queues while preserving established stagger/order | Fewer empty queue probes; dispatch ns, backlog and starvation tails |
| Fuse an existing pick/claim boundary only if profiling justifies it | Reduce BPF/kernel crossings while keeping atomic idle claiming and all topology constraints | Claim win rate, retries, migration/LLC misses, wake-to-run and total CPU cost |
| Device wakeup dependency hints | Place the runnable producer/consumer that can unblock a frame | Event-to-run, fence-to-run, frame miss rate and input latency |

Cake already has rank masks, a CTZ candidate picker, an atomic claim wrapper,
and counters `CAKE_SITE_TACI`, `TACI_WIN`, `CLAIM_RETRY`, cross-LLC moves,
queue hold thresholds and clock-pair calibration. Reuse those in a separate
probe run; measure final frames again with probes off. A claim success is not
automatically a good placement: pair it with subsequent delay and cache cost.

POPCNT is useful for actual density/pressure decisions, not as an extra step
where testing nonzero suffices. CLZ helps power-of-two buckets; the demonstrated
Cake use is diagnostic histograms, absent from normal probe-off operation.
MULHI can implement a proven fixed-point calculation or amortized quotient;
adding reciprocal setup to every changing divisor already lost here.
Reordering successful fast paths must preserve fairness and warmth; choosing
the earliest free CPU was a prior regression in this repository.

The existing sched_ext API already supports idle selection/claiming and direct
local insertion from select_cpu. Inspect it before designing a duplicate fused
helper. Direct insertion can avoid enqueue, but it is only useful for the
appropriate valid placement path. [sched_ext operation flow](https://docs.kernel.org/scheduler/sched-ext.html).

## CPU, GPU and mouse pipeline

Useful information follows the work:

```text
device event / GPU completion
    -> kernel records timestamp and cause for an actual wakeup
    -> Cake reads bounded metadata when choosing a CPU
    -> eligible, warm, sufficiently quiet CPU is atomically claimed
    -> runnable consumer executes -> GPU submission / presentation
```

For GPU work, fence completion already supports timestamps, waiters and
callbacks. First trace fence signal to runnable to execution and identify
CPU-side submission starvation. Any callback design must respect fence locks,
object lifetime and interrupt context; defer scheduler policy to a permitted
wakeup/selection context. Registering extra fence callbacks can itself enable
signaling work, so instrumentation cost must be measured.
[DMA-fence synchronization](https://docs.kernel.org/driver-api/dma-buf.html).

This machine has an RTX 4090 and NVIDIA 615.71.09. Do not assume a generic DRM
scheduler modification covers NVIDIA's entire queue/firmware path. NVIDIA's
open modules require corresponding userspace and GSP components. Driver
integration is a separate experiment. [NVIDIA kernel-module scope](https://github.com/NVIDIA/open-gpu-kernel-modules).

For mouse input, follow input/evdev wakeups and the consumer chain through
the compositor and game. A USB-controller IRQ is not proof that a particular
game thread is the consumer. A bounded, expiring kernel-origin hint may help
an actual runnable dependency; direct polling or bypassing the input stack
would add work and would not solve USB sampling or display scanout latency.
Use event timestamps and dependency identity; mouse coordinates/key content
are unnecessary for scheduling. [Linux input flow](https://docs.kernel.org/input/input-programming.html).

No new signal makes a blocked GPU consumer runnable before completion or
guarantees more GPU throughput. Preserve affinities, cgroup entitlement,
higher scheduling classes and bounded service for unrelated tasks. Validate
device-event-to-execution separately from render time and input-to-photon.

## Evidence and disposition

- Current host: Ryzen 7 9800X3D, 16 threads, one LLC; kernel
  `7.2.8-1-cachyos-custom`, boot `e4d51516-9170-4a66-b0bd-1e47327fab05`.
- 12/12 load-only configurations and 24/24 scheduler slots succeeded. Journal
  shows 24 enables and 24 normal user-space unregisters; no verifier rejection,
  runnable stall, watchdog, warning splat or oops in the host measurement window.
  Existing direct slice/vtime and cpu_acquire/release deprecation messages
  remain, as does the loader's existing MEMLOCK warning.
- 34 Rust unit tests + 3 integration tests passed; one privileged topology
  test ignored. Debug/release Clippy, formatting and release build passed.
  Fourteen focused diagnostic harness tests passed, including mismatched
  bytes, source escape, pair symlinks and missing native-mode confirmation.
- Fresh host scalar check: 1,156 CTZ/POPCNT vectors, 5,780 program runs,
  zero mismatches. The old runner requires an output-directory argument before
  `--check-only`; an initial invocation also ran its timing section. Those
  unplanned timings are retained but excluded from all performance conclusions.
- Booted the installed kernel image in isolated QEMU/TCG. Its build ID
  `f1273a7dd1ebe1c8e8a9c45abd910cd50f80f2d5` matches the live kernel's notes,
  and extracted BTF matches the live BTF. All three scalar selftest programs
  passed: zero/boundary/single-bit cases, 1,024 pseudorandom states, and
  callee-saved-register preservation for CTZ, POPCNT, CLZ and MULHI.
  They also passed with kernel BMI1/POPCNT/ABM feature flags cleared; the
  guest `/proc/cpuinfo` confirms their absence. This exercises unary C
  fallback selection, not an alternative architecture or a performance result.
- In a VM-only copy of the measured Cake executable, changed all four scalar
  symbol names to unavailable, equal-length names without changing instructions
  or ELF layout. Default inspection loaded successfully; enabling native bitops
  failed before load on the missing CTZ symbol. The scheduler stayed disabled.
  This tests the exact absent-weak-symbol branches, not broad old-kernel support.
  Initial VM setup failed on the host userspace's AVX-512 requirement; isolated
  baseline libraries and init resolved it. Guest setup failures are retained
  separately and are not host kernel failures or successful validation runs.
- Full source HEAD `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a`, preserving
  prior dirty work. Final release SHA-256
  `238869478389fceceb64ffe681eebce1025c9c848ec050aa5b0606d5ed6d3723`;
  embedded BPF `889948f8cf0dff94238379fc9b39664314d9c2cc511cbcee89cba79c129d9b2c`.
- Binary/object/source snapshots and commands:
  `target/cake_assembly_20261002T012901Z/` in the scheduler checkout.
- Raw bytes/disassembly, complete frame CSVs and analysis:
  `/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_assembly_20261002T012901Z/`.
  Reproduce summaries with its `analyze.py`; `frames-analysis.json` retains
  every slot, both block effects, arm means, identity and accounting checks.
- Native scheduling restored, BPF runtime accounting `0`, pointer policy `2`.
  Removed only the two temporary capability-bearing activation copies after
  verifying their exact uncapped binary/object archives. The ordinary release
  binary remains available at `target/release/scx_cake`.

Keep the wrapper simplification as experimental code with positive screening
evidence. Do not change instruction defaults or claim the globally fastest
mode. Next performance gate is a matched-load repeated/holdout comparison
and a real-game capture, with separate instrumented attribution. The kernel
roadmap remains a design proposal; no new device or IRQ interface is built.
