# Further scalar-instruction passes — October 2, 2026

Selective CTZ/POPCNT fastcall is the better next compiler candidate from this
pass: it retains the CPU-selection reduction and avoids the earlier all-unary
CLZ histogram growth. Moving portable fallbacks out of line did not reduce the
native release code. A wider CTZ queue scan now has an exact-order prototype.
The [cost ladder §10](../../AUDIT_OPERATION_COST_2026-09-15.md#10-local-hardware-costs-and-further-instruction-passes-2026-10-02)
also records fresh 9800X3D hardware-counter measurements, including the cost of
the count-result masks. None of this promotes a new default.

## Scope and artifacts

The question was whether existing scalar instructions can do more useful Cake
work, or lose surrounding overhead, without changing scheduling decisions.
Source HEAD is `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a` with the preserved
dirty tree. The experiment plan, source snapshots, two experimental release
builds and restoration evidence are under:

- Candidate: `/home/ritz/Documents/Repo/scx/target/cake_instruction_pass_20261002T072438Z/`
- Measurements: `/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_instruction_pass_20261002T072438Z/`

The ordinary release binary and its exactly-once embedded BPF were restored
byte-for-byte after both builds, before host measurement. Production
`cake.bpf.c` and `main.rs` are unchanged from the start of this pass. No kernel
was installed or rebooted. Division-free stayed off in the host comparisons.

| Build | Binary SHA-256 | BPF SHA-256 |
|---|---|---|
| Ordinary release | `238869478389fceceb64ffe681eebce1025c9c848ec050aa5b0606d5ed6d3723` | `889948f8cf0dff94238379fc9b39664314d9c2cc511cbcee89cba79c129d9b2c` |
| Selective CTZ/POPCNT fastcall | `3b54509442c602adee19ddbf52ba84d969d0f60dd3afa5e2843e0ffd0708a422` | `717e50edc506a317190a742e0e17672a18bba6a0c551fbb46c0545cc24bfb059` |
| Selective + portable fallback outlining | `71b0be5a725a6c94ec72cfcbd69c0bc330e55e75b71c3690523e4282c9b099f8` | `cd667f49159a0435d6c4ef71bd64f4042384dd8d3ec5a876df3d2a481aa99d79` |

Release build flags remain `cargo build --locked --release -p scx_cake -j4`.
The selective build force-includes [fastcall-selective-decls.bpf.h](fastcall-selective-decls.bpf.h)
through `BPF_EXTRA_CFLAGS_PRE_INCL`. The outlined patch is retained as
`portable-outline.patch` alongside the candidate. It introduces noinline
portable CTZ/POPCNT bodies and leaves the native branches inline. These are
research variants, not build-host-dependent production defaults.

## Pass 1: selective fastcall, verified in real loaded release code

The earlier header annotated CTZ, POPCNT and CLZ. The new header annotates only
CTZ and POPCNT. This is a compiler change; no new scalar kfunc is needed.
[Clang documents](https://clang.llvm.org/docs/AttributeReference.html#bpf-fastcall)
the recognizable compatibility spill/fill pattern. The kernel decides whether
its preservation contract allows removal; compiler annotation alone is not proof
of removed saves. The retained unary-fastcall kernel and the installed kernel's
image were both tested in VMs.

Actual native instruction counts with `--native-bitops`, probe off, on the
retained patched kernel, identical two-vCPU topology:

| Callback | Ordinary | Previous all-unary fastcall | Selective | Selective + outlined fallback |
|---|---:|---:|---:|---:|
| select_cpu | 1,423 | 1,415 | **1,414** | 1,425 |
| enqueue | 1,952 | 1,950 | 1,953 | 1,953 |
| dispatch | 1,163 | 1,161 | 1,162 | 1,164 |
| stopping | 306 | 306 | 306 | 306 |

Selective select_cpu is 5,949 bytes versus 5,984 ordinary, with 71 versus 80
translated-BPF stack accesses. Enqueue increases one native instruction despite
two fewer BPF stack accesses; this is not a uniform whole-scheduler count win.
Under native histograms with probe on, stopping returns to **493 instructions,
2,044 bytes, 46 stack accesses**, versus the all-unary header's 499 / 2,068 / 52.
Portable-mode compiler layout also changes even when verifier pruning removes
the native arms; a dormant C path can affect register allocation before loading.

The older kernel image retains compatibility saves. Its bitops select_cpu is
1,436 ordinary versus 1,430 selective, enqueue 1,968 versus 1,969, and dispatch
1,174 versus 1,173. Different kernel build configurations mean these absolute
counts should not be compared with the patched-kernel row as a patch-only delta.

Native, feature-disabled fallback, and older-kernel VMs passed **36 Cake
inspection loads and 10 activation/restoration smoke tests**. The existing
scalar selftest object also passed 18 positive program executions and three
expected MULHI preservation rejections. All VM results are correctness/codegen
evidence, not hardware latency. The new candidates' short activation tests do
not replace long-run fairness, hotplug or multithreaded stress validation.

## Pass 2: outlining the portable branch

This experiment tried to stop a large portable bit-count expression from
affecting the native branch's register allocation. The loaded code went in the
wrong direction: outlined select_cpu has two more instructions than ordinary
and eleven more than selective, with ordinary's 80 stack accesses rather than
selective's 71. Dispatch and enqueue also grow relative to ordinary.

This rejects the proposed instruction-count mechanism in this build, not every
possible inlining policy or its unmeasured hardware performance. The patch is
archived for review; it was not left in Cake's scheduling source.

## Pass 3: CTZ skips empty spans in the generic queue ring

[wide-ring-scan.h](wide-ring-scan.h) contains a prototype for the generic linear
ring fallback, after any topology-specific steal-order branch. It loads a qmask
word on the same word transitions, bounds eligible bits to the current segment,
and uses CTZ to jump to the next marked CPU. Wraparound still stops before the
calling CPU. It must not replace a loader-ranked or cross-LLC-filtered order.

The [UBSan-enabled differential validator](wide-ring-validate.c) passed:

| Coverage | Cases |
|---|---:|
| Every mask/source/early-success position for spans 1–10 | 188,412 |
| Every span 1–1,024 and source, empty/full/self/boundary patterns | 2,099,200 |
| Seeded arbitrary masks, early success and alternating per-read mutation | 200,000 |
| Total, zero mismatches | **2,487,612** |

Checks compare the complete attempted-CPU list, qmask word-read list and values,
return value, and bounded progress. They use identical values per corresponding
read, not a model of every real concurrent timing interleaving. A faster scan can
observe a real writer at another time. No zero CTZ or undefined shift occurred.

For source CPU 0 on an empty 1,024-CPU span, source-level loop iterations fall
from 1,023 to **16**, with the same 16 word reads. Full masks still take 1,023
iterations, and the candidate adds per-iteration calculations. Density matters.
This body has not been integrated or verifier-tested in Cake and has no hardware
timing. The 9800X3D's 16-thread one-word path already has a separate opt-in CTZ
experiment; do not count the wider-host prototype as a new benefit on this host.

## Host measurements: same frozen release pair, current kernel

The host runs `7.2.8-1-cachyos-custom`, boot
`e4d51516-9170-4a66-b0bd-1e47327fab05`. It has the original four scalar
operations but **not** the later unary `KF_FASTCALL` kernel patch. Thus this
comparison prices the selective compiler layout with older-kernel compatibility
saves retained. It does not measure the patched-kernel spill-removal benefit.

Both binaries use `--native-bitops --toggle probe=0`. The maintained
`cakebench cost --no-build --arm-artifact ...` route validates retained
binary/BPF/source identities; these are diagnostic identities, not canonical
score/promotion receipts. The appsim specification is the fitted Helldivers 2
mission workload with duration reduced to 15 seconds. It is a CPU simulation,
not the game or a GPU/input benchmark. Fixed-cadence FPS is not throughput.

Two host load-only inspections passed before measurement. Native byte lengths
are available in `programs.tsv`, but native bytes are **hidden** at the retained
`kptr_restrict=2`; `jit_visible=false`. The files with actual native disassembly
in this pass are VM captures. Host metadata reports select_cpu 6,361 → 6,338
bytes, enqueue 8,419 → 8,417 and dispatch 4,935 → 4,930. Translated BPF is visible;
its stack-access counts are respectively 80 → 73, 121 → 119 and 76 → 74.

### Initial five-block instrumented screen

Twenty valid slots, order `ABBABAABABBABAABABBA`, 623,740 frames, accounting
enabled. The table contains equal-weight slot means. The intervals use five
paired block effects and Student t with four degrees of freedom. They describe
the observations under this desktop load; workload interference prevents causal
performance acceptance even if a particular interval were narrow.

| Metric | Ordinary | Selective | Change B − A | Paired 95% interval |
|---|---:|---:|---:|---:|
| select_cpu ns/call | 141.461 | 142.563 | +1.102 | −16.479 to +18.682 |
| enqueue ns/call | 371.554 | 384.322 | +12.769 | −114.490 to +140.027 |
| dispatch ns/call | 101.195 | 93.367 | −7.828 | −108.489 to +92.834 |
| BPF CPU ms/second | 96.564 | 95.267 | −1.297 (−1.34%) | −56.132 to +53.538 |
| Frame p99 ns | 629,160 | 627,440 | −1,720 | −24,979 to +21,539 |
| Frame p99.9 ns | 714,420 | 694,670 | −19,750 | −225,971 to +186,471 |

Total busy spans **41.45–82.98%**. Whole-phase sampled Unreal process activity
averages **27.14% of total machine capacity**, including gaps and attachment
time; it is not a per-slot matched external-load measurement. Average arm busy
61.32% versus 61.17% conceals major within-block differences. Dispatch's five
effects are −113.03, −4.84, +113.82, −28.18 and −6.91 ns/call. This is why the
small overall average cannot be called a repeatable instruction saving.

### Separate probe-off frame screen

Eight valid slots, order `ABBABAAB`, 249,496 frames. BPF accounting remained off,
with zero lifetime counters verified by the harness. p99 changes **−450 ns**,
p99.9 **−3,850 ns**, mean adjacent-frame absolute jitter **−422.8 ns**, mean
slot maximum **−35,750 ns**, and 0.1% low FPS **+26.28 (+1.79%)**.

The two p99 effects are **−1,550 and +650 ns**, and p99.9 effects **−12,600 and
+4,900 ns**. Every corresponding two-block t interval includes zero; two blocks
are only a screen. Total busy spans 30.44–45.76%, with 34.59% in A versus 30.71%
in B. Background work fell during the first block. The raw non-appsim subtraction
even becomes negative (down to −0.87%) in some quiet slots: its two accounting
sources are not precise enough to price near-zero external activity. Those
values are retained and marked physically invalid as a background estimate,
not clamped into a false zero-noise claim. One-second process samples are also
retained; whole-phase observed Unreal activity is 1.48% of machine capacity.

### Quiet-start follow-up

After the initial screens, a fresh five-second `/proc/stat` sample measured
0.314% background busy. A new five-block cost experiment was declared before
running, with the same frozen binaries, arguments, workload and slot order.
It is retained separately as `quiet-cost`; no original samples are excluded or
pooled into it. Its primary outcome remains select_cpu ns/call, with aggregate
BPF cost, other callbacks, frame tails and stability as guardrails.

All 20 slots passed, retaining another 623,740 frames. The run started near
30.6% total busy, but separate Blender activity appeared during block four.
Slot 14/A reached 38.7% and slot 16/B 90.4% total busy. One-second process
samples identify Blender using roughly 68–70% of total machine capacity during
the latter slot; instantaneous total busy approached 100%. No process was
stopped. This cohort is **quiet-start, later Blender-contaminated**, not a clean
hardware confirmation.

| Metric | Ordinary | Selective | Change B − A | Paired 95% interval |
|---|---:|---:|---:|---:|
| select_cpu ns/call | 85.134 | 84.797 | **−0.337** | −4.136 to +3.461 |
| enqueue ns/call | 166.779 | 160.520 | −6.260 | −26.933 to +14.414 |
| dispatch ns/call | 17.573 | 53.799 | +36.226 | −58.725 to +131.178 |
| BPF CPU ms/second | 41.444 | 33.401 | −8.043 (−19.41%) | −33.211 to +17.124 |
| Frame p99 ns | 619,750 | 638,930 | +19,180 | −33,037 to +71,397 |
| Frame p99.9 ns | 650,550 | 724,300 | +73,750 | −133,453 to +280,953 |

The select_cpu block effects are +0.599, −0.604, +3.131, −5.226 and +0.414
ns/call. The large apparent aggregate CPU saving is concentrated in block four;
the other four aggregate-cost effects are all positive. It must not be attributed
to a few removed instructions. Callback frequency and which scheduling paths
run change with the competing workload. All blocks, including the interference,
remain in the estimates. The three cohorts are not pooled. No performance win
or loss is established for the selective variant.

Together the host screens passed **48/48 slots and retained 1,496,976 frames**.
All returned normally and restored native scheduling. BPF accounting returned
to zero. Temporary provisioned copies retain their exact bytes but have had
their file capabilities removed after measurement. Relevant raw output directories are:

- `runs/cost/20261002T023746_appsim/` — initial instrumented screen.
- `runs/cost/20261002T024449_appsim/` — accounting-off frame screen.
- `runs/cost/20261002T024932_appsim/` — separately declared quiet-start screen.

`cost-analysis.json`, `frames-analysis.json`, `quiet-cost-analysis.json` and
the process-sample JSONL files live in the measurement root named above.
Intervals are descriptive with five or two blocks, no multiple-metric correction
or holdout-based acceptance. Real games, input latency, GPU behavior and a host
boot with unary KF_FASTCALL remain outside this evidence.

## Pass 4: shorter native patterns for a future JIT patch

The [three small compiler probes](bit-pattern-probes.c), built with Clang
22.1.8 `-O2`, distinguish existing C opportunities from operations the BPF JIT
currently recognizes:

| Expression | BPF v3 body, excluding exit | Native `-march=znver5` body, excluding return |
|---|---:|---|
| `word & (word - 1)` | 3 instructions | 1 BLSR |
| `word & ~excluded` | 3 instructions | 1 ANDN |
| Cake's variable ring rotation | 10 instructions | LEA, NOT, SHRX, SHLX, OR |

These are compiler probes, not loaded BPF timings or a new kernel patch. The
retained loaded native-bitops Cake dumps have no BLSR/ANDN. The local x86 JIT
emits the ordinary BPF ALU operations individually; a safe peephole could combine
eligible patterns, with register liveness, branch-entry and CPU-feature checks.

Actual matching clear-lowest sites are the irregular SMT expansion and marked
queue loop. **The failed-claim expression `w &= ~(1ULL << c)` is not generally
equivalent:** `c` comes from preference filtering and need not be the lowest
bit of `w`. Substituting BLSR there could repeatedly choose a failed CPU or
discard the wrong candidate. Mask exclusion matches IRQ/seat preference
filtering, but hoisted/shared complements must retain their other uses.

The rotate probe is also useful negative evidence: even the native compiler
chooses a BMI2 two-shift sequence here. Adding a rotate kfunc without including
argument moves and RCX preservation cannot be presumed cheaper. Prefer JIT
pattern recognition over an extra ordinary-ABI helper when it removes the same
scalar work without introducing call overhead; that is a hypothesis to validate.

## What remains worth implementing next

1. **Range information for scalar returns.** In the retained kernel,
   `check_kfunc_call()` marks ordinary scalar returns unknown. A trusted range
   contract for these operations could let a compatible Cake path omit some
   result masks. CTZ/CLZ need `[0,64]` generally and `[0,63]` only after proving
   nonzero input; POPCNT is `[0,64]`. Input facts must be captured before caller
   registers are invalidated. Test zero and unknown inputs, pointer-index safety,
   hardware-disabled fallbacks and old-kernel selection. No such verifier patch
   was made in this pass. The local mask-chain measurement prices the opportunity,
   not the benefit of an unimplemented patch.
2. **Finish the compiler/verifier spill-layout investigation.** Selective
   annotation avoids the observed histogram growth now. A minimized reproducer
   for mixed fastcall stack layouts could recover CLZ's spill removal without
   broadly relaxing the verifier's alias/stack checks.
3. **Integrate and test the wider scan only on its matching topology path.**
   Preserve locality matrix ordering and queue-observation rules, then measure
   sparse and dense occupancy separately. Native CTZ call/ABI cost can dominate
   when nearly every CPU is marked.
4. **Compile-time native specialization remains a separate experiment.**
   Current volatile mode loads can survive verifier pruning. Multiple portable
   and native objects, selected and validated by the loader, could remove them;
   deleting runtime capability validation or hardcoding this host is not that
   implementation.

The pass also rechecked shifts and multiplication: the retained x86 JIT already
emits BMI2 SHLX/SHRX when the source register calls for it. Generic low multiply,
AND/OR and shifts do not need extra kfunc calls. Irregular SMT expansion already
uses CTZ; its regular-layout fast path is a few word operations. Rank-tier scans
read preference masks, so a count instruction alone cannot replace that search.
Additional MULHI in wrap-prone ratio comparisons would be a separate correctness
and policy experiment; it is not a free instruction substitution. Complete
division-free setup remains substantially more than one CLZ/MULHI instruction.
