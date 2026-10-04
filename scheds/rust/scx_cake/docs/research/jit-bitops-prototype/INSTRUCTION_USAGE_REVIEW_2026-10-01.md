# Cake scalar instruction review and additional usage experiments — 2026-10-01

**Two new uses produced callback savings worth confirming: CTZ queue scans and
CLZ diagnostic histograms. MULHI vtime remains inconclusive.** All 32 live
slots passed; 996,188 simulated frames are retained. Background compilation
and Unreal activity prevent performance acceptance. Original scheduler source,
release binary and embedded BPF object were restored byte-for-byte.

Question: where can the four added scalar operations reduce Cake's real callback
cost while preserving arithmetic, CPU preferences, liveness, and frame behavior?
This review includes source inspection, compiler output, exact offline checks,
and new paired diagnostic measurements. It does not promote a scheduler default.

## What the kernel patch actually supplies

The combined patch registers four scalar kfuncs and recognizes their calls in
the x86 BPF JIT. It exposes existing CPU operations to BPF; it adds no scheduler
signal or task statistic. Cake still reads the same runtime, voluntary-switch,
idle-mask, and queue-mark data.

| Operation | Patched x86 body | Existing Cake usage | New usage tested |
|---|---|---|---|
| CTZ | `TZCNT RAX,RDI`, with BMI1 | Select a CPU from a ranked nonzero mask; generic SMT-mask expansion | Iterate only marked steal queues, preserving sibling-first preference |
| POPCNT | `POPCNT RAX,RDI`, with POPCNT | Count idle CPUs for the three-quarters-idle serial handoff gate | No additional required population count found in normal BPF policy |
| CLZ | `LZCNT RAX,RDI`, with ABM/LZCNT | Normalize the divisor in the experimental reciprocal quotient | Compute saturated logarithmic probe-histogram buckets |
| MULHI | `MOV RAX,RDI; MUL RSI; MOV RAX,RDX` | Two reciprocal-refinement products plus the numerator product | Exact full-width fixed-point vtime scaling |

Feature-ineligible unary operations fall back to ordinary kernel calls in the
patch. Cake checks feature/symbol availability before selecting its native
modes. The patch does not mark these kfuncs `KF_FASTCALL`: compiler argument
moves, live-register handling, and the ordinary call ABI remain relevant even
when the JIT replaces the call itself with a short instruction sequence.
[Clang's fastcall contract](https://clang.llvm.org/docs/AttributeReference.html#bpf-fastcall)
requires preservation beyond that ordinary ABI. MUL writes RDX, which maps to
BPF R3; merely adding fastcall flags to the existing two-argument MULHI body
would violate that contract.

The installed kernel exposes all four symbols and the live Cake experiments
exercise the selected kfunc paths. Fresh current-boot native JIT byte dumps and
standalone CLZ/MULHI kernel selftests remain uncollected. The retained patch
explains expected lowering; it is not an authenticated build receipt for the
booted kernel. Prior CTZ/POPCNT primitive JIT evidence belongs to its recorded
earlier boot, not automatically this one.

## Why division-free lost while bitops looked helpful

Default dynamic BPF division already lowers to hardware division plus register
setup/preservation on x86. It is not a software long-division loop. The BPF ISA
defines ordinary division and low-half multiplication; the additional kfuncs
fill different gaps. [Kernel BPF ISA documentation](https://www.kernel.org/doc/html/latest/bpf/standardization/instruction-set.html).

The exact reciprocal implementation constructs its reciprocal for every
quotient. On the general path it performs one CLZ, a seed-table read, eight
low-half multiplies, three MULHI operations, shifts/adds/comparisons, and final
correction. Two MULHIs build the reciprocal; only the third applies it to the
numerator. There is no reciprocal reuse across ordinary calls. Admission can
conditionally request a second quotient with the same divisor and recompute
the reciprocal; it already reuses the first quotient when the dividend matches.
That conditional frequency has not been instrumented.

The Möller–Granlund paper provides the reciprocal algorithm and discusses
amortization and single-division results on older processors. Those measurements
do not establish a win for this single-word BPF implementation on Zen 5.
[Improved division by invariant integers](https://gmplib.org/~tege/division-paper.pdf).
Runtime-divisor libraries similarly separate reciprocal generation from reuse.
[libdivide](https://libdivide.com/).

Fresh Clang 22.1.8 BPF v3 probes, counting operations including exit but excluding
relocation annotations and extra slots of wide immediates:

| Standalone function | BPF operations | Scalar kfunc calls | Explicit BPF stack accesses |
|---|---:|---:|---:|
| `x / (d | 1)` | 4 | 0 | 0 |
| Full native reciprocal quotient, odd divisor | 94 | 4 | 4 |
| Existing full-range vtime scaling, both branches | 17 | 0 | 0 |
| MULHI full-range vtime scaling | 11 | 1 | 0 |
| Existing 16-band histogram | 32 | 0 | 0 |
| CLZ 16-band histogram | 8 | 1 | 0 |

These are static function sizes, not executed counts or latency estimates. The
ordinary vtime fast path executes only one low multiply and a shift after its
range check; its slow branch is included in the 17-operation total. Histogram
loops may exit early. Kernel-emitted native bodies are not included in these
BPF counts. An initial count of 97 for the quotient accidentally included three
relocation annotations; the corrected count is 94.

All Cake quotient divisors are `nvcsw | 1`. The generic power-of-two shortcut
adds nothing beyond divisor one; LLVM actually eliminates that test in the
odd-divisor probe. Conversely, LLVM retains `normalized & 1` and a multiply by
that value even though normalization shifts by 1–63 and makes it zero. An
explicit even-normalized reciprocal could trim that work, but would still pay
the main reciprocal setup. This is an untested follow-up, not an explanation
that requires inventing a hidden hardware fault.

In the preceding five-block screen, division-free cost **+5.81% BPF CPU**, with
`select_cpu` **+11.01 ns/call** and `enqueue` **+9.40 ns/call**. Select ran about
159,332 times/s in that arm. Its measured contribution rose **1.754 ms/s**, about
**91.2%** of the total **1.923 ms/s** increase. This matches the direct
slice/admission quotient call sites. No new scheduler signals were involved.

Existing native CTZ/POPCNT instead replace expanded bit-count sequences without
constructing a reciprocal. LLVM's BPF lowering marks CTZ/CLZ/popcount for
expansion, matching our installed compiler probes.
[LLVM BPF lowering source](https://llvm.org/doxygen/BPFISelLowering_8cpp_source.html).
The prior bitops screen measured enqueue **-5.87 ns/call** and total BPF CPU
**-0.47%**, but the total interval crossed zero. It did not isolate CTZ from
POPCNT. Its `running` reduction is not direct instruction savings: the normal
old `running` and `irq_leave` paths execute none of the four new operations.
Indirect effects, invocation mix and measurement variation remain possible.

## Complete usage audit

| Area | Finding and decision |
|---|---|
| Cold CPU picker | Existing native CTZ already covers the shared picker used by placement and pool-claim paths. Replacing additional callers individually would duplicate the wrapper. |
| SMT expansion | Existing CTZ covers irregular sibling maps. This host's uniform sibling distance of eight uses shifts/OR instead; no per-bit scan to accelerate there. |
| Serial handoff gate | Existing POPCNT counts the local idle mask. The wide-host path uses an existing count. Additional popcounts for empty/single-bit tests would replace already cheap comparisons/bit tests without supplying needed information. |
| Steal queues | New CTZ candidate skips clear queue marks. Host order is sibling first, then circular CPU order. The loader checks equality with its existing matrix before accepting the experiment. A plain generic ring would have changed that order. |
| Wide generic ring | CTZ per qmask word is a promising extension for sparse queues above the matrix span. Not implemented/live-tested on this 16-thread host. |
| CPU performance tiers | The loop searches an array of tier masks, not a bitset of matching tier IDs. CTZ cannot directly replace it without another representation or building that bitset. No simple scalar substitution established. |
| Foreign LLC pools | Marks are separate pool fields, not a shared mask. CTZ would require extra shared state/maintenance. No one-LLC benefit; deferred. |
| Slice, burst, starvation credit | Full reciprocal division is already routed through the common helper. Comparisons already use bounded cross-products where possible. More unconditional native calls would not remove reciprocal setup. |
| Vtime weights | Reciprocals are already precomputed. New MULHI experiment reconstructs the low 64 bits of the shifted full product, avoiding the overflow split. Common-path extra multiply/ABI costs must be measured. |
| Histograms | Two new CLZ sites replace bounded log2 loops, with zero forced to one and the original saturation preserved. These sites are diagnostic-only: no default-path frame benefit is claimed. |
| Single-bit masks, powers of two, constant scaling | Existing AND/OR/shifts and comparisons already express these operations cheaply. POPCNT/CLZ calls are not automatic improvements. |
| Atomics and packed fields | The four added scalar operations do not supply atomic bit-test/set/clear or carry/rotate operations. Those would need distinct kernel/JIT work and concurrency validation. |
| Rust loader and monitor | Kernel BPF kfuncs are not userspace Rust intrinsics. Topology construction and reporting are separate costs; no new per-callback kernel usage follows from rewriting those loops. |

## Candidate contracts and verification

Three independent research flags gate the new uses; original division-free stays
off in every new measured arm. Each requested flag has explicit startup
confirmation checked by the maintained runner. All flags are off by default.

The CTZ scan snapshots eligible queue marks, tries the SMT sibling first, rotates
the remaining mask, and enumerates its set bits. Static-mask order matches the
existing matrix. Its snapshot can miss a mark published during the walk; marks
are steal hints and owners are woken, so this is not an assertion of identical
concurrent interleavings or a formal liveness proof. Unsupported topologies
fail closed for this research flag. The generic/default routes remain available.

The vtime candidate computes
`base + ((runtime * reciprocal) >> 20 | (mulhi(runtime, reciprocal) << 44))`,
with unsigned wrap semantics matching the existing full-range result. The
histogram candidate computes `min(63 - clz((ns >> shift) | 1), bands - 1)`.

The exact shared candidate helpers passed UBSan-backed independent checks:
388,228 queue-order cases, 2,009,450 vtime cases, and 4,524,672 histogram cases,
with zero mismatches. Tests include CPU 63, rotation by zero, empty/full/sparse
masks, all spans 1–64, weight levels, overflow boundaries, maximum unsigned
values, bucket boundaries, saturation, and randomized inputs. Native arithmetic
uses actual TZCNT/LZCNT/MUL in the userspace test; this is not a BPF kernel
primitive selftest. Rust: 33 unit and 3 integration tests passed; one privileged
topology verifier test was ignored. Debug/release package Clippy and release
build passed. Cargo emitted its existing unrelated `scx_rustland_core`
unused-manifest-key warning; no candidate compiler/Clippy diagnostics occurred.

The preserved experimental binary is
`84516a012b2b2f3b1779193ff89069fbf5573746fe7a04158a2a29feae70a60f`, with embedded
BPF `699c0880857929112e2ae45aa29a1182b4134bec2b9e20812324224d940a8774`.
The source snapshot, expansion-only patch, baseline, disassembly, command logs,
and identity are retained under `target/cake_scalar_expansion_20261001/`.
Measurement identity, plans, all frames and raw slot metrics are under sibling
`scx_cake_bench/runs/native_scalar_expansion_20261001/`.

## New measured results

The maintained `cakebench cost` runner completed two independent screens,
ABCDDCBA followed by DCBAABCD in each. Each mode therefore has four 15-second
observations in two blocks. All 32 slots passed source/binary identity, requested
mode confirmation, verifier load, activation, normal exit and restoration.
The kernel journal independently records 32 enables and 32 normal disables,
without a warning, Oops or watchdog event. Native scheduling and BPF statistics
were restored. No new default policy was accepted.

These are source-attributed diagnostic runs with basic binary/object pairing,
not score-bearing v5-receipt comparisons against EEVDF. Unreal, compiler jobs
and Discord were present. Main-screen total busy ranged **57.91–96.94%**;
estimated non-appsim busy **25.34–66.88%**. Histogram-screen total busy ranged
**63.86–94.31%**; non-appsim estimate **30.81–65.75%**. The latter subtracts
appsim child CPU from host busy and includes harness/kernel overhead. A pure
external-process CPU average was not measured. Noise class:
`desktop_and_unreal_contaminated_diagnostic`.

### Non-probe screen: baseline is existing native CTZ/POPCNT

| Additional use | BPF CPU change | Dispatch delta ns/call | Frame p99 delta ns | Frame p99.9 delta ns | 0.1% low FPS |
|---|---:|---:|---:|---:|---:|
| CTZ queue scan | -2.21% | -18.05 | -10,550 | +95,850 | 728.19 vs 843.24 |
| MULHI vtime | -25.35% observed, confounded | -208.78, confounded | -113,725, confounded | -304,900, confounded | 1,173.03, confounded |
| Both | -27.51% observed, confounded | -214.55, confounded | -94,475, confounded | -205,425, confounded | 1,104.66, confounded |

The MULHI arms averaged about **69% busy**, versus **87%** for baseline/CTZ.
That invalidates interpreting their large apparent improvements as an
instruction benefit. It also changes callback invocation mix: callback means
and total BPF time cannot repair the confound automatically.

CTZ scan versus baseline lowered dispatch by **31.22 and 4.89 ns/call** in the
two blocks and total BPF by **4.539 and 3.499 ms/s**. Its mean jitter fell
**4,637 ns**, but p99.9 worsened in both blocks and 0.1% low FPS fell. On the
MULHI background, adding CTZ lowered dispatch **10.43 and 1.12 ns/call**, but
frame tails were again mixed/worse overall. These are useful signs, not an
accepted net win. In the separate probe-on screen, CTZ-only versus baseline
reversed direction: dispatch **+44.15 ns/call**, total BPF **+5.49%**, amid a
higher and changing load. Do not hide that result or pool the two workloads.

### Probe-on screen: measure diagnostics separately

| Comparison | BPF CPU change | Stopping delta ns/call | Running delta ns/call | Frame p99 delta ns | Frame p99.9 delta ns |
|---|---:|---:|---:|---:|---:|
| CLZ histograms vs original histograms | -1.09% | -8.21 | -1.76 | +40,600 | +99,150 |
| CLZ histograms added to CTZ scan | -2.46% | -11.09 | -3.05 | -85,300 | +96,400 |

The CLZ-only stopping deltas were **-6.44 and -9.98 ns/call**; adding CLZ to
CTZ gave **-7.83 and -14.35 ns/call**. That agrees with the burst/handoff
histogram mechanism. Aggregate BPF deltas changed sign between blocks, while
CLZ-only frame p99, p99.9 and jitter all worsened. Its 0.1% low FPS was
**780.37 vs 838.30**. This supports a candidate for reducing probe overhead,
not a default-path gaming claim.

The baseline probe census recorded **16,604,680 selects**, only **343 serial
gate attempts** (0.00207%), and **3,446,757 steal-move attempts**. The latter
counter increments before the move and is not a successful-steal count. It
also does not distinguish a successful sibling-first try from a later CTZ-loop
try. These are lifetime census counts, including the settling interval, not
counts over exactly the BPF-stat measurement window.

Baseline histogram distributions explain the likely opportunity: **83.25%**
of hop samples were bucket zero, with mean bucket **0.21**; mean handoff bucket
was **6.18**, and burst **5.73**. The old loops do little work for most hops and
more for handoff/burst. This is a source/data explanation of where savings can
arise, not independent causal timing proof.

All frames and all slots are retained, with no trimming or exclusions. Only
two independent blocks per screen were collected; correlated frames do not
supply hundreds of thousands of independent comparisons. Fixed-cadence appsim
FPS is not uncapped game throughput. These experiments measure no actual game
or input-to-display latency.

## Disposition and next experiments

- **CTZ scan: needs a clean rerun.** Preserve it as an isolated patch. Confirm
  callback savings and the p99.9/0.1%-low guardrails with frozen matched blocks;
  count sibling-first versus CTZ-loop attempts in a separate diagnostic run.
- **CLZ histograms: needs a clean diagnostic rerun.** Repeated stopping savings
  fit the source mechanism. Keep probe-on comparisons separate from ordinary
  scheduler performance, and retain tail regressions in the decision.
- **MULHI vtime: inconclusive.** The common original path is one multiply plus
  a shift; full-width MULHI adds a second product and ABI work. The smaller
  total static function is not evidence of cheaper ordinary slices. Compare
  at matched load before either accepting or rejecting it.
- **Existing CTZ vs POPCNT:** separate ablations are still needed to assign the
  earlier combined-bitops improvement to one primitive. The current heavy-load
  POPCNT gate frequency cannot be substituted for the earlier quiet workload.
- **Kernel follow-up:** safe unary fastcall could reduce overhead at existing
  sites without inventing more operations. It needs correct feature-disabled
  and non-JIT fallbacks, register-preservation tests and actual emitted-code
  inspection. MULHI requires a separate preservation solution.
- **Quotient follow-up:** explicitly specialize even-normalized reciprocal
  setup, or investigate reuse only where two quotients share a divisor within
  one admission. Measure that path's frequency first. Avoid adding per-task
  storage merely to save arithmetic unless its own cost is established.

The three expansion flags were removed from the working scheduler after
preserving the exact experiment; the original release binary and BPF hashes
match the pre-experiment baseline. Existing `--native-bitops` and
`--division-free` work remain intact. The temporary capability-bearing test
copy was removed; the uncapped archived binary, source and measurements remain.
No user application was stopped and no kernel/sysctl security setting changed.

## Reproduction and retained evidence

- [Expansion-only patch](../../../../../../target/cake_scalar_expansion_20261001/expansion-only.patch), applies cleanly to the restored dirty baseline.
- [Exact candidate source and binary](../../../../../../target/cake_scalar_expansion_20261001/candidate/).
- [Original source/build identity](../../../../../../target/cake_scalar_expansion_20261001/before.json) and [experimental identity](../../../../../../target/cake_scalar_expansion_20261001/identity.json).
- [Offline reproduction script](../../../../../../target/cake_scalar_expansion_20261001/reproduce.py), [validation](../../../../../../target/cake_scalar_expansion_20261001/offline-validation.json), [BPF counts](../../../../../../target/cake_scalar_expansion_20261001/probe-counts.json), and [disassembly](../../../../../../target/cake_scalar_expansion_20261001/reproduce-3.log).
- [Experiment plan](../../../../../../../scx_cake_bench/runs/native_scalar_expansion_20261001/plan.json), [full results](../../../../../../../scx_cake_bench/runs/native_scalar_expansion_20261001/RESULTS.md), [analysis and all slot metrics](../../../../../../../scx_cake_bench/runs/native_scalar_expansion_20261001/analysis.json), [analysis script](../../../../../../../scx_cake_bench/runs/native_scalar_expansion_20261001/analyze.py), and [kernel journal](../../../../../../../scx_cake_bench/runs/native_scalar_expansion_20261001/kernel.log).
- [Earlier five-repeat comparison](REPEAT_5X_2026-10-01.md), the source of the division-free regression discussed above.

Offline reproduction, with no scheduler activation:

```sh
python3 target/cake_scalar_expansion_20261001/reproduce.py
python3 /home/ritz/Documents/Repo/scx_cake_bench/runs/native_scalar_expansion_20261001/analyze.py
```

The retained plan/command files describe the diagnostic live screens. Native
security/capability provisioning and path validation must precede a new live
run; the archived binary itself has no file capabilities. Full games, broader
topologies, independent holdout and current-boot primitive JIT verification
remain separate gates.
