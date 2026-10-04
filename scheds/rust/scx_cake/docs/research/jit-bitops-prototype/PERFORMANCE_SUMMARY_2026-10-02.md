# Kernel patch and Cake performance: findings through October 2

We have meaningful measured callback savings, a promising frame-time screen,
and confirmed improvements in generated code. We also learned which changes
lose performance. We have not established a broad real-game, input-latency,
or end-to-end speedup from the complete patch stack.

The measurements below concern different changes. Most host comparisons use
the same already-patched kernel and vary Cake's flags or release code. Wrapper
cleanup compares two Cake builds with native bitops enabled in both. The newer
fastcall/bounds and DSQ kernels have VM/code-generation evidence. These are not
all estimates of one kernel-patch effect, and their percentages must not be added.

Later follow-up: [the direct DSQ index is now implemented and simulated](DSQ_DIRECT_INDEX_2026-10-02.md).
Its six ordinary-kernel VM configurations and 20 simulation slots passed;
emulated wall time changed −0.023%, with an interval spanning improvement and
regression. Hardware benefit remains unmeasured and the debug gate is open.
The chart pack below retains its original measurement snapshot.

## Charts and downloadable data

- [All five shareable PNGs, ZIP](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/scx_cake_performance_pngs.zip) (2,250 × 1,500 pixels each, labeled with scope and limitations)
- [All five charts in one self-contained HTML page](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/charts.html)
- [Five-page chart PDF](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/cake_performance_charts.pdf)
- [Metric comparisons, CSV](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/metrics.csv)
- [All 40 five-repeat slots, CSV](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/five_block_slots.csv)
- [Complete data, intervals, source paths and hashes](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/data.json)

Charts are also available as individual PNG and editable SVG files beside the
PDF. Negative time deltas mean faster; positive FPS deltas mean higher throughput
only when the workload actually measures throughput. Here, appsim is paced:
its approximately 2,079 average synthetic FPS is not an uncapped game FPS result.
1 µs = 1,000 ns. Jitter here is mean absolute adjacent-frame-time difference,
not mouse-to-display latency or scheduler wake jitter.

## 1. Most promising frame-time screen

Removing repeated wrapper symbol checks shrank loaded native select code by
four static instructions / 28 bytes. With CTZ and POPCNT enabled in both arms,
eight 15-second release slots produced this result:

| Metric | Before | After | Observed change |
|---|---:|---:|---:|
| Frame p99 | 655,150 ns | 633,300 ns | **−21,850 ns / −3.34%** |
| Frame p99.9 | 722,950 ns | 668,975 ns | **−53,975 ns / −7.47%** |
| Mean adjacent-frame jitter | 91,333 ns | 84,902 ns | **−6,431 ns / −7.04%** |
| 0.1% low synthetic FPS | 1,341.28 | 1,458.15 | **+8.71%** |
| Mean of slot maximum frame times | 828,700 ns | 823,100 ns | −5,600 ns / −0.68% |

Both paired blocks improved p99: **−22,950 and −20,750 ns**. This is a useful
positive result worth retaining. It does not prove that four removed instructions
alone caused a 21.85 µs difference. There are only two blocks, about 49% estimated
non-appsim CPU activity, no independent holdout, and no real game/GPU/input test.
BPF accounting was disabled throughout, so these are normal release frame results.

![Wrapper screen](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/02_wrapper_screen.png)

Source: [assembly and pipeline report](ASSEMBLY_PIPELINE_REVIEW_2026-10-01.md),
retained `cake_assembly_20261002T012901Z/frames-analysis.json` and the eight
original slot receipts. Every slot passes identity, continued attachment,
normal exit, restoration, and disabled-accounting checks.

## 2. What the five-repeat test supports

Five mirrored blocks, 40 valid slots, ten observations per mode and 1,247,480
simulated frames. This was a more stable host load than the first quick screen.

| Comparison against portable default | Observed change | Exploratory 95% interval |
|---|---:|---:|
| Bitops enqueue callback | **−5.87 ns/call / −2.59%** | −10.67 to −1.44 ns |
| Bitops running callback | **−0.83 ns/call / −2.43%** | −1.35 to −0.05 ns |
| Bitops total BPF CPU time | −0.47% | −1.13% to +0.16% |
| Bitops frame p99 | −400 ns | −1,730 to +530 ns |
| Division-free total BPF CPU time | **+5.81%** | +3.88% to +7.80% |
| Division-free frame p99 | +920 ns | −2,090 to +3,670 ns |

Enqueue and running were cheaper in four of five blocks. Those are small,
measured favorable callback results; the aggregate CPU and frame intervals
include zero. Not every callback moved favorably: `update_idle` increased
**0.085 ns/call** (exploratory interval +0.030 to +0.151 ns); dispatch and
stopping also have small positive point estimates with intervals crossing zero.
These observations do not isolate a causal cost in those unchanged paths.
Division-free increased BPF CPU cost in **all five blocks**,
and select_cpu became **11.01 ns/call slower**. Adding bitops to division-free
still increased total BPF CPU cost by **6.01%**.

The failure is informative: hardware MULHI/CLZ are useful primitives, but this
exact division replacement repeatedly constructs a reciprocal for changing
divisors. Actual select assembly exchanges three DIV sites for nine MUL and
three LZCNT sites plus surrounding work. More use of the new instructions is
not automatically cheaper. Host fixed-work application completion time was
not measured in this experiment, so no such wall-clock claim follows.

![Five-repeat measurements](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/01_hardware_repeats.png)

The plotted intervals were refreshed by enumerating all 3,125 paired bootstrap
resamples of the five blocks. The original report used 20,000 sampled bootstrap
resamples; small endpoint differences are expected. Neither method makes the
frames independent, adjusts for all tested comparisons, or establishes universal
benefit. BPF runtime accounting was enabled equally in all 40 slots.

The original report's named top-level `analysis.json` is absent. The 40 slot
receipts and original `table.txt` remain; this summary recomputes their results
without overwriting the old experiment. The reproduced points agree with the
[five-repeat report](REPEAT_5X_2026-10-01.md).

## 3. Confirmed primitive and code-generation findings

The installed scalar implementation emits **TZCNT, POPCNT, LZCNT and MUL** in
the retained host Cake JIT. Native bitops select contains three TZCNT sites and
one POPCNT site. These counts include referenced subprograms and are not a
per-invocation instruction trace.

Hardware PMU probes on the 9800X3D show why surrounding work matters:

| Dependent native sequence | Median core cycles/op | Median wall ns/op |
|---|---:|---:|
| TZCNT | 1.0006 | 0.1825 |
| TZCNT followed by AND 63 | 2.0012 | 0.3652 |
| LZCNT | 1.0005 | 0.1824 |
| LZCNT followed by AND 63 | 2.0013 | 0.3657 |
| POPCNT | 1.0006 | 0.1825 |

These userspace dependency chains include loop overhead. Each sequence has ten
16-million-operation batches with no PMU multiplexing. They demonstrate an
approximately one-cycle mask cost in these sequences, not a corresponding
whole-callback speedup. [Hardware-cost chart](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/03_instruction_costs.png).

The newer verifier/fastcall kernel and native specialization remove surrounding
work in actual loaded release code:

| Static measure | Baseline | Specialized | Change |
|---|---:|---:|---:|
| select_cpu native instructions | 1,444 | 1,418 | −26 / −1.80% |
| select_cpu BPF stack accesses | 80 | 67 | **−13 / −16.25%** |
| select_cpu native bytes | 6,087 | 5,961 | −126 / −2.07% |
| enqueue native instructions | 1,963 | 1,956 | −7 |
| dispatch native instructions | 1,177 | 1,173 | −4 |
| stopping native instructions, probe off | 306 | 306 | unchanged |
| Typed DSQ lookup own stack bytes | 96 | 32 | **−64 / −66.67%** |

The Cake comparisons use the same patched kernel and 8-core/16-thread VM.
DSQ comparison is a separate kernel change. Its generic comparison becomes a
64-bit comparison; hashing also inlines. Its body grows from 82 to 91 instructions
because the hash code moves in from a callee. That does not negate the removed
calls, and a smaller frame does not establish its ns cost. These candidates
still need hardware timing. [Code-generation chart](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/04_codegen.png).

The bounds/refactor pass passed 20,844 differential executions, 56 Cake inspection
loads and 8 activation checks. The subsequent DSQ candidate passed 26,248
differential executions, 42 inspection loads and 9 activation checks. These are
separate campaigns, partly reusing test vectors; do not count them as independent
performance repetitions. Removing precision tracking in a deliberate verifier
mutation made two invalid CTZ/CLZ programs pass verification; the retained patch
rejects both. Negative programs were never executed.

## 4. Other useful findings and failed approaches

| Experiment | What happened | Learning |
|---|---|---|
| Initial bitops quick screen | p99 −49,250 ns, BPF CPU −1.95%; high noise | The large first effect was not reproduced by the five-repeat screen |
| Later normal-release bitops screen | p99 +15,375 ns; mixed blocks | No consistent frame benefit across host conditions |
| CTZ queue scanning | p99 −16,650 ns versus bitops, but mean slot maximum +1,449,200 ns | Faster common-path observations can coexist with worse rare delays |
| CLZ diagnostic histograms | stopping −8.21 ns/call initially, −8.87 ns/call on follow-up | Repeated diagnostic-path savings; probe-off release does not run this path |
| Selective CTZ/POPCNT fastcall | Avoids the all-unary header's extra CLZ histogram instructions | Annotate selectively; a smaller local operation can change allocation elsewhere |
| Outlining portable fallbacks | Native select code grew | Source simplification/inlining intuition is insufficient |
| Removing masks without LLVM range information | Select code grew | Compiler and verifier must both know the valid range |
| Generic wide CTZ ring prototype | Empty 1,024-CPU ring: 1,023→16 loop iterations; 2,487,612 finite checks passed | Useful sparse-scan mechanism; not integrated or a measured benefit on this 16-thread host |
| Fastcall QEMU fixed-work test | +28,321 ns completion; interval −231,025 to +287,667 ns | No speedup established; guest timing is not a 9800X3D prediction |
| Quiet-start compiler comparison | select −0.337 ns; interval −4.136 to +3.461 ns; later Blender interference | Not a clean hardware confirmation of the newer kernel fastcall patch |
| Historical perf attribution | Analyzer included unrelated BPF in “Cake time” | Corrected denominator before using old profiles for prioritization |
| Direct-index DSQ table, later follow-up | Six ordinary-kernel VM configurations and 20/20 simulation slots passed; emulated wall time −0.023%, inconclusive | Implemented; hardware benefit unmeasured, debug gate open; see [report](DSQ_DIRECT_INDEX_2026-10-02.md) |

[Repeatability chart](/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z/05_repeatability.png)
shows the block effects from separate frame screens. The experiments differ
in code, flags, instrumentation and load; the chart is not a cumulative speedup.
The older KovaaK kick-policy results are deliberately excluded from patch gains:
they tested another scheduling-policy change, not these scalar instructions.

## 5. What the evidence supports now

- **Measured favorable results:** small bitops enqueue/running savings;
  repeated CLZ diagnostic savings; a promising two-block wrapper-cleanup frame
  improvement; approximately one-cycle native unary operations in PMU probes.
- **Confirmed implementation improvements:** real native scalar emission,
  less surrounding code/stack traffic with the right compiler/verifier contract,
  and a simpler kernel DSQ comparison. Runtime benefit of the newest candidates
  remains unmeasured on hardware.
- **Consistent loss in the tested implementation:** division-free raises BPF
  CPU cost. Leave it off for performance testing unless testing a different,
  demonstrably cheaper complete algorithm.
- **Still open:** repeatable real-game benefit, input-to-display latency,
  hardware performance of the newer kernel candidates, and broader topology/
  fairness stress. Callback savings and code-generation wins are useful even
  while these endpoints remain open.

Reproduce the charts without starting Cake:

```bash
python3 -B target/cake_performance_summary_20261002T151939Z/build_summary.py \
  /home/ritz/Documents/Repo/scx_cake_bench/runs/cake_performance_summary_20261002T151939Z
```

The generator, its console log, source-hash manifest, CSV exports, SVG/PNG figures,
and PDF are retained. This report generated artifacts only; it performed no new
scheduler activation, benchmark workload, kernel installation, or source refactor.
