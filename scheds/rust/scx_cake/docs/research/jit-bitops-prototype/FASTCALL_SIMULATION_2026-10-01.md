# Fastcall simulation: five balanced blocks

**Simulation completed successfully; no speedup established.** Both retained
release binaries ran under the actual fastcall-patched kernel in QEMU TCG.
All 20 slots passed, producing 60,000 simulated frames and completing
320,000,000 fixed-work arithmetic steps with matching checksums. Emulator timing
is mixed. This does not change the hardware-performance status of the
[fastcall patch](FASTCALL_KERNEL_REVIEW_2026-10-01.md).

## What ran

- A: ordinary release `238869478389fceceb64ffe681eebce1025c9c848ec050aa5b0606d5ed6d3723`.
- B: annotated release `9d0140ab824c15152e6e37f554efcabb6d2ba08516b33ad507c3387c33bdada2`.
- Same retained fastcall kernel image, two virtual CPUs, QEMU CPU `max`,
  multithreaded TCG, 2 GiB RAM. `/dev/kvm` remains unavailable.
- Both arms: `--native-bitops --toggle probe=0`; quotient, ring and native
  histogram modes off. BPF runtime accounting remained disabled.
- Predeclared order: `ABBA BAAB ABBA BAAB ABBA`, ten observations per arm.
- Unmodified maintained `bench/appsim/appsim.c`, compiled statically for the
  guest: six seconds at a 500 FPS pacing target, three serial stages and twelve
  periodic background threads. This synthetic specification is not fitted to
  a particular game. It measures a dependency chain and frame pacing, not GPU
  execution, input-to-photon latency or real-game FPS.
- Each slot also runs four workers, each executing 250,000 rounds of sixteen
  dependent xorshift steps, yielding every 256 rounds. The program records time
  from the common start barrier through worker completion. Total work is exactly
  sixteen million steps per slot, independent of elapsed time. Every checksum
  equals `372f4292d9ee79b1`, including a native userspace reference execution.

The VM harness verifies enabled state, owned executable path, versioned ops
name, disabled BPF accounting, continued attachment during workloads, scheduler
exit, and restoration to native scheduling after each arm. All checks passed.
The kernel's bypass-activation counter did not increase during any workload;
no kernel warning, panic, watchdog failure or soft lockup appeared in the log.
This supports operation under these workloads; it does not establish identical
scheduling decisions, fairness under all loads, or hardware speed.

An initial attempt stopped before starting either workload because the harness
incorrectly rejected periods in Cake's versioned ops name. That validation was
fixed, the init rebuilt, and the complete predeclared campaign rerun. The failed
attempt is retained separately; no timed observation was removed as an outlier.

## Guest timing results

All values below are **emulated guest time**, not predictions for the 9800X3D.
Frame metrics are equally weighted slot means. Confidence intervals use five
paired block differences, not 60,000 supposedly independent frames.

| Metric | Ordinary release | Annotated release | B − A | Approximate 95% paired interval |
|---|---:|---:|---:|---:|
| Frame p99 | 2,037,023 ns | 2,035,802 ns | −1,221 ns | −44,288 to +41,846 ns |
| Frame p99.9 | 2,076,555 ns | 2,063,035 ns | −13,520 ns | −57,050 to +30,010 ns |
| Mean adjacent-frame jitter | 17,332 ns | 19,813 ns | +2,481 ns | −21,138 to +26,100 ns |
| Dependency-chain p99 | 345,216 ns | 346,170 ns | +954 ns | −174,198 to +176,106 ns |
| Fixed-work completion | 17,397,861 ns | 17,426,182 ns | +28,321 ns (+0.163%) | −231,025 to +287,667 ns |

Mean slot maximum was 2,145,020 versus 2,120,460 ns; 0.1% lows were 473.064
versus 477.266 synthetic FPS. Their paired intervals also include zero.
Both arms completed all 3,000 frames per slot. The 500 FPS cap makes the tiny
average-FPS/mean-frame differences unsuitable as throughput evidence. The
fixed-work test supplies the separate completion-time endpoint.

P99 block differences were +16,546, +35,550, +951, −57,250 and −1,902 ns.
Fixed-work differences were +55,449, +351,975, +37,237, −197,611 and −105,445 ns.
Neither result repeats consistently across blocks. Smaller instructions did
not produce a distinguishable application-level speedup in this experiment.

Host non-QEMU busy averaged 1.38% across one-second samples, range 0–6.40%;
total host busy averaged 5.67%. These are whole-VM observations, including
monitor/kernel work, not per-slot matched interference. Guest busy averaged
41.17% for A and 32.34% for B, with a paired interval spanning zero for the
difference. Do not convert emulated utilization or TCG translation cost into a
claim about physical CPU efficiency. `noise_class` is
`qemu_tcg_diagnostic_uncontrolled_host`.

## Instruction-model findings and a limitation

Actual retained JIT bytes were disassembled and scoped traces fed to
`llvm-mca -mcpu=znver5`, 2,000 iterations each, with both load/store alias
assumptions. This produced a useful warning about the tool itself:

**LLVM 22.1.8 maps `znver5` to `Znver4Model`.** The name accepts Zen 5 features
but does not select a dedicated Zen 5 scheduling model. The release source and
the installed tool's six-wide dispatch / Zn4 resources agree.
[Exact LLVM release source](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.8/llvm/lib/Target/X86/X86.td#L1856).

The installed model also assigns ENDBR64 a 100-uop, 100-cycle placeholder.
Raw whole-subprogram estimates are retained but excluded from conclusions.
Separate component projections omit the two identical ENDBR64 instructions
from each serial-gate trace, explicitly recording the omitted offsets. This
does not assert that ENDBR64 has zero cost on the real machine.

| Scoped component | Ordinary → annotated modeled uops | Modeled reciprocal throughput |
|---|---:|---:|
| Unary ABI stress fragment: argument setup, scalar op, four register saves/restores | 10 → 2 | CTZ 4 → 0.5 cycles; POPCNT/CLZ 4 → 0.75 cycles |
| Cake serial gate, valid mask and true result; ENDBR64 excluded | 41 → 39 | 9.75 → 9.75 cycles |
| First diagnostic histogram block | 26 → 30 | 6.5 → 6.5 cycles |
| Second diagnostic histogram block, including preceding division | 29 → 31 | 18 → 18 cycles |

These are model resource bounds, not measured operation latencies. In the
serial-gate projection, fewer uops do not reduce the model's throughput
bottleneck. The focused ABI fragment deliberately keeps four caller registers
live; it is not a prediction that Cake drops from four cycles to half a cycle.

Changing the model's alias assumption changes histogram simulation markedly:
the first block's modeled total is about 7 cycles/iteration for either arm with
`noalias=true`, but about 12 → 23 with `noalias=false`. These are alternate
assumptions, not a measured confidence interval. LLVM's model does not determine
cache hit/miss behavior or store-to-load forwarding, and does not model branch
prediction. Trace branch outcomes were explicitly selected; no dynamic path
frequency was inferred. [LLVM MCA model and limitations](https://llvm.org/docs/CommandGuide/llvm-mca.html).

The useful conclusion is narrower: removing saves really reduces instructions
and potential resource demand, while remaining loads, dependencies and retained
spills can dominate a larger path. A dedicated hardware run is still necessary
to assign nanoseconds or gaming benefit to this patch.

## Evidence and restoration

Candidate/test sources and reproducible runners:
`/home/ritz/Documents/Repo/scx/target/cake_fastcall_sim_20261002T040342Z/`.

Measurement and analysis:
`/home/ritz/Documents/Repo/scx_cake_bench/runs/cake_fastcall_sim_20261002T040342Z/`.

- `plan.json`: identities, hypotheses, ABBA order and stopping conditions.
- `validated/`: all 20 slot receipts, frame CSVs, fixed-work results, Cake logs,
  kernel events and host-noise samples; `vm-result.json` records clean completion.
- `analyze-vm.py` / `vm-analysis.json`: all-slot checks, summaries and paired
  intervals; checksum reference retained separately.
- `mca/`: exact JIT source hashes/offsets, assembly inputs, complete model output,
  official versioned model definition, model identity and projection exclusions.
- Candidate `model-jit.py`: reproducible extraction and model commands.

The normal release binary/BPF, host boot, kernel and scheduler configuration
remain unchanged. This is diagnostic simulation evidence, not a score-bearing
receipt, an EEVDF comparison or a promotion decision.
