# 2026-05-18 S160/S172 Refinement Findings

This note preserves findings from the S160/S172 champion refinement lane so the
same micro-shapes are not rediscovered without new evidence.

## Baseline

- Source baseline: `/tmp/scx_cake_cmp_20260518T163250Z/champion_s160`
- Release BPF object: `target/release/build/scx_cake-67bd55c7985fe425/out/cake.bpf.o`
- Baseline BPF SHA256: `9df312119f3b899f2e32607562e919665244513f1507d8072b98e16a81f31e59`
- Baseline BPF size: `119112` bytes
- Current-condition S160 full control:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T222039Z_all_wide/matrix/20260518T222039Z_all_scheduler-matrix.XUPUgP/analysis_metrics.tsv`

## Rejected implementation shape: full stack `u64 facts` packing in `enqueue_body`

- Mechanism family: dependency-chain / stack-shape optimization.
- Shape: pack several independent scalar enqueue facts into one local `u64`.
- Static result: rejected before release runtime because linked-object audit showed
  `enqueue_body` became worse: `+25` instructions, `+1` call, `+3` stack refs.
- Interpretation: broad stack-local packing is the wrong shape for BPF hot paths
  here. It increased register pressure / stack interaction instead of reducing it.
- Resurrection condition: only retry as pointer-to-existing-state, rodata,
  task-storage, or per-CPU packed state that removes repeated work without adding a
  local stack aggregate.

## Rejected implementation shape: service-token packing alone

- Mechanism family: dependency-chain / service-order token packing.
- Shape: pack enqueue service lane and service index into a short local token.
- Static result: mixed; `enqueue_body` improved `-4` instructions and `-2`
  branches, but added `+1` stack ref.
- Interpretation: not worth standalone benchmark budget under the no-standalone-S
  rule. It may remain a child shape if a larger task-storage/service-order family
  needs a compact token, but it is not a push candidate by itself.

## Rejected implementation shape: inline wakeup-vtime clamp only

- Mechanism family: dependency-chain thrashing / helper-call live-range reduction.
- Shape: change `cake_clamp_wakeup_vtime()` from `__noinline` to
  `__always_inline`, without service-token packing.
- Build: passed release build.
- Candidate BPF SHA256:
  `874581e4d42a9b49d83f767f1803a082cedc0d1c7d38f6c88a8e2864e80a9f53`
- Candidate BPF size: `119144` bytes (`+32` vs S160).
- Static audit vs S160:
  - `cake_clamp_wakeup_vtime`: removed as standalone function, `0 (-11)` insns.
  - `enqueue_body`: `454 (+10)` insns, `88 (+6)` branches, `12 (-3)` calls,
    `8 (-8)` stack refs, stack L/S `5/3 (-7/-1)`, STLF-risk loads `0`.
  - Dispatch/select functions unchanged in the audit set.
- Focused guard observations:
  - `perf-sched-fork` one-run output: `0.134s`; worse than S160 control native
    output `0.128s` from the full control.
  - `perf-sched-thread` one-run output: `0.120s`; better than S160 control native
    output `0.126s`.
  - Guard results were diagnostic/mixed, not decisive rejection evidence.
- Full release suite:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T232916Z_all_wide/matrix/20260518T232916Z_all_scheduler-matrix.MZ08Au/analysis_metrics.tsv`
- Goal-score comparison vs current S160 control:
  - Equal-weight score: `0.985425` (`-1.46%`).
  - Summed wall: `203.24s -> 203.41s` (`+0.08%`, slower).
  - Primary lower wall rows: `82.88s -> 83.07s` (`+0.23%`, slower).
  - Wins: `argon2-hashing +1.16%`, `ffmpeg-compilation +0.25%`,
    `perf-memcpy +5.17%`, `prime-numbers +2.82%`,
    `stress-ng-cpu-cache-mem +3.46%`, `xz-compression +1.34%`,
    `y-cruncher-pi-1b +0.11%`.
  - Flats: `perf-sched-thread`, `schbench`, `x265-encoding`.
  - Losses: `blender-render -16.19%`, `kernel-defconfig -9.84%`,
    `perf-sched-fork -5.00%`.
- Decision: rejected as a push candidate and restored to exact S160 source/object.
- Interpretation: reducing enqueue call/stack pressure without preserving original
  call/timing/code-layout behavior shifted benchmark outcomes. Static stack wins
  are not sufficient; this shape strongly helped throughput-ish rows but damaged
  latency/layout-sensitive Blender, kernel-defconfig, and fork messaging.
- Resurrection condition: only retry as part of a larger action-timing/state-blend
  mechanism, or with debug proof explaining why Blender/kernel/fork lose and a
  guard that preserves those paths.

## Current next lane

Move away from stack-local structs/packing and standalone inline/codegen changes.
The next useful family is a larger service-classification/task-storage or
existing-state-pointer mechanism:

- avoid repeated `p->comm` / service-kind work on hot wake/enqueue paths;
- store compact, task-associated classification where lifetime and verifier rules
  allow it;
- keep false-sharing risk out of global/shared lines;
- prove that repeated classification or helper calls actually drop in debug/static
  artifacts before spending full-suite budget;
- benchmark current-condition back-to-back against S160 before any nightly push.
