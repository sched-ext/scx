# Release CTZ/CLZ build and quick screens — October 1, 2026

The CTZ queue scan and CLZ histogram experiments are built into the ordinary
optimized release binary as opt-in flags. All 28 live slots passed activation,
identity, mode-selection, normal exit, and native-restoration checks. No default
was changed: the normal-release frame results do not establish a fastest mode.
Division-free remains off throughout this experiment.

## Release configuration

Build: `cargo build --locked --release -p scx_cake` (also `cake build`).
Rust uses the workspace's thin-LTO release profile. The retained BPF build log
confirms Clang 22.1.8, `-O2`, and `-mcpu=v3`. The separate `release-fast` profile
disables LTO; its name is not evidence of faster scheduler execution.

| Flag | Release behavior | Current status |
|---|---|---|
| None | Existing portable implementation, probe off | Default |
| `--native-bitops` | Existing CTZ/POPCNT kfunc paths | Opt-in; frame gain unconfirmed |
| `--native-ring` | CTZ enumeration of marked queues | Opt-in research; topology/order checks fail closed |
| `--native-hist` | CLZ histogram bucket calculation | Only useful with `--toggle probe=1` |
| `--division-free` | Exact reciprocal quotient | Off; prior repeated screen increased BPF CPU cost |

The normal performance path has probe disabled, including the probe-only
`cpu_acquire` callback. Runtime rodata selects the instruction paths before
verifier loading. No separate debug build or compile feature is needed.

## Normal release frame screen

Added `cakebench cost --frames-only` to the maintained diagnostic harness.
It requires accounting already off, never enables/disables it, and retains
zero per-program lifetime counters before and after each slot. This catches
external BPF statistics users as well as a nonzero sysctl. Frame-only output
does not present disabled counters as zero callback cost.

One frozen release binary, explicit `probe=0`, accounting off, 15 seconds per
slot, order `ABCCBACBAABC`: four observations per arm, two mirrored blocks.
All 374,220 simulated frames retained. This follow-up was separately declared
after the user requested normal release-path focus; it is not pooled with
the earlier instrumented observations.

| Mode | p99 ns | p99.9 ns | 0.1% low FPS | Mean slot maximum ns | Non-appsim busy % |
|---|---:|---:|---:|---:|---:|
| A: default | 637,200 | 726,925 | 1,130.68 | 2,061,450 | 34.06 |
| B: native CTZ/POPCNT | 652,575 | 819,275 | 1,062.14 | 1,644,825 | 34.30 |
| C: B + CTZ queue scan | 635,925 | 712,375 | 1,061.09 | 3,094,025 | 32.41 |

Bitops versus default: p99 **+15,375 ns**, p99.9 **+92,350 ns**, 0.1% lows
**-6.06%**, mean adjacent-frame jitter **+3,059 ns**. The two p99 block effects
were +31,050 and -300 ns; background-load differences reversed between blocks.
This screen does not reproduce a normal-release frame win from bitops alone.

Adding queue scanning versus bitops: p99 **-16,650 ns**, p99.9 **-106,900 ns**,
mean adjacent-frame jitter **-3,267 ns**. However, 0.1% lows were **-0.10%** and
the mean of slot maximum frame times increased **1,449,200 ns**. Queue scanning
also had 1.89 percentage points less estimated background CPU use. Its p99 block
effects were -30,800 and -2,500 ns. These are mixed observations, not acceptance.

Host busy ranged 63.82–72.17%; estimated non-appsim busy ranged 30.86–38.75%.
UnrealEditor and Discord were left running. `noise_class` is
`desktop_and_unreal_contaminated_diagnostic`; exact external-process CPU was
not isolated (`external_cpu_avg_pct=null`). Non-appsim estimates include
harness and kernel work. No trimming or exclusions. Quantiles are equal-weight
slot means, and frames are correlated observations, not hundreds of thousands
of independent repetitions. Fixed-cadence appsim FPS is not uncapped game FPS.

## Separate instrumented cost screens

Each screen had eight slots, `ABBABAAB`, four observations per arm, 15 seconds
per slot. Together they retained 498,939 frames with BPF runtime accounting on.

- CTZ queue scan, probe off: dispatch **-0.11 ns/call**, block effects -4.21
  and +3.99 ns. Aggregate BPF CPU **+1.18%**. Frame p99 -600 ns and p99.9
  -41,850 ns, with 0.1% lows +28.46%. This did not repeat the earlier dispatch
  saving. Non-appsim busy ranged 31.35–34.22%.
- CLZ histograms, probe on: stopping **-8.87 ns/call**, block effects -9.47
  and -8.26 ns. Aggregate BPF CPU **-5.60%**, but frame p99 +14,600 ns and
  p99.9 +73,475 ns. Non-appsim busy ranged 31.86–36.05%, with the CLZ arm
  averaging 1.04 points less. The callback saving repeats the prior finding;
  it optimizes diagnostics and is not a normal probe-off release saving.

The earlier division-free and MULHI-vtime findings were not rerun here. No
new MULHI-vtime code was added. See the [instruction audit](INSTRUCTION_USAGE_REVIEW_2026-10-01.md)
and [five-repeat quotient/bitops comparison](REPEAT_5X_2026-10-01.md).

## Validation and identity

- `cargo test --locked -p scx_cake`: 33 unit + 3 integration tests passed;
  one privileged topology load test ignored. Debug and release Clippy, format,
  optimized release build, and `git diff --check` passed.
- Seven focused harness tests passed, including rejection of external runtime
  accounting, restored scheduler state on an invalid slot, and frame-only output.
- Queue and histogram helper bodies match the retained prior exhaustive tests:
  388,228 queue-order cases and 4,524,672 histogram cases, zero mismatches.
  These are reused exact-body checks, not fresh millions of tests this turn.
- 28/28 live slots, 873,159 total simulated frames. No verifier rejection,
  runnable stall, watchdog, kernel warning/oops, or abnormal scheduler exit.
  The pre-existing 8 MiB MEMLOCK startup warning remains; all loads succeeded.
  Cargo also reports the unrelated `scx_rustland_core` `lib.include` manifest warning.
- Tested on Ryzen 7 9800X3D, 16 threads / one LLC, kernel
  `7.2.8-1-cachyos-custom`, boot `e4d51516-9170-4a66-b0bd-1e47327fab05`.
  Multi-LLC/other-topology activation and fresh JIT-byte capture are untested.
  No EEVDF, real-game, input-latency, holdout, or default-promotion verdict.

Source HEAD: `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a`, with the preserved
dirty tree plus this experiment. Exact source hashes and before/after patches
are retained. Basic binary/object pairing passed, including exactly one
embedded object; this is diagnostic attribution, not a score-bearing v5 receipt.

Binary SHA-256: `92f34727e5ee55078ad32a335fe9787c893f3b058033df543fd86884aaabe907`.
BPF SHA-256: `2f7c96ac713d89ed01b15758fe88e217e77a10458c1bdeeaf77203163b811f2e`.

The executable remains at `target/release/scx_cake`. Exact binary, BPF object,
source snapshot, original baseline, build logs and checks are retained at
`target/cake_ctz_clz_quick_20261001T220947Z/` in the scheduler repository.
The temporary capability-bearing activation copy is removed after testing.

Measurement root:
`/home/ritz/Documents/Repo/scx_cake_bench/runs/ctz_clz_quick_20261001T220947Z/`.
Read `FRAMES_RESULTS.md` / `frames-analysis.json` for release-only data and
`RESULTS.md` / `analysis.json` for cost screens. Each has all slot and block
effects, commands, loader logs, journal checks and raw capture references.

Disposition: experiments remain available for further testing, off by default.
Normal-release repeatability under matched background load is still owed.
Native scheduling is restored and BPF runtime accounting is disabled.
