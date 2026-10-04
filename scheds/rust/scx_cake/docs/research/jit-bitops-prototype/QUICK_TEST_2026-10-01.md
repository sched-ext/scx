# Quick native scalar comparison — 2026-10-01

All eight slots passed verifier loading, requested flag selection, binary
identity, zero exit status and restoration to native scheduling. No stalls or
abnormal scheduler exits occurred. Existing MEMLOCK and sched_ext API
deprecation notices remain. The kernel journal records eight normal enables
and eight normal disables, with no BUG, WARNING, Oops or watchdog event.

The same September 30 binary was used throughout: SHA256
`0c27e5613b3d2d28517ad40bbf7e30d7a49a0f2eb232e1c6576e846710e6c708`.
Kernel and source identity match the preceding [smoke report](HARDWARE_SMOKE_2026-10-01.md).
Modes A/B/C/D were default, `--native-bitops`, `--division-free`, and both.
The maintained `cakebench cost` route ran ABCDDCBA with 15-second appsim slots:
249,495 simulated frames in total. Both quotient modes confirmed kernel
CLZ/MULHI selection.

| Mode | BPF CPU ms/s | Change | Frame p99 ns | Change |
|---|---:|---:|---:|---:|
| Default | 141.22 | — | 703,450 | — |
| Native bitops | 138.46 | -1.95% | 654,200 | -49,250 ns |
| Division-free | 158.87 | +12.51% | 733,150 | +29,700 ns |
| Both | 149.19 | +5.65% | 678,450 | -25,000 ns |

These are arithmetic means of two slot metrics, not pooled frame quantiles.
BPF CPU time sums measured Cake program execution, including accounting hooks,
per wall second. Statistics instrumentation was enabled for every arm.
Bitops-only reduced running by 0.57 ns/call but increased dispatch by 57.52
ns/call. Division-free increased running by 2.63 and dispatch by 115.81
ns/call; both increased them by 0.81 and 71.96 ns/call. Callback mix and host
load varied, so these differences do not isolate individual instruction costs.

Unreal and Discord remained active. Ambient CPU use before testing was 19.80%;
total slot busy varied from 62.5% to 79.8%. Per-slot external CPU use was not
isolated. Default p99 shifted from 770,100 to 636,800 ns, more than the observed
aggregate bitops improvement. Bitops p99 was 653,000 and 655,400 ns, giving
opposite effect directions in the forward and reverse comparisons. All modes
held the configured cadence of approximately 2,079 FPS; this is not an
uncapped throughput or real-game FPS result.

Conclusion: functional smoke passed. Bitops-only has the most encouraging
aggregate screen, but no reliable performance winner is established.
Division-free has no demonstrated overall benefit. Both flags remain off by
default. Fresh CLZ/MULHI differential selftests, JIT byte inspection, quiet
paired repeats and real-game results remain pending.

Evidence:

- `/home/ritz/Documents/Repo/scx_cake_bench/runs/native_scalar_quick_20261001/`:
  plan, source patch, binary/BPF/kernel identity, analysis, kernel log and report.
- `/home/ritz/Documents/Repo/scx_cake_bench/runs/cost/20261001T155040_appsim/`:
  all slot logs, startup selections, raw frame CSVs, summaries and callback data.

The cost runner gained per-arm JSON argv, rejection of ignored flags/missing
startup confirmation and a zero-exit validity check. Three focused tests passed.
Its existing dirty changes were preserved. No scheduler source changed.
Native scheduling and `bpf_stats_enabled=0` were restored; the temporary
capability-bearing binary was removed after validation.
