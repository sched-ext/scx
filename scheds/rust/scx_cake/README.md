# scx_cake 1.2.0

[![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: 6.12+](https://img.shields.io/badge/kernel-6.12%2B-green.svg?style=flat-square)](https://kernel.org)
[![sched_ext](https://img.shields.io/badge/sched_ext-BPF-orange.svg?style=flat-square)](https://github.com/sched-ext/scx)

`scx_cake` is a gaming-focused `sched_ext` CPU scheduler. It applies
CAKE-inspired low-latency ideas to CPU time: keep the wake path short, publish
per-CPU state from one writer so placement reads cheap cache-line facts, give
frame-critical threads a deterministic local handoff, and arbitrate everything
else through a per-LLC virtual-time queue.

The current design is the **service-gated hybrid queue** (2026-06-10). On a
focused KovaaK's workload it beats Linux EEVDF (6.18/7.1-era, including the
HRTICK-at-deadline and POC-selector improvements) on every MangoHud metric
measured — average FPS, 1% low, 0.1% low, p99/max frametime, frametime
stddev, and jitter — under an order-rotated, focus-gated A/B protocol, and it
beats `scx_cosmos` and `scx_lavd` under the same protocol. Measured results
and methodology are below; the full decision log is in
[docs/mutation_campaign_2026-06-10.md](./docs/mutation_campaign_2026-06-10.md).

> [!WARNING]
> `scx_cake` is experimental scheduler code. It requires a Linux kernel with
> `sched_ext` support and root privileges to run.

## Quick Start

### Requirements

- Linux kernel `6.12+` with `sched_ext`
- Rust toolchain and the build dependencies of the main `scx` repository
- root privileges to run the scheduler

### Build

A plain release build **is the measured champion configuration** — no flags
needed:

```bash
git clone https://github.com/sched-ext/scx.git
cd scx

# Champion defaults: gaming profile / 1000us quantum / queue-policy=llc-vtime
# / hybrid-queue=4 / storm-guard=shield / busy-wake-kick=policy
# / enq-kick-idle=on (BTF-gated) / irq-avoid=auto
cargo build --release -p scx_cake

# Debug build for TUI/capture and runtime A/B work
cargo build -p scx_cake
```

Build-time A/B overrides (each documented in `build.rs`):

| Env | Default | Meaning |
| :-- | :-- | :-- |
| `SCX_CAKE_QUEUE_POLICY` | `llc-vtime` | Busy-fallback queue shape. `local` restores the per-CPU local-first design (and compiles in the native-fast-wake game stack, see below). |
| `SCX_CAKE_HYBRID_QUEUE` | `4` | Frame gate for the llc-vtime build. `0` off, `1` GameThread+RenderThread local, `2`/`3` single-thread gates (measured worse — destabilize 1% lows), `4` RenderThread always local + GameThread local only onto idle/frame-owned targets (champion). |
| `SCX_CAKE_PROFILE` / `SCX_CAKE_QUANTUM_US` | `gaming` / `1000` | Baked profile and base slice. |
| `SCX_CAKE_STORM_GUARD` / `SCX_CAKE_BUSY_WAKE_KICK` | `shield` / `policy` | Busy-wake handoff and kick policy. |
| `SCX_CAKE_VTIME_WAKE_FLOOR` | `0` | EEVDF-style wake-lag floor at arbiter inserts (parked: measured worse on 0.1% lows). |
| `SCX_CAKE_GAME_DIAG` | `0` | Compile the release game-diagnostics recorder (per-CPU action counters + frame-preemptor attribution) for `--verbose` capture runs. |

### Run

```bash
# Champion defaults — release binary, no arguments
sudo ./target/release/scx_cake

# Runtime knobs (all measured, all reversible)
sudo ./target/release/scx_cake --irq-avoid 0          # disable RT/IRQ noise-avoid
sudo SCX_CAKE_ENQ_KICK_IDLE=0 ./target/release/scx_cake   # disable the enqueue idle-kick fold
sudo ./target/release/scx_cake --frame-reserve        # parked experiment, see docs

# Debug TUI / capture
sudo ./target/debug/scx_cake --verbose
```

Notable runtime flags:

| Flag / Env | Default | Meaning |
| :-- | :-- | :-- |
| `--enq-kick-idle` / `SCX_CAKE_ENQ_KICK_IDLE` | on | Fold the enqueue idle-kick into the local-DSQ insert using the kernel's `SCX_ENQ_KICK_IDLE` enq_flag (resolved from the booted kernel's BTF; falls back to the explicit `scx_bpf_kick_cpu` on older kernels). Measured: enqueue callback 164.6 → 46.8 ns/call in-game, zero frame-metric change. The upstream patch and a 7.0-stable backport ship in [kernel-patches/](./kernel-patches/). |
| `--irq-avoid auto\|0\|<cpus>` / `SCX_CAKE_IRQ_AVOID` | `auto` | At load, sample `/proc/interrupts` and RT (FIFO/RR) thread residency; demote CPUs hosting IRQ storms (≥2k/s) or active RT threads (≥300 wakes/s — compositor and audio threads in practice) in the routing perf scores. |
| `--frame-reserve` / `SCX_CAKE_FRAME_RESERVE` | off | Parked: reserve one core exclusively for the frame anchor. Measured to backfire — an exclusively-idle core becomes the kernel's preferred RT wake target (`cpupri` ranks idle CPUs first), so the anchor eats more preemptions, not fewer. Kept as a documented falsification. |
| `--queue-policy`, `--storm-guard`, `--busy-wake-kick` | baked | Debug builds patch these at runtime; release uses the baked values. |

## Design

`scx_cake` optimizes for frame consistency and responsiveness with throughput
as a bounded property. Two structural ideas carry the design:

1. **Cake Scoreboard Dispatch** — every CPU owns and publishes one cache line
   of state (`cpu_status`: idle/accept bits, owner class, pressure, epoch;
   `cpu_frontier`: vtime frontier). Placement decisions read these
   single-writer lines plus loader-built topology RODATA, never another CPU's
   private bookkeeping.
2. **Service-gated hybrid queue** — the busy-fallback path is split by thread
   role. The frame pipeline's serial pair (GameThread/RenderThread) gets the
   deterministic LOCAL handoff shape; everything else is arbitrated through a
   per-LLC virtual-time queue. The pair gating is load-bearing: measured,
   gating only one of the two threads destabilizes 1% lows by 3-8x (the
   GameThread↔RenderThread handoff must keep one queue shape end-to-end).

### Why hybrid

The two pure queue shapes trade departments, measured against EEVDF on the
same scene, same day:

| shape | wins | loses |
| :-- | :-- | :-- |
| `local` (per-CPU local-first) | max frametime, jitter (tight spreads) | avg FPS (−1.5%, zero overlap), 1% low, p99 |
| `llc-vtime` (shared arbiter) | avg FPS (first EEVDF avg beat) | 1% low, p99, tail extremes |
| **hybrid gate 4** | **all of the above** | — |

The gate condition for GameThread (LOCAL only onto idle or
FRAME/INTERACTIVE-owned targets, arbiter otherwise) keeps the pair-coherent
handoff where it matters and escapes bulk pileups where it does not.

### Scoreboard layers

| Layer | Writer | Reader | Purpose |
| :-- | :-- | :-- | :-- |
| Static topology RODATA | userspace loader at attach | BPF hot path | Sibling, primary, LLC/core IDs, per-CPU LLC DSQ, fast-probe and core-spread candidate tables. Perf scores feed the routing order — after RT/IRQ noise demotion. |
| CPU publication lanes | owning CPU only | remote wake placement | One cache-line `cpu_status` and one `cpu_frontier` per CPU: idle/accept/wake-preempt bits, owner class, pressure bucket, vtime frontier. Writes are elided when the visible state is unchanged. |
| LLC pending lane | LLC enqueue side, cleared on dispatch miss | dispatch | Conservative hint that the shared per-LLC vtime DSQ may have work, so idle dispatch never pays empty pulls. |
| Private CPU BSS | owning CPU | same CPU | Tick slice, last PID, owner-runtime EWMA, service kind, run-start timestamps. Page-aligned, never read remotely on the hot path. |

### Scheduling flow (champion build: release, llc-vtime, hybrid 4)

**select_cpu** — find an idle target cheaply:
1. Synchronous message-wake fast path (pipe-style wakers) → SMT sibling.
2. Generic bulk escape: default-user, non-sync work asks the kernel's native
   idle pick first; a hit is authoritative.
3. Scoreboard fast-scan: previous CPU, then loader-built probe slots, claimed
   with `scx_bpf_test_and_clear_cpu_idle`; full-idle-core spread for bulk
   vtime work.
4. Native idle helper as the trusted fallback; clean-idle hits direct-dispatch
   from select when the published scoreboard agrees.

**enqueue** — route by published target state:
1. Idle target → direct insert to `SCX_DSQ_LOCAL_ON | cpu`. With the
   `SCX_ENQ_KICK_IDLE` fold the insert itself carries the idle kick — one
   BPF→kernel crossing per idle wake instead of two.
2. Busy target accepted by owner status (storm-guard shield policy, owner
   class/pressure gated) → local insert plus shaped kick.
3. Hybrid frame gate: RenderThread always, GameThread conditionally (target
   idle or FRAME/INTERACTIVE-owned) → the same LOCAL insert shape.
4. Everything else → per-LLC vtime DSQ (`dsq_vtime`-ordered) with a wakeup
   vtime ceiling clamp (`frontier + 2 quanta`) and a scoreboard-shaped kick.

**dispatch** — local first, shared second:
1. Local DSQ work runs first; keep-running extends the current owner when
   nothing is queued.
2. The `llc_pending` hint gates a pull from the per-LLC vtime queue.
3. Going idle publishes the idle/accept state for remote wake placement.

**running / stopping** — owner bookkeeping: vtime integration
(`dsq_vtime += runtime + nice_adj`), owner-runtime EWMA, owner class and
pressure publication, frontier updates.

### The `local` alternate build

`SCX_CAKE_QUEUE_POLICY=local` restores the previous champion shape: per-CPU
local-first fallback plus the **native-fast-wake game stack** (prev-CPU idle
override, miss tunnel, strict SMT-sibling gating, dispatch rescue skip). That
stack is compiled out of the llc-vtime build entirely. The local build remains
the right choice for workloads that prize worst-frame tightness over average
FPS and 1% lows; the hybrid champion supersedes it for general gaming.

### Fairness / virtual time

Task-local `p->scx.dsq_vtime` in nanoseconds, additive model:
`vtime += runtime + (100 - weight) * 20480`. Seeded from the per-CPU published
frontier on enable; wakeup vtime clamped to `frontier + 2 quanta` so sleepers
rejoin near the present instead of starving behind CPU-bound progress.
Fairness is bounded, not strict — the arbiter orders the fallback queue; the
local shapes trust placement.

### Service classification

Hot-path service detection is comm-string matching (64-bit word compares on
`p->comm`): the frame pair (`GameThread`, `RenderThread`), benchmark services
(`schbench`, `stress-ng-*`, `sched-pipe`, `sched-messaging`). It drives the
hybrid gate, slice shaping, busy-wake suppression, and bench service
contracts. A behavioral classifier exists in debug telemetry but is not yet
wired into release placement.

## Measured results (2026-06-10)

Protocol: focused KovaaK's, MangoHud socket-triggered 60s captures, arms
alternated ABBA across cycles (slot position dominates tail rankings
otherwise — measured), focus-gated fail-closed, scheduler-transition settle,
fresh game instance (rare multi-ms game-side stutters hit both arms at a
session-dependent rate; extremes are therefore reported as medians /
stutter-excluded means at small n). Hardware: Ryzen 7 9800X3D, RTX 4090,
4K240. Kernel: 7.1-rc7 CachyOS (EEVDF with HRTICK-at-deadline default-on and
the cake-inspired POC idle selector — both active in the baseline).

### vs EEVDF (fresh instance, 4-cycle ABBA, n=4/arm)

| metric | cake hybrid4 | EEVDF | Δ |
| :-- | --: | --: | :-- |
| avg FPS | 1008.6 | 1004.8 | **+0.4%** slot-consistent |
| 1% low | 777.2 | 711.9 | **+9.2% — zero overlap** (every cake run beat every EEVDF run) |
| p99 frametime | 1.288ms | 1.405ms | **−8.4% — zero overlap** |
| 0.1% low | 617.7 | 588.5 | **+6.8%** (stutter-excluded) |
| max frametime | — | — | **−3.3%** (median) |
| frametime stddev | — | — | **−13.6%** (median) |
| jitter (max Δ) | — | — | **−6.1%** (median) |

Across the day's aged-instance sets the same configuration held 1% low and
p99 wins with zero losses; cake's tail spreads run 3-4x tighter than EEVDF's
(e.g. 1% low σ 10-40 vs 43-103), and EEVDF's tail quality drifts downward
over a session while cake's stays flat.

### vs the sched_ext field (same protocol)

- **scx_cosmos**: cake wins avg, 1% low, p99, FT-stddev in both cycles
  (including from the disadvantaged slot); extremes tie. No losses.
- **scx_lavd**: cake wins everything — avg +7%, 1% low +14.7%, jitter −86%;
  lavd threw repeated 4-5ms stutters in this scene.

### Mechanism wins (bpf_stats, in-game)

- `SCX_ENQ_KICK_IDLE` fold: enqueue callback 164.6 → 46.8 ns/call (−72%) at
  ~13k idle wakes/s.
- Frame-preemptor attribution (diag builds): 99.7% of GameThread's
  involuntary context switches are RT-class sandwiches (compositor/audio
  FIFO threads) invisible to sched_ext — the finding behind `--irq-avoid`
  and the documented `--frame-reserve` falsification.

## Topology

The loader detects CPUs, LLCs, SMT pairs, and per-CPU perf scores
(`acpi_cppc/highest_perf`) from sysfs, applies the RT/IRQ noise demotion, and
bakes everything into `const volatile` RODATA so the verifier const-folds
loop bounds and the JIT sees immediates. `CAKE_MAX_CPUS`/`CAKE_MAX_LLCS` are
compile-time pow2 from `build.rs`. Single-LLC release builds collapse the
LLC-iteration paths.

## Release and debug builds

Release compiles the policy lean: telemetry, learned-locality, arena task
contexts, route-prediction/confidence subsystems, and the debug TUI surface
are compiled out (empty stubs, dead-code-eliminated). Debug builds carry the
full capture surface: TUI (`--verbose`), per-task telemetry, path counters,
and runtime A/B knobs. `SCX_CAKE_GAME_DIAG=1` release builds add a small
per-CPU action-counter recorder for headless capture without the full debug
tax.

## Measuring performance

The benchmark suite lives in the separate `scx_cake_bench_assets` repository
(game capture harness with MangoHud socket triggering, focus gating,
scheduler-runner staging, ABBA cycle driver, ML ingestion). Quick local
measurement:

```bash
# Per-callback ns via kernel bpf_stats (NOPASSWD helper after one-time install)
sudo cake-bpfstats enable && sudo cake-bpfstats show

# Scheduler-agnostic per-thread shape (/proc): run%, wait/slice, migrations,
# voluntary/involuntary switches
python3 bench/scx_cake_thread_profile.py --scenario-id mytest --duration 45 --print
```

A/B harnesses for the enqueue fold are in
[bench/enq_kick_idle_ab.sh](./bench/enq_kick_idle_ab.sh) and
[bench/enq_kick_idle_schbench_ab.sh](./bench/enq_kick_idle_schbench_ab.sh).

## Source tour

| File | Role |
| :-- | :-- |
| [src/main.rs](./src/main.rs) | userspace loader, CLI, RODATA setup, IRQ/RT noise scan, frame-reserve governor, attach loop |
| [src/bpf/cake.bpf.c](./src/bpf/cake.bpf.c) | scheduler policy and `sched_ext` callbacks |
| [src/bpf/intf.h](./src/bpf/intf.h) | shared structs, constants, scoreboard layout, diag counters |
| [src/topology.rs](./src/topology.rs) | topology detection and mask construction |
| [src/tui.rs](./src/tui.rs) | debug TUI and telemetry consumer |
| [kernel-patches/](./kernel-patches/) | `SCX_ENQ_KICK_IDLE` upstream patch + 7.0-stable backport |
| [docs/](./docs) | research notes, design analysis, and the mutation-campaign decision logs |

### Main callbacks

| Callback | Purpose |
| :-- | :-- |
| `cake_select_cpu` | message-wake fast path, native bulk escape, scoreboard probes, native fallback, clean direct dispatch |
| `cake_enqueue` | idle direct insert (+`SCX_ENQ_KICK_IDLE` fold), accepted busy-wake local handoff, hybrid frame gate, per-LLC vtime arbiter |
| `cake_dispatch` | local first, keep-running, `llc_pending`-gated LLC pull, idle publication |
| `cake_running` / `cake_stopping` | owner bookkeeping, vtime integration, status/frontier publication |
| `cake_enable` | seed `dsq_vtime` from the published frontier |
| `cake_init` / `cake_exit` | DSQ creation, `cpuperf` max pin, exit info |

## Vocabulary

| Term | Meaning in `scx_cake` |
| :-- | :-- |
| Cake Scoreboard Dispatch | Placement from loader-built candidates plus owner-written per-CPU status/frontier lanes. |
| hybrid queue (gate 4) | RenderThread busy-fallback always LOCAL; GameThread LOCAL onto idle/frame-owned targets, per-LLC vtime arbiter otherwise. |
| `cpu_status` | Owner-published per-CPU lane: idle/accept, SAT cache/mem, wake-preempt, owner class, pressure, epoch, latency class. |
| `cpu_frontier` | Owner-published per-CPU vtime frontier; seeds and clamps task vtime without touching private BSS. |
| `llc_pending` | Conservative shared-DSQ pending hint that gates dispatch pulls. |
| owner class | EWMA-derived class of a CPU's current owner (short / interactive / frame / bulk) published in `cpu_status`. |
| noise-avoid | Load-time demotion of IRQ-storm and active-RT-resident CPUs in routing perf scores (`--irq-avoid`). |
| enq-kick-idle fold | `SCX_ENQ_KICK_IDLE` enq_flag on local inserts: the kernel issues the idle kick from inside the insert — one kfunc crossing per idle wake. |
| direct dispatch | `SCX_DSQ_LOCAL_ON \| cpu` insert when the target is clean-idle or an accepted busy wake. |
| per-LLC vtime DSQ | Shared fallback queue ordered by `p->scx.dsq_vtime`, one per LLC. |
| `dsq_vtime` | Per-task virtual time; additive runtime + nice adjustment. |
| quantum | Base slice, baked at build time in release (gaming: 1ms). |
| ABBA protocol | A/B cycles with arm order rotated between cycles; slot position otherwise dominates tail rankings. |

## Related notes

- [docs/mutation_campaign_2026-06-10.md](./docs/mutation_campaign_2026-06-10.md) — the hybrid-queue campaign: decision log, falsifications, and measurement laws
- [docs/hot_path_optimization_analysis.md](./docs/hot_path_optimization_analysis.md)
- [docs/idle_path_bubble_reduction_proposal.md](./docs/idle_path_bubble_reduction_proposal.md)
- [docs/benchmark_winner_analysis.md](./docs/benchmark_winner_analysis.md)
