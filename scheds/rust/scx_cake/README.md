# scx_cake: CAKE DRR++ Adapted for CPU Scheduling

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: 6.12+](https://img.shields.io/badge/Kernel-6.12%2B-green.svg?style=flat-square)](https://kernel.org)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg?style=flat-square)](https://github.com/sched-ext/scx)

> **ABSTRACT**: `scx_cake` is an experimental BPF CPU scheduler that adapts the network [CAKE](https://www.bufferbloat.net/projects/codel/wiki/Cake/) algorithm's DRR++ (Deficit Round Robin++) for CPU scheduling. Designed for **gaming workloads** on modern AMD and Intel hardware.
>
> - **4-Class System** — Tasks classified as GAME / NORMAL / HOG / BG by PELT utilization and game family detection
> - **Zero Global Atomics** — Per-CPU BSS arrays with MESI-guarded writes eliminate bus locking
> - **3-Gate select_cpu** — prev_cpu idle → performance-ordered scan → kernel fallback → tunnel
> - **Per-LLC DSQ Sharding** — Eliminates cross-CCD lock contention on multi-chiplet CPUs
> - **EEVDF-Inspired Weighting** — Virtual runtime with nice scaling and tiered DSQ ordering

---

> [!WARNING]
> **EXPERIMENTAL SOFTWARE**
> This scheduler is experimental and intended for use with `sched_ext` on Linux Kernel 6.12+. Performance may vary depending on hardware and user configuration.

> [!NOTE]
> **AI TRANSPARENCY**
> Large Language Models were used for optimization pattern matching and design exploration. All implementation details have been human-verified, benchmarked on real gaming workloads, and validated for correctness.

---

## Navigation

- [1. Quick Start](#1-quick-start)
- [2. Philosophy](#2-philosophy)
- [3. 4-Class System](#3-4-class-system)
- [4. Architecture](#4-architecture)
- [5. Configuration](#5-configuration)
- [6. Build Modes](#6-build-modes)
- [7. TUI Guide](#7-tui-guide)
- [8. Performance](#8-performance)
- [9. Vocabulary](#9-vocabulary)

---

## 1. Quick Start

```bash
# Prerequisites: Linux Kernel 6.12+ with sched_ext, Rust toolchain

# Clone and build
git clone https://github.com/sched-ext/scx.git
cd scx && cargo build --release -p scx_cake

# Run (requires root)
sudo ./target/release/scx_cake

# Run with live stats TUI
sudo scx_cake -v
```

---

## 2. Philosophy

Traditional schedulers (CFS, EEVDF) optimize for **fairness** — if a game and a compiler both run, each gets 50% CPU time. For gaming, this creates two problems:

1. **Latency inversion**: A 50µs input handler waits behind a 50ms compile job
2. **Frame jitter**: Game render threads get preempted mid-frame by background work

**scx_cake's answer**: Detect the game process family automatically (Steam, Wine/Proton, native games) and give it scheduling priority. Non-game tasks are classified by PELT CPU utilization into NORMAL, BG, or HOG classes with progressively lower priority. The system self-tunes — no manual configuration needed.

This is the same insight behind network CAKE: short flows (DNS, gaming packets) should not be delayed by bulk flows (downloads). scx_cake applies this to CPU time.

---

## 3. 4-Class System

`scx_cake` classifies every task into one of four classes. Classification uses PELT (Per-Entity Load Tracking) utilization from the kernel and automatic game family detection via process tree analysis.

### Class Hierarchy

| Class      | DSQ Weight Range | Typical Workload                                                     |
| :--------- | :--------------- | :------------------------------------------------------------------- |
| **GAME**   | [0, 5120]        | Game process tree + audio daemons + compositor (during GAMING state) |
| **NORMAL** | [8192, 13312]    | Default — interactive desktop tasks                                  |
| **BG**     | [32768, 37888]   | Low PELT utilization non-game tasks during GAMING (4× penalty)       |
| **HOG**    | [49152, 54272]   | High PELT utilization (≥78% CPU) non-game tasks — lowest priority (6× penalty) |

> [!TIP]
> **Lower weight = dispatches first.** Non-overlapping weight ranges guarantee class ordering: all GAME tasks dispatch before any NORMAL task, all NORMAL before any BG, all BG before any HOG.

### How Classification Works

1. **Game detection**: Two-phase detection scans for Steam environment variables and Wine `.exe` processes. Detected game TGIDs and their parent PID are written to BPF BSS. The entire process family (game + wineserver + audio + compositor) is promoted to GAME class.
2. **PELT-based classification**: Every 64th stop, the scheduler reads the kernel's `util_avg` for each task. Tasks with ≥78% CPU utilization are classified as HOG; lower-utilization non-game tasks become BG during GAMING state, or NORMAL otherwise.
3. **Audio/Compositor protection**: PipeWire daemons and Wayland compositors are detected at startup and baked into RODATA. During GAMING state, they receive GAME-level priority via the class-aware kick guard.
4. **Waker-boost chain**: Tasks woken by GAME threads inherit GAME priority for one scheduling cycle. This automatically promotes game pipeline threads (sim→render→present) without explicit classification.

### Game Detection Deep Dive

Game detection runs in the **Rust TUI polling loop** (userspace, every refresh interval) and writes results to BPF BSS. The BPF side never scans `/proc` — it only reads the pre-resolved `game_tgid`, `game_ppid`, and `sched_state` from BSS.

**Detection Pipeline** (priority order):

1. **Phase 1 — Steam**: For each PPID group with ≥`GAME_MIN_THREADS` threads, read `/proc/<ppid>/environ` looking for `SteamGameId=` or `STEAM_GAME=`. If found, validate that the group contains a real game binary (not just `steam`, `steamwebhelper`, or `pressure-vessel`). Confidence: **100** (instant lock).
2. **Phase 2 — Wine/Proton .exe**: For remaining PPIDs with ≥`GAME_MIN_THREADS`, read `/proc/<ppid>/cmdline` looking for any argument ending in `.exe`. Covers Heroic Launcher, Lutris, manual Wine launches. Confidence: **90** (5-second holdoff).

**TGID Resolution**: Once a winning PPID is found, resolve the actual game TGID by:

- Building per-TGID max `pelt_util` across all threads in the PPID group
- Sorting TGIDs by descending PELT (the game's render loop consumes ms, infra exes consume µs)
- Filtering through a Windows infrastructure blocklist: `services.exe`, `winedevice.exe`, `pluginhost.exe`, `svchost.exe`, `explorer.exe`, `wineboot.exe`, `crashhandler.exe`, etc.
- Extracting the game name from `/proc/<tgid>/cmdline` (for `.exe`) or `/proc/<tgid>/comm` (for native)

**Hysteresis State Machine**:

- **Holdoff timer**: Lower-confidence candidates wait before locking (Steam=instant, .exe=5s). The same candidate must persist across multiple polls to lock.
- **Sticky incumbent**: Once locked, a game stays locked until its `/proc/<tgid>` disappears (process exits). A challenger can only displace it with **strictly higher** confidence.
- **Exit detection**: Every poll checks if `/proc/<game_tgid>` still exists. On exit → `tracked_game_tgid = 0`, `sched_state` transitions from GAMING → IDLE.

**BSS Propagation**: The resolved state is written to BPF BSS every refresh:

```
bss.game_tgid       = tracked_game_tgid    // for existence checks + display
bss.game_ppid       = tracked_game_ppid    // primary family signal for BPF classification
bss.game_confidence  = game_confidence      // 0/90/100
bss.sched_state      = IDLE | COMPILATION | GAMING
```

The BPF classification engine in `cake_init_task` and `cake_stopping` reads `game_ppid` to decide if a task belongs to the game family. All scheduling behavior changes (class assignment, DSQ weights, quantum caps, kick guard) flow from `sched_state`.

### DRR++ Deficit Tracking

Adapted from network CAKE's flow fairness:

- Each task starts with a **deficit** (quantum + new-flow bonus ≈ 10ms credit)
- Each execution bout consumes deficit proportional to runtime
- When deficit exhausts → new-flow bonus removed → task competes normally
- GAME tasks skip deficit drain entirely — their new-flow bonus persists forever

### EEVDF-Inspired Weighting

scx_cake uses a virtual runtime system inspired by EEVDF:

- **Sleep lag credit**: Tasks that yield voluntarily (game threads at vsync, audio callbacks) accumulate credit that reduces their DSQ weight on the next wakeup — dispatching them ahead of continuous consumers.
- **Nice scaling**: Per-task `vtime_mult` (reciprocal of weight: `102400/p->scx.weight`, 1024=nice0) scales vruntime cost. Higher priority → lower vtime_mult → dispatches sooner. Computed once per 64 stops or on `set_weight` callback.
- **Capacity scaling**: On heterogeneous CPUs (P/E cores), E-core runtime is scaled by CPU capacity so tasks running on slower cores accumulate proportionally less vruntime.

---

## 4. Architecture

### Overview

```mermaid
flowchart TD
    subgraph HOT["BPF Hot Path"]
        SELECT["cake_select_cpu<br/>3-gate + tunnel"] --> |GATE 1| PREV["prev_cpu idle?<br/>scx_bpf_test_and_clear_cpu_idle"]
        SELECT --> |GATE 2| SCAN["Perf-ordered scan<br/>cpus_fast_to_slow / cpus_slow_to_fast<br/>(only when big_core_phys_mask != 0)"]
        SELECT --> |GATE 3| KERNEL["scx_bpf_select_cpu_dfl<br/>kernel authoritative idle scan"]
        SELECT --> |TUNNEL| ENQ["cake_enqueue<br/>all CPUs busy"]

        PREV --> LOCALON["SCX_DSQ_LOCAL_ON<br/>direct to CPU"]
        SCAN --> LOCALON
        KERNEL --> LOCALON

        ENQ --> |"weighted vtime"| LLCDSQ["Per-LLC DSQ"]
        LLCDSQ --> DISPATCH["cake_dispatch"]
        DISPATCH --> |"1. Local LLC<br/>scx_bpf_dsq_move_to_local"| LOCAL["Run task"]
        DISPATCH --> |"2. Cross-LLC steal<br/>(nr_llcs > 1, victim queued > 1)"| STEAL["Steal from other LLC"]
    end

    subgraph CLASSIFY["Classification Engine (cake_stopping)"]
        EVERY["Every stop"] --> DEFICIT["DRR++ deficit drain"]
        EVERY --> WFREQ["Wake counter EWMA"]
        EVERY --> VTIME["Vtime staging<br/>(staged_vtime_bits)"]
        GATE64["Every 64th stop<br/>(confidence gate)"] --> RECLASS["PELT reclassify<br/>GAME / NORMAL / HOG / BG"]
        GATE64 --> NICE["vtime_mult recompute"]
        RUNNING["cake_running<br/>(every context switch)"] --> STAMP["BSS: run_start, tick_slice,<br/>is_yielder, game_running,<br/>game_cpu_mask"]
    end
```

### Source Files

| File           | Lines  | Purpose                                                          |
| :------------- | :----- | :--------------------------------------------------------------- |
| `cake.bpf.c`   | ~3,170 | All BPF ops + classification engine + BenchLab                   |
| `intf.h`       | ~740   | Shared structs, constants, telemetry definitions                 |
| `bpf_compat.h` | ~37    | Relaxed atomics compatibility shim                               |
| `main.rs`      | ~845   | Rust loader, CLI, profiles, topology, audio/compositor detection |
| `topology.rs`  | ~284   | CPU topology detection (CCDs, P/E cores, V-Cache, SMT)           |
| `calibrate.rs` | ~304   | ETD inter-core latency measurement (CAS ping-pong)               |
| `tui.rs`       | ~4,170 | Terminal UI: debug view, live matrix, BenchLab, topology         |

### Ops Callbacks

| Callback                  | Role                                                       | Hot/Cold          |
| :------------------------ | :--------------------------------------------------------- | :---------------- |
| `cake_select_cpu`         | 3-gate idle CPU selection + kfunc tunneling                | **Hot**           |
| `cake_enqueue`            | 3-path router: wakeup / requeue / nostaged                 | **Hot**           |
| `cake_dispatch`           | Local LLC → cross-LLC steal                                | **Hot**           |
| `cake_running`            | BSS staging: run_start, is_yielder, game_running, game_cpu_mask | **Hot** (minimal) |
| `cake_stopping`           | 4-stage pipeline: DRR++ → reclassify → EEVDF → staged pack | **Warm**          |
| `cake_tick`               | Cross-LLC load balance hint (every 8th tick, single-CCD eliminated) | **Warm** (throttled) |
| `cake_set_weight`         | Computes `vtime_mult = 102400/weight` (once per weight change) | **Cold** (rare)   |
| `cake_yield`              | Yield count telemetry (stats-gated)                        | **Cold**          |
| `cake_runnable`           | Preempt count + wakeup source telemetry (stats-gated)      | **Cold**          |
| `cake_set_cpumask`        | Event-driven affinity update (replaces polling)            | **Cold**          |
| `cake_init_task`          | Arena + task_storage allocation, initial classification    | **Cold** (once)   |
| `cake_exit_task`          | Arena deallocation                                         | **Cold** (once)   |
| `cake_init` / `cake_exit` | DSQ creation, arena init, UEI                              | **Cold** (once)   |

### Data Structures

**Dual-storage architecture**:

- **`cake_task_hot`** (BPF task_storage, ~10ns lookup) — CL0 scheduling-critical fields used every stop: `task_class`, `deficit_u16`, `packed_info`, `warm_cpus`, `staged_vtime_bits`, `vtime_mult`, `dsq_weight_base`, `dsq_vtime`
- **`cake_task_ctx`** (BPF Arena, ~29ns TLB walk) — Telemetry-only fields, gated behind `CAKE_STATS_ACTIVE`. Dead in release builds.
- **`cake_cpu_bss`** (BSS array, L1-cached) — Per-CPU hot fields: `run_start`, `tick_slice`, `is_yielder`, `idle_hint`, `game_running`, `vtime_local`, `sched_state_local`

**Per-CPU arena** (`cake_per_cpu`, conditional sizing):

- Release: 64B/CPU (CL0 only, 1 page total)
- Debug: 128B/CPU (CL0 + CL1 telemetry, 2 pages total)

### DSQ Architecture

```mermaid
flowchart LR
    subgraph SINGLE["Single-CCD (9800X3D)"]
        DSQ0["LLC_DSQ_BASE + 0<br/>vtime ordered<br/>nr_llcs = 1<br/>stealing skipped"]
    end

    subgraph MULTI["Multi-CCD (9950X)"]
        DSQ1["LLC_DSQ_BASE + 0<br/>CCD 0 cores"] <-->|"cross-LLC steal<br/>when local empty"| DSQ2["LLC_DSQ_BASE + 1<br/>CCD 1 cores"]
    end
```

- **Vtime encoding**: `now_cached + dsq_weight` — class weight ranges guarantee ordering (GAME always before NORMAL)
- **RODATA gate**: `if (nr_llcs <= 1) return;` skips all cross-LLC stealing on single-CCD systems

### Zero Global State

| Anti-pattern                | scx_cake                                      |
| :-------------------------- | :-------------------------------------------- |
| Global atomics              | **0** (except game_cpu_mask, transition-only) |
| Volatile variables          | **0**                                         |
| Division in hot path        | **0** (shift-based µs conversion: `>> 10`)    |
| Global vtime writes         | **0** (per-task only)                         |
| RCU lock/unlock in hot path | **0**                                         |

### SYNC Strip

During GAMING, `select_cpu` strips `SCX_WAKE_SYNC` from wake flags:

```c
if (cpu_bss[prev_cpu].sched_state_local == CAKE_STATE_GAMING)
    wake_flags &= ~SCX_WAKE_SYNC;
```

**Rationale**: In gaming, wakes are signal-only (vsync, GPU completion, futex unlock). SYNC dispatch migrates the wakee to the waker's CPU, destroying L1/L2 cache warmth (1.6-3.5µs refill penalty) for zero data-locality benefit. A/B tested: SYNC enabled = same or slightly worse FPS in Arc Raiders. Elden Ring's main thread was bouncing across 5+ cores/frame due to SYNC wakes from vkd3d_queue and GXWorkers on random cores.

### CO-RE Kernel Version Branching

`select_cpu` uses CO-RE (Compile Once, Run Everywhere) to support multiple kernel versions:

- **6.17+**: `scx_bpf_select_cpu_and` — single kfunc with cpumask parameter, handles affinity-restricted tasks (Wine/Proton)
- **6.12-6.16**: `scx_bpf_select_cpu_dfl` — legacy API via `__noinline` wrapper that isolates stack usage

The CO-RE check `__COMPAT_HAS_scx_bpf_select_cpu_and` is resolved at BPF load time — the unused path is **physically removed** from the JIT output. Not a runtime branch; zero cost.

### Kfunc Tunneling

`select_cpu` caches key decisions in per-CPU BSS (`cpu_bss`). Current tunneling uses `vtime_local` for per-CPU monotonic max vtime and `last_pid` for same-task fast paths in `cake_running`.

### PID Class Cache

`stopping_quantum_pack` writes each task's class to a BSS hash array (`pid_class_cache[pid & MASK]`). Gate 2's performance-ordered scan reads this instead of calling `bpf_task_storage_get()`:

| Lookup | Avg Latency | Tail (P99.9) |
| :--- | :--- | :--- |
| `bpf_task_storage_get` | 28ns | 1,982ns |
| BSS `pid_class_cache` | 14ns | 96ns |

Hash collisions are benign: worst case = wrong scan direction for one dispatch cycle.

### Enqueue Pipeline

`cake_enqueue` is a thin stub calling `enqueue_body`, which routes to one of three `__noinline` sub-functions:

| Path | Trigger | Frequency | Behavior |
| :--- | :--- | :--- | :--- |
| `enqueue_wakeup_path` | `SCX_ENQ_WAKEUP` or `SCX_ENQ_PREEMPT` | ~90% | Consumes staged_vtime_bits, applies new-flow bonus, 2x slice for GAME |
| `enqueue_requeue_path` | Neither wakeup nor preempt (yield/exhaust) | ~9% | 50% remaining slice (200µs floor), no new-flow bonus |
| `enqueue_nostaged` | `staged_vtime_bits` missing VALID bit | ~1% | Pre-init tasks — uses raw `now()` + quantum |

All three paths converge at `enqueue_dsq_dispatch` for DSQ insertion + class-aware kick.

### Stopping Pipeline

`cake_stopping` runs a 4-stage `__noinline` pipeline on every task stop:

1. **`stopping_drr_ewma`** — Computes runtime (`rt_raw`), updates EWMA wake counter (exponentially-decayed wake frequency), triggers reclassification on every 64th stop. Returns `rt_raw`.
2. **`stopping_reclassify`** (1/64 gate) — Full PELT classification: game family → audio → compositor → HOG/BG/NORMAL. MESI-guarded write avoids RODATA fetch when class is stable (~95% of calls).
3. **`stopping_eevdf_weight`** — Advances `dsq_vtime` by `rt_raw × vtime_mult >> 10`. Applies vtime floor. Returns `dsq_weight_base`.
4. **`stopping_quantum_pack`** — Packs PID class cache + staged_vtime_bits (VALID + NEW_FLOW + DSQ_WEIGHT) for enqueue consumption.

Each stage is `__noinline` to isolate register pressure — the eBPF verifier sees each function's 10-register budget independently.

### Class-Aware Kick Guard

When a task is enqueued into the per-LLC DSQ, `enqueue_dsq_dispatch` decides how aggressively to wake a target CPU based on the **class of the task currently running on that CPU**:

1. **Read 3 fields on one cache line**: `idle_hint`, `game_running`, and `sched_state_local` from `cpu_bss[enq_cpu]`. All at byte offsets 5, 29, and 28 — same 128B V-Cache sector, single cache line read.
2. **OR chain**: If `idle_hint || game_running || sched_state != GAMING` → use `SCX_KICK_IDLE` (gentle, no IPI on busy CPUs). This fires if the CPU is idle, or is running a GAME-class task (game, audio, compositor, kthread during gaming), or we're not in GAMING state.
3. **Aggressive IPI**: Only when all three conditions fail — GAMING state + non-game task on a busy target CPU — does the kick use a raw IPI (`flags = 0`).

The `game_running` flag is set by `running_task_change` using `task_class`: any task classified as `CAKE_CLASS_GAME` (game family members, audio daemons, compositors, kthreads during gaming) sets `game_running = 1`. This means:

- **Game threads are protected from interruption** by non-game IPI kicks
- **Audio/compositor threads get the same protection** as game render threads
- **Non-game tasks** (HOG, BG, NORMAL) get aggressively preempted when a DSQ task is waiting

### Starvation Guard

The tiered DSQ weight system intrinsically prevents starvation:

- **Non-overlapping weight ranges** guarantee that within each class, tasks compete fairly on vtime (runtime cost determines ordering)
- **New-flow bonus** gives newly-woken tasks a vtime advantage, preventing permanent queue-back
- **Deficit drain** ensures long-running tasks lose their new-flow bonus and compete normally
- **Vtime floor**: `vtime_local - 200ms` cap prevents infinite credit accumulation from long sleeps. Kernel analog: `update_min_vruntime()`. A task sleeping for hours can't monopolize the CPU for 200ms on wakeup.
- **Requeue slice reduction**: Yielded/preempted tasks get 50% of remaining slice with a 200µs floor, preventing micro-slicing while reducing priority for non-completing tasks.

The clock domain fix in `cake_running` (using `scx_bpf_now()` instead of `p->se.exec_start`) prevents a subtle starvation bug: after ~22 minutes, accumulated IRQ time drift in `exec_start` would exceed the u32 wrap boundary, corrupting elapsed-time checks and causing unconditional preemption (priority inversion).

**Anti-starvation slice lifecycle**: `p->scx.slice` is deliberately **not** written in `cake_stopping`. Writing it there causes the kernel's `balance_one()` to set `SCX_RQ_BAL_KEEP`, which skips `local_dsq` and `ops.dispatch()` entirely — starving all other tasks on the CPU. This was a verified regression. No other sched-ext scheduler (bpfland, cosmos, lavd) writes `p->scx.slice` in stopping. GAME double-slice is applied in `enqueue_wakeup_path` instead.

### Scheduler States

The userspace TUI drives state machine transitions written to BPF BSS:

| State           | Value | Trigger                            | Effect                                   |
| :-------------- | :---- | :--------------------------------- | :--------------------------------------- |
| **IDLE**        | 0     | No game or compiler detected       | Baseline — NORMAL/HOG classes only       |
| **COMPILATION** | 1     | ≥2 compiler processes at ≥78% PELT | Cluster co-scheduling for build locality |
| **GAMING**      | 2     | Game detected (Steam/.exe/family)  | Full priority system: GAME/HOG/BG active |

### Loader Intelligence

The Rust loader (`main.rs`) performs significant one-time work at startup, baking results into BPF RODATA (immutable after load):

**Prefcore Ranking → Core Steering Arrays**:

- Reads `/sys/devices/system/cpu/cpu*/cpufreq/amd_pstate_prefcore_ranking` for each CPU
- Sorts by descending rank (fastest first), grouping SMT siblings together: `[best_phys, best_smt, second_phys, second_smt, ...]`
- Populates `cpus_fast_to_slow` (GAME scan order) and `cpus_slow_to_fast` (non-GAME scan order) in RODATA
- 0xFF sentinel terminates the array on CPUs without prefcore rankings

**Audio Stack Detection** (2-phase):

1. **Phase 1 — Comm scan**: Searches `/proc/*/comm` for known audio daemons: `pipewire`, `wireplumber`, `pipewire-pulse`, `pulseaudio`, `jackd`, `jackdbus`
2. **Phase 2 — PipeWire socket scan**: Reads `/proc/net/unix` to find the PipeWire socket inode (`/run/user/<uid>/pipewire-0`), then scans `/proc/*/fd` for processes holding a file descriptor to that inode. This catches audio mixer daemons (`goxlr-daemon`, `easyeffects`, etc.) without brittle comm lists.

- Up to 8 audio TGIDs baked into `audio_tgids[]` RODATA. During GAMING, BPF promotes matching tasks to GAME class.

**Compositor Detection**:

- Scans `/proc/*/comm` for known Wayland/X11 compositors: `kwin_wayland`, `kwin_x11`, `mutter`, `gnome-shell`, `sway`, `Hyprland`, `weston`, `labwc`, `wayfire`, `river`, `gamescope`, `Xwayland`, `Xorg`, `X`
- Up to 4 compositor TGIDs baked into `compositor_tgids[]` RODATA. During GAMING, compositors receive GAME-level priority — essential for frame presentation latency parity.

**Topology Arrays**:

- `cpu_sibling_map[]` — SMT sibling pairs (Gate 2 class-mismatch filter)
- `cpu_llc_id[]` — Per-CPU LLC assignment (DSQ sharding)
- `llc_cpu_mask[]`, `core_cpu_mask[]` — Bitmask sets for LLC/core grouping
- `big_core_phys_mask`, `little_core_mask`, `vcache_llc_mask` — Intel hybrid + V-Cache topology

---

## 5. Configuration

### Profiles (`--profile, -p`)

| Profile     | Quantum | Starvation | Use Case                              |
| :---------- | :------ | :--------- | :------------------------------------ |
| **gaming**  | 2ms     | 100ms      | **(Default)** Balanced for most games |
| **esports** | 1ms     | 50ms       | Competitive FPS, ultra-low latency    |
| **legacy**  | 4ms     | 200ms      | Older CPUs, reduced overhead          |
| **battery** | 4ms     | 200ms      | Power-efficient for handhelds/laptops |
| **default** | 2ms     | 100ms      | Alias for gaming                      |

### CLI Arguments

| Argument                  | Default  | Description                             |
| :------------------------ | :------- | :-------------------------------------- |
| `--profile, -p <PROFILE>` | `gaming` | Select preset profile                   |
| `--quantum <µs>`          | profile  | Base time slice in microseconds         |
| `--new-flow-bonus <µs>`   | profile  | Extra deficit for newly woken tasks     |
| `--starvation <µs>`       | profile  | Max run time before forced preemption   |
| `--verbose, -v`           | `false`  | Enable live TUI stats display           |
| `--interval <secs>`       | `1`      | TUI refresh interval                    |
| `--testing`               | `false`  | Automated benchmarking mode (see below) |

### Testing Mode

`--testing` runs an automated benchmark for CI and regression testing:

1. **Warmup**: 1 second pause for the scheduler to stabilize
2. **Collection**: 10 seconds of operation, sampling per-CPU BSS dispatch counters
3. **Output**: Single-line JSON to stdout:

```json
{
  "duration_sec": 10.0,
  "total_dispatches": 1847263,
  "dispatches_per_sec": 184726.3
}
```

The scheduler exits automatically after printing. Requires a **debug build** (release builds silently ignore `--testing`). Useful for comparing scheduling throughput across code changes.

### Yield-Gated Quantum

Instead of per-tier multipliers, scx_cake uses a **yield-gated quantum** system:

- **Yielders** (cooperative tasks that voluntarily yield): Get full quantum ceiling (up to 50ms)
- **Non-yielders** (bulk consumers): Get PELT-scaled slice, capped to 2ms (or 8ms during COMPILATION)
- **GAME during GAMING**: 2x quantum (tasks yield at vsync, so they'll never consume it all)

> [!NOTE]
> **Higher weight = dispatches later.** GAME [0-5120] dispatches before NORMAL [8192-13312] dispatches before BG [32768-37888] dispatches before HOG [49152-54272]. Within each class, PELT utilization and runtime cost provide fine-grained ordering.

### Examples

```bash
# Default gaming profile
sudo scx_cake

# Competitive gaming
sudo scx_cake -p esports

# Gaming with custom quantum and live stats
sudo scx_cake --quantum 1500 -v

# Battery-friendly for laptop gaming
sudo scx_cake -p battery
```

---

## 6. Build Modes

`scx_cake` has two build modes that control whether telemetry instrumentation is compiled into the BPF code.

### Release Mode (`cargo build --release`)

- `build.rs` passes `-DCAKE_RELEASE=1` to Clang
- **All `#ifndef CAKE_RELEASE` blocks are dead-code eliminated** — arena telemetry, per-task counters, gate hit tracking, BenchLab, and the entire `cake_task_ctx` arena struct are compiled out
- `CAKE_STATS_ENABLED` is a compile-time constant `0` — Clang eliminates all telemetry branches at BPF compile time
- Per-CPU arena blocks shrink from 128B (debug) to 64B (release)
- **TUI still works** but only shows aggregate BSS stats (gate latencies, dispatch counts). Per-task arena fields (gate hit %, callback durations, quantum breakdown) are unavailable

> [!TIP]
> Use `--release` for production gaming. The telemetry overhead is small (~2-5%), but eliminating it gives the tightest possible scheduling latency.

### Debug Mode (`cargo build`)

- `CAKE_RELEASE` is **not defined** — all telemetry code is compiled in
- `CAKE_STATS_ENABLED` becomes a volatile BSS read of `enable_stats`, controllable at runtime
- `CAKE_STATS_ACTIVE` = `CAKE_STATS_ENABLED && !bench_active` — telemetry is suppressed during BenchLab runs to avoid measuring measurement overhead
- Full per-task arena telemetry: gate hit counters, callback duration timers, quantum utilization, waker chain, LLC placement, dispatch gap tracking
- **Required for**: full TUI live matrix, BenchLab benchmarks, per-task gate analysis

```bash
# Production (release) — minimal overhead, limited TUI
cargo build --release -p scx_cake
sudo ./target/release/scx_cake -v

# Development (debug) — full telemetry, complete TUI
cargo build -p scx_cake
sudo ./target/debug/scx_cake -v
```

### Conditional Compilation (`build.rs`)

`build.rs` detects the build host's hardware topology from sysfs and passes compile-time flags to BPF Clang. This right-sizes all BPF arrays, loops, and masks to the exact hardware — zero wasted BSS, zero dead loop iterations.

| Flag | Detection | Effect |
| :--- | :--- | :--- |
| `CAKE_MAX_CPUS` | `/sys/devices/system/cpu/online` → next_pow2 [16,512] | Sizes all per-CPU arrays and loop bounds |
| `CAKE_MAX_LLCS` | `/sys/devices/system/cpu/cpu*/cache/index3/id` → unique count | Sizes LLC mask arrays and DSQ IDs |
| `CAKE_SINGLE_LLC` | `max_llcs == 1` | Eliminates all cross-LLC steal code + `cake_tick` body |
| `CAKE_HAS_HYBRID` | Any CPU with different `cpu_capacity` | Compiles in Gate 2 P/E scan, prefcore arrays, core steering |
| `CAKE_RELEASE` | `--release` profile | Eliminates all telemetry (see Release Mode above) |

On a 9800X3D (16 CPUs, 1 LLC, no hybrid): arrays are 16-wide, all cross-LLC and Gate 2 code is physically absent from the BPF object. The verifier never sees those paths.

---

## 7. TUI Guide

The TUI is activated with `--verbose` / `-v` and provides real-time visibility into every scheduling decision. It requires a **debug build** for full per-task telemetry.

### Tabs

Navigate between tabs with `Tab` / `→` (next) and `Shift-Tab` / `←` (previous).

| Tab                 | Content                                                                                |
| :------------------ | :------------------------------------------------------------------------------------- |
| **Dashboard**       | Aggregate stats header + live task matrix with per-task scheduling data                |
| **Topology**        | CPU topology map: CCDs, P/E cores, V-Cache, SMT siblings, core-to-core latency heatmap |
| **BenchLab**        | In-kernel kfunc microbenchmarks: 60+ operations with ns-precision timing               |
| **Reference Guide** | Quick reference for column meanings, keybindings, and terminology                      |

### Dashboard: Aggregate Stats

The top section shows system-wide scheduling statistics aggregated from per-CPU BSS counters:

- **Gate hit rates**: Gate 1 (prev_cpu idle) %, Gate 2 (perf-ordered scan) %, Gate 3 (kernel fallback) %, Tunnel %
- **Dispatch stats**: DSQ queued, consumed, local dispatches, cross-LLC steals, dispatch misses
- **Flow stats**: New flow dispatches, old flow dispatches, DRR++ deficit activity
- **Game state**: Detected game name, TGID, PPID, thread count, sched_state (IDLE/COMPILATION/GAMING)
- **EEVDF stats**: Vprot suppression count, capacity scaling events

### Dashboard: Live Task Matrix

The scrollable table shows one row per task with these columns:

| Column     | Meaning                                                                             |
| :--------- | :---------------------------------------------------------------------------------- |
| **CPU**    | Last CPU the task ran on                                                            |
| **PID**    | Process ID                                                                          |
| **ST**     | Liveness: ●LIVE (BPF-tracked + running), ○IDLE (alive, no BPF data), ✗DEAD (exited) |
| **COMM**   | Task command name (from `/proc/PID/comm`)                                           |
| **CLS**    | Task class: GAME 🎮, NORM, HOG 🔥, BG                                               |
| **VCSW**   | Voluntary context switches (delta per interval)                                     |
| **AVGRT**  | Average runtime per execution bout (µs)                                             |
| **MAXRT**  | Maximum single-run duration (µs)                                                    |
| **GAP**    | Average dispatch gap — time between consecutive runs (µs)                           |
| **JITTER** | Scheduling jitter — variance in dispatch timing (µs)                                |
| **WAIT**   | Average wait time in DSQ before dispatch (µs)                                       |
| **RUNS/s** | Scheduling frequency — how often this task runs per second                          |
| **CPU**    | Current/last CPU placement (core ID)                                                |
| **SEL**    | `select_cpu` callback duration (ns)                                                 |
| **ENQ**    | `enqueue` callback duration (ns)                                                    |
| **STOP**   | `stopping` callback duration (ns)                                                   |
| **RUN**    | `running` callback duration (ns)                                                    |
| **G1**     | Gate 1 (prev_cpu idle) hit percentage for this task                                 |
| **G3**     | Gate 3 (kernel scan) hit percentage for this task                                   |
| **DSQ**    | DSQ tunnel (all busy) hit percentage                                                |
| **MIGR/s** | CPU migrations per second                                                           |
| **TGID**   | Thread Group ID (process leader PID)                                                |
| **Q%F**    | Quantum full — % of runs where task consumed entire time slice                      |
| **Q%Y**    | Quantum yield — % of runs where task yielded voluntarily                            |
| **Q%P**    | Quantum preempt — % of runs where task was preempted                                |
| **WAKER**  | PID of the last task that woke this task                                            |
| **NICE**   | Vtime multiplier (1024=nice0) — EEVDF vruntime scaling factor                       |

Tasks are grouped by TGID (process) with collapsible headers. The detected game family is highlighted.

### Topology Tab

Displays the detected CPU topology in a visual format:

- **CCD map**: Which cores belong to which LLC/CCD
- **P/E core identification**: Big cores vs Little cores (Intel hybrid)
- **V-Cache detection**: Asymmetric LLC sizes across CCDs
- **SMT siblings**: Logical CPU pairs sharing a physical core
- **Core-to-core latency matrix**: Press `b` to run an ETD (Empirical Topology Discovery) benchmark measuring CAS ping-pong latency between every core pair. Results display as a color-coded heatmap.

### BenchLab Tab

In-kernel microbenchmark suite measuring the real cost of scheduling primitives:

- **60+ benchmarked operations**: kfunc trampolines, BSS reads, arena lookups, RODATA constants, data structure accesses, idle cascades, classification paths
- Each operation shows: **ID**, **Name**, **Category** (Data Read, Synchronization, Idle Selection, etc.), **Type** (K=kfunc, C=cake-internal), and **measured latency in nanoseconds**
- Press `b` to trigger a benchmark run (runs in-kernel, suppresses telemetry during measurement)
- Results persist across runs; press `c` to copy to clipboard for external analysis

### Keybindings

| Key               | Action                                                              |
| :---------------- | :------------------------------------------------------------------ |
| `q` / `Esc`       | Quit                                                                |
| `Tab` / `→`       | Next tab                                                            |
| `Shift-Tab` / `←` | Previous tab                                                        |
| `↑` / `↓`         | Scroll table / bench results                                        |
| `t`               | Jump to top of table                                                |
| `s`               | Cycle sort column (PID → PELT → Runs/s → CPU → Gate1% → ...)        |
| `S`               | Toggle sort direction (ascending ↔ descending)                      |
| `f`               | Toggle filter: BPF-tracked only ↔ all system tasks                  |
| `Enter`           | Collapse/expand PPID group (Dashboard)                              |
| `Space`           | Collapse/expand TGID group (Dashboard)                              |
| `x`               | Fold/unfold all PPID groups (Dashboard)                             |
| `c`               | Copy current tab data to clipboard                                  |
| `d`               | Dump full snapshot to timestamped file (`tui_dump_<epoch>.txt`)     |
| `r`               | Reset all BSS stats counters to zero                                |
| `b`               | Run benchmark (BenchLab on most tabs, core latency on Topology tab) |
| `+` / `=`         | Faster refresh rate (halve interval, min 250ms)                     |
| `-`               | Slower refresh rate (double interval, max 5000ms)                   |

### Data Export

Two export methods are available from any tab:

- **Clipboard** (`c`): Copies the current tab's data as formatted text. On Dashboard, includes aggregate stats + full task matrix. On BenchLab, includes all benchmark results with categories.
- **File dump** (`d`): Writes a complete snapshot to `tui_dump_<epoch>.txt` in the current working directory. Includes all stats, task matrix, and metadata. Useful for before/after comparisons or sharing with developers.

---

## 8. Performance

### Target Hardware

| Component | Specification                       |
| :-------- | :---------------------------------- |
| CPU       | AMD Ryzen 7 9800X3D (1 CCD, 8C/16T) |
| Kernel    | Linux 6.12+ with sched_ext          |

### Design Targets

- **Sub-microsecond scheduling decisions** — Select CPU + enqueue under 100ns typical
- **Zero bus lock contention** — No global atomics means no scaling regression under load
- **Consistent 1% lows** — Tiered weight system prevents frame time spikes from background work
- **Automatic game detection** — Two-phase Steam/Wine detection with holdoff hysteresis

### Benchmarks

- [schbench](https://github.com/brendangregg/schbench) — Scheduler latency microbenchmark
- Arc Raiders — AAA game stress testing (frame rates, 1% lows)
- Splitgate 2 — Competitive FPS latency testing

> [!NOTE]
> Throughput workloads (compilers, render farms) will perform **worse** than CFS/EEVDF. This scheduler explicitly trades throughput for latency — the same tradeoff network CAKE makes for packets.

### Comparison with Other sched_ext Schedulers

| Feature                 | scx_cake                            | scx_bpfland                    | scx_lavd                       | scx_cosmos                        |
| :---------------------- | :---------------------------------- | :----------------------------- | :----------------------------- | :-------------------------------- |
| **Primary goal**        | Gaming latency                      | General-purpose interactive    | Latency-sensitive workloads    | General-purpose + gaming          |
| **Task classification** | 4-class (GAME/NORMAL/HOG/BG)        | Interactive vs batch (2-class) | Urgency score (continuous)     | Latency criticality (multi-level) |
| **Game detection**      | Automatic (Steam/Wine/process tree) | None                           | Behavioral (latency patterns)  | None                              |
| **DSQ structure**       | Per-LLC vtime-ordered               | Per-LLC + shared               | Global ordered                 | Per-LLC                           |
| **Idle CPU selection**  | 3-gate custom + kernel fallback     | Kernel default                 | Custom idle scan               | Kernel default + LLC preference   |
| **EEVDF features**      | Nice scaling, kick guard, capacity  | None                           | Urgency scoring                | None                              |
| **Core steering**       | Prefcore-aware (P/E, V-Cache)       | LLC-aware                      | LLC-aware                      | LLC-aware                         |
| **Global atomics**      | 0 (MESI-guarded BSS)                | Minimal                        | Some                           | Minimal                           |
| **When to choose**      | Gaming-first, multi-game families   | Desktop daily driver           | Mixed interactive + throughput | Desktop with gaming needs         |

> [!NOTE]
> scx_cake is **not** a general-purpose scheduler. It makes explicit tradeoffs that benefit gaming at the cost of throughput workloads. For daily desktop use without gaming, `scx_bpfland` or `scx_cosmos` may be better choices.

---

## 9. Vocabulary

### Core Concepts

| Term            | Definition                                                                                                                               |
| :-------------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| **CAKE**        | [Common Applications Kept Enhanced](https://www.bufferbloat.net/projects/codel/wiki/Cake/). Network AQM algorithm this scheduler adapts. |
| **DRR++**       | Deficit Round Robin++. Network algorithm balancing fair queuing with strict priority.                                                    |
| **PELT**        | Per-Entity Load Tracking. Kernel mechanism providing exponentially-decayed CPU utilization per task (`util_avg`).                        |
| **Class**       | Classification level (GAME/NORMAL/HOG/BG). Controls DSQ weight, quantum cap, and preemption policy.                                      |
| **Deficit**     | Per-task credit from DRR++. New tasks get bonus credit; GAME tasks skip deficit drain entirely.                                          |
| **Quantum**     | Base time slice a task is allotted before a scheduling decision.                                                                         |
| **Sleep Lag**   | Implicit EEVDF credit from time spent sleeping. A task's dormant vtime naturally falls behind `vtime_now`, so it sorts lower (dispatches sooner) when it wakes.    |
| **Waker Boost** | Transitive priority inheritance: tasks woken by GAME threads get GAME-level priority for one cycle.                                      |
| **Staged Bits** | Pre-computed scheduling state packed into a single u64 by `cake_stopping`, consumed by `cake_enqueue` to avoid redundant computation.    |
| **Jitter**      | Variance in scheduling latency between consecutive events. Low jitter = consistent frame delivery.                                       |

### Architecture

| Term                    | Definition                                                                                     |
| :---------------------- | :--------------------------------------------------------------------------------------------- |
| **Task Storage**        | BPF local storage attached to each task. 10ns lookup; holds CL0 hot scheduling fields.         |
| **Arena**               | BPF memory region for per-task telemetry data. 29ns TLB walk; dead in release builds.          |
| **BSS**                 | Zero-initialized BPF global data. Per-CPU arrays (`cpu_bss`) provide L1-cached hot fields.     |
| **Kfunc Tunneling**     | Caching kfunc return values in per-CPU BSS to avoid redundant trampoline calls.                |
| **MESI Guard**          | Read-before-write pattern: skip store if value unchanged, preventing cache invalidation.       |
| **RODATA Gate**         | Compile-time constant that eliminates entire code paths (e.g., single-CCD skips stealing).     |
| **Confidence Gate**     | Reclassification runs every 64th stop. 63/64 stops reuse cached task_class from task_storage.  |
| **BenchLab**            | In-kernel microbenchmark suite measuring kfunc costs, data access patterns, and gate cascades. |
| **Bitfield Coalescing** | Packing fields written together into adjacent bits for fused clear/set ops.                    |
| **CO-RE**               | Compile Once, Run Everywhere. BPF mechanism that resolves version-specific kfuncs at load time, physically removing dead paths from JIT output. |
| **PID Class Cache**     | BSS hash array tunneling task_class from stopping to select_cpu. 2x faster than task_storage with 20x lower tail jitter. |
| **EWMA Wake Counter**   | Per-task exponentially-weighted wake frequency tracker. Short intervals ramp up; long intervals decay. Proxy for interactive vs. batch behavior. |
| **Vtime Floor**         | `vtime_local - 200ms` cap preventing infinite sleep credit. Kernel analog: `update_min_vruntime()`. |
| **Capacity Scaling**    | P/E core vtime normalization via `cpuperf_cap_table[cpu]`. E-core runtime scaled by capacity so tasks accumulate proportionally less vruntime. JIT-eliminated on symmetric AMD (all 1024). |

### Hardware

| Term              | Definition                                                                                              |
| :---------------- | :------------------------------------------------------------------------------------------------------ |
| **CCD**           | Core Complex Die. Physical chiplet containing cores (9800X3D: 1 CCD, 9950X: 2 CCDs).                    |
| **LLC**           | Last Level Cache (L3). Cores in same LLC communicate ~3-5x faster than cross-LLC.                       |
| **SMT**           | Simultaneous Multi-Threading. Two logical CPUs per physical core.                                       |
| **P/E Cores**     | Intel hybrid architecture: Performance cores (fast) and Efficiency cores (power-saving).                |
| **V-Cache**       | AMD 3D V-Cache. Asymmetric LLC sizes across CCDs (e.g., 96MB vs 32MB on 9800X3D).                       |
| **ETD**           | Empirical Topology Discovery. Measures inter-core CAS latency at startup for display.                   |
| **Cache Line**    | 64-byte block of memory. Smallest unit the CPU loads from RAM. Foundation of data layout.               |
| **MESI Protocol** | Cache coherency protocol (Modified/Exclusive/Shared/Invalid). Unnecessary writes trigger invalidations. |

### Performance

| Term                | Definition                                                                              |
| :------------------ | :-------------------------------------------------------------------------------------- |
| **Hot Path**        | Code on every scheduling decision: select_cpu → enqueue → dispatch.                     |
| **Cold Path**       | Infrequent code: task init, reclassification (every 64th stop).                         |
| **Direct Dispatch** | `SCX_DSQ_LOCAL_ON` — task goes directly to a CPU's local queue, bypassing the DSQ path. |
| **1% Lows**         | Average framerate of the slowest 1% of frames. Key metric for stutter.                  |
| **Branchless**      | Code avoiding `if/else` to prevent CPU pipeline stalls from branch misprediction.       |
| **Register Budget** | eBPF VM has 10 general-purpose registers (R0-R9). Each `__noinline` function gets its own budget. Stack spills (memory loads) add ~5ns latency per spill. |

### Anti-Patterns

| Term                   | Definition                                                                                    |
| :--------------------- | :-------------------------------------------------------------------------------------------- |
| **False Sharing**      | Performance penalty when CPUs write to different data on the same 64-byte cache line.         |
| **Cache Invalidation** | Forcing other cores to discard cached data via unnecessary writes. Causes bus locking.        |
| **Micro-slicing**      | Preempting tasks too frequently. Queued interruptions degrade throughput and increase jitter. |
| **Volatile**           | Compiler hint preventing optimization. Clogs LSU, breaks ILP/MLP parallelism. Avoid in BPF.   |

---

**License**: GPL-2.0
**Maintainer**: RitzDaCat
