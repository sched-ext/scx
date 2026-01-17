# scx_cake: A Low-Latency Gaming Scheduler

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: 6.12+](https://img.shields.io/badge/Kernel-6.12%2B-green.svg)](https://kernel.org)
[![sched_ext](https://img.shields.io/badge/sched__ext-scheduler-orange.svg)](https://github.com/sched-ext/scx)
[![AI Usage: True](https://img.shields.io/badge/AI%20Usage-True-lightgrey.svg)]()

> **ABSTRACT**: `scx_cake` is an experimental BPF CPU scheduler designed for **gaming workloads**. It abandons traditional "Fairness" in favor of strict "Latency Prioritization", reducing total scheduling overhead to approximately **~70-120 CPU cycles per task\*** (down from ~470 cycles in naive implementations).
>
> _\*Estimates are speculative and hardware-dependent (Ryzen 7 9800X3D)._

---

## Table of Contents

1. [Research Objectives](#1-research-objectives)

   - [Test Platform](#test-platform)

2. [Architecture: The Zero-Cycle Engine](#2-architecture-the-zero-cycle-engine)

   - [Cycle Cost Analysis](#cycle-cost-analysis)
     - [Per-Function Breakdown](#per-function-breakdown)
     - [Call Frequency Estimation](#call-frequency-estimation-gaming-workload-on-9800x3d)
     - [Before vs After Comparison](#comparison-before-vs-after-optimizations)
   - [A. Pre-Computed Math](#a-pre-computed-math-2-cycles)
   - [B. Global Bitmask Search](#b-global-bitmask-search-5-cycles)
   - [C. The Scoreboard](#c-the-scoreboard-neighbor-awareness)
   - [D. Direct Dispatch Bypass](#d-direct-dispatch-bypass-5-cycles)

3. [The 7-Tier Classification System](#3-the-7-tier-classification-system)

   - [Tier Classification Logic](#tier-classification-logic)

4. [Performance Optimizations](#4-performance-optimizations)

   - [Understanding CPU Cycles](#understanding-cpu-cycles)
   - [A. Timestamp Caching](#a-timestamp-caching-scx_bpf_now)
   - [B. Cache Line Optimization](#b-cache-line-optimization)
   - [C. Idle Path Streamlining](#c-idle-path-streamlining)
   - [D. Division-Free Arithmetic](#d-division-free-arithmetic-bitwise-magic)
   - [E. Branchless Programming](#e-branchless-programming)
   - [F. Pre-Computed Values](#f-pre-computed-values)

5. [HPC Patterns & Industry Best Practices](#5-hpc-patterns--industry-best-practices)

   - [Confirmed Patterns](#confirmed-patterns-already-implemented)
   - [Evaluated But Not Implemented](#evaluated-but-not-implemented)
   - [Key References](#key-references)

6. [Experimental Findings](#6-experimental-findings)

   - [A. Performance Wins](#a-performance-wins-)
   - [B. Performance Regressions & Lessons Learned](#b-performance-regressions--lessons-learned-)
   - [C. The "1% Low" Regression (Case Study)](#c-the-1-low-regression-case-study)
   - [D. The "FPS Overshoot" Phenomenon](#d-the-fps-overshoot-phenomenon)
   - [E. Performance Baseline](#e-performance-baseline)
   - [F. Benchmarking](#f-benchmarking)

7. [Usage](#7-usage)

   - [Quick Start](#quick-start)
   - [Monitoring (Verbose Mode)](#monitoring-verbose-mode)
   - [CLI Options](#cli-options)

8. [License & Acknowledgments](#8-license--acknowledgments)

9. [Glossary](#9-glossary)

---

## Glossary

Quick reference for technical terms used throughout this document.

| Term                 | Definition                                                                                                                                  |
| :------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| **BPF / eBPF**       | Extended Berkeley Packet Filter - a technology allowing sandboxed programs to run in kernel space without modifying kernel source           |
| **sched_ext**        | Linux kernel framework (6.12+) that allows custom CPU schedulers to be implemented as BPF programs                                          |
| **DSQ**              | Dispatch Queue - a holding queue where tasks wait before being assigned to a CPU                                                            |
| **Tier**             | Priority level (0-6) assigned to tasks based on behavior; determines quantum, preemption rights, and demotion thresholds                    |
| **Quantum**          | Base timeslice given to a task; default 2ms. Higher tiers get shorter slices (more preemption points)                                       |
| **Slice Multiplier** | Per-tier factor applied to quantum; e.g., 0.7x for Tier 0 means 1.4ms slice at 2ms quantum                                                  |
| **Wait Budget**      | Max time a task can wait in queue before being considered for demotion; prevents queue bloat                                                |
| **Starvation Limit** | Max runtime before forced preemption; safety net for runaway tasks                                                                          |
| **TZCNT**            | "Trailing Zero Count" - x86 hardware instruction (`__builtin_ctzll`) that finds the first set bit in O(1) time                              |
| **TSC**              | Time Stamp Counter - hardware register counting CPU cycles; reading it costs ~15-25 cycles                                                  |
| **rq->clock**        | Cached timestamp on each CPU's run queue; cheaper to read than TSC (~3-5 cycles)                                                            |
| **Vtime**            | Virtual Time - a fairness mechanism that normalizes task runtimes; deleted in scx_cake                                                      |
| **Sparse Score**     | 0-100 metric computed from task behavior; high score = short bursts = high priority tier                                                    |
| **Hot Path**         | The critical code path executed on every scheduling decision (wakeup → dispatch)                                                            |
| **False Sharing**    | Performance degradation when CPUs update different variables on the same cache line                                                         |
| **Cache Line**       | 64-byte block of memory fetched as a unit; crossing lines or sharing causes overhead                                                        |
| **L1 Cache**         | Fastest CPU cache (~1-4 cycles access); our task context is designed to fit here                                                            |
| **Direct Dispatch**  | Bypassing the global queue to place a task directly on an idle CPU's local queue                                                            |
| **Preemption**       | Forcibly stopping a running task to run a higher-priority one                                                                               |
| **Starvation**       | When a task waits too long without running; our starvation limits prevent this                                                              |
| **1% Low FPS**       | Gaming benchmark metric: the FPS that 99% of frames exceed; indicates stutter/smoothness                                                    |
| **Context Switch**   | The CPU operation of saving one task's state and loading another's (~1000+ cycles)                                                          |
| **Atomic Operation** | CPU instruction that completes indivisibly; used for lock-free concurrent access                                                            |
| **Branchless**       | Code without if/else jumps; avoids branch misprediction penalty (~15-20 cycles)                                                             |
| **Multiply-Shift**   | Division approximation using `x * magic >> shift`; avoids slow division instruction                                                         |
| **SMT**              | Simultaneous Multi-Threading (Hyperthreading); 2 threads share one physical core                                                            |
| **NUMA**             | Non-Uniform Memory Access; memory access time varies by which CPU socket owns the RAM                                                       |
| **IPC**              | Instructions Per Cycle; measure of CPU efficiency (higher = better)                                                                         |
| **EMA**              | Exponential Moving Average - lightweight runtime estimator: `new_avg = (old_avg * 7 + sample) >> 3`. Replaced Kalman filter (too CPU-heavy) |

---

## 1. Research Objectives

Modern Operating System schedulers (CFS, EEVDF) are designed for **Fairness** and **Throughput**.

**The Problem**: In competitive gaming, "Fairness" is detrimental. If the scheduler pauses the Game Render thread to let a background compiler run "fairly", the player perceives stutter (1% low FPS drop) or input lag.

**The Hypothesis**: By removing fairness logic and optimizing the "Hot Path" to run faster than a DRAM access (**Wait-Free**), we can achieve hardware-level responsiveness.

_(See [Section 3.1](#comparison-scx_cake-vs-eevdf) for a detailed comparison with EEVDF)_

**The Solution**: A **7-Tier Classification System** combined with optimized scheduling primitives.

### Test Platform

- **CPU**: AMD Ryzen 7 9800X3D (8 cores, 16 threads with SMT) @ ~5.0 GHz
- **RAM**: 96GB DDR5
- **GPU**: NVIDIA RTX 4090
- **OS**: CachyOS 6.18 (Linux kernel 6.12+)

---

## 2. Architecture: The Zero-Cycle Engine

The core innovation of `scx_cake` is the reduction of scheduling overhead by **~70%** compared to standard implementations.

> [!WARNING] > **Speculative Estimates**: All cycle counts listed below are **conservative estimates** based on the referenced AMD Ryzen 7 9800X3D architecture. Actual runtime performance depends heavily on CPU frequency, cache state, and memory timings.

### Cycle Cost Analysis

#### Per-Function Breakdown

| Function                | Role                    | Estimated Cycles (Speculative\*) | Key Optimizations                                                |
| :---------------------- | :---------------------- | :------------------------------- | :--------------------------------------------------------------- |
| `cake_enqueue`          | Task wakeup             | ~2-5c                            | Pre-computed tier (bitfield extract), MLP loads                  |
| `cake_select_cpu`       | Find idle CPU           | ~15-25c                          | `scx_bpf_now()`, **Wait-Free Dual-View Map**, MLP "Cluster Bomb" |
| `cake_dispatch`         | Move task to CPU        | ~5-10c                           | Direct dispatch bypass (SCX_ENQ_LAST)                            |
| `cake_running`          | Task starts             | ~15-25c                          | `scx_bpf_now()`, Prefetch hints                                  |
| `cake_stopping`         | Task stops              | ~40-50c                          | **Fused Load-Compute-Store**, Tier recalc                        |
| `cake_update_idle`      | CPU idle transition     | ~5-10c                           | Single atomic byte write (Wait-Free)                             |
| **Hot Path Total**      | enqueue→select→dispatch | **~22-40c**                      | --                                                               |
| **Full Task Lifecycle** | All callbacks           | **~70-120c**                     | --                                                               |

#### Call Frequency Estimation (Gaming Workload on 9800X3D)

| Event                        | Est. Frequency | Cycles/Event\* | Cycles/Second         | % of 1 Core |
| :--------------------------- | :------------- | :------------- | :-------------------- | :---------- |
| Task wakes                   | ~100,000/sec   | ~25c           | 2,500,000             | 0.05%       |
| Task stops                   | ~100,000/sec   | ~45c           | 4,500,000             | 0.09%       |
| Idle transitions             | ~50,000/sec    | ~7c            | 350,000               | 0.007%      |
| **Total Scheduler Overhead** | --             | --             | **~7.35M cycles/sec** | **~0.15%**  |

_Note: At 5 GHz, one core executes 5,000,000,000 cycles/sec. Scheduler overhead is negligible._

#### Comparison: Before vs After Optimizations

| Metric                     | Naive Implementation | scx_cake             | Improvement    |
| :------------------------- | :------------------- | :------------------- | :------------- |
| Hot path (wakeup→dispatch) | ~400c                | ~25c                 | **16x faster** |
| Full task lifecycle        | ~470c                | ~90c                 | **5x faster**  |
| CPU idle check             | ~300c (map scan)     | ~5c (Wait-Free Scan) | **60x faster** |
| Timestamp read             | ~20c (TSC)           | ~5c (cached)         | **4x faster**  |

---

### A. Pre-Computed Math (2 Cycles)

**The Innovation**: All complex math (Tier calculation, Slice adjustment) is moved to the "Stopping Path" (when a task finishes).

```c
/* OLD: Math calculated ON WAKEUP (Critical Path) - ~100 Cycles */
u64 vtime = (p->scx.dsq_vtime * 100) / weight; // Division!
u8 tier = calculate_tier(p->runtime);          // Branching!

/* NEW: Pre-Computed. Just Load. - 2 Cycles */
u8 tier = GET_TIER(tctx);  // L1 Load (bitfield extract)
```

### B. Wait-Free Dual-View Map (5 Cycles)

**The Innovation**: A global `idle_map` that supports both "Byte-Granularity Writes" (Wait-Free) and "Chunk-Granularity Reads" (Fast Scan).

```c
/* Dual-View Union in .bss */
union {
    u8  as_bytes[64];   /* WRITE VIEW: Access individually (No False Sharing logic needed) */
    u64 as_chunks[8];   /* READ VIEW:  Access in 8 chunks (Fast Scan) */
} idle_map;

/* WRITER (Idle Path): Single byte write. No ATOMIC LOCK. */
idle_map.as_bytes[cpu] = 1;

/* READER (Select CPU): Wide load to check 8 CPUs at once. */
if (idle_map.as_chunks[0]) ... // Checks CPUs 0-7 instaneously
```

### C. MLP "Cluster Bomb" (Parallel Loads)

**The Innovation**: Issuing all independent memory loads at the start of a function to maximize Memory Level Parallelism.

```c
/* OLD: Serial Pointer Chasing - ~60 Cycles Latency */
tctx = get_ctx(p);      // Stall...
tier = tctx->tier;      // Stall...
map  = bpf_map_lookup;  // Stall...

/* NEW: Cluster Bomb - ~20 Cycles Latency (Overlapped) */
u64 spec_mask = victim_mask;           // Load 1
u8 tier = GET_TIER(tctx);              // Load 2
u8 prev_idle = idle_map.as_bytes[cpu]; // Load 3
/* CPU executes all loads in parallel while ALU calculates */
```

### D. Direct Dispatch Bypass (SCX_ENQ_LAST)

**The Innovation**: Directly assigning a task to a CPU's local queue, bypassing global logic and redundant BPF calls.

```c
/* OLD: Standard Queueing - ~50 Cycles */
scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice);

/* NEW: Direct to CPU - 5 Cycles */
/* SCX_ENQ_LAST tells kernel to skip expensive "re-queue" checks */
scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, quantum_ns, SCX_ENQ_LAST);
```

---

## 3. The 7-Tier Classification System

Tasks are classified by **Behavior**, not "Niceness". The tier determines timeslice, preemption aggressiveness, and demotion thresholds.

### Tier Overview

| Tier  | Name             | Typical Tasks                   | Priority          |
| :---- | :--------------- | :------------------------------ | :---------------- |
| **0** | Critical Latency | Mouse, keyboard, game input     | Highest           |
| **1** | Realtime         | Audio, networking, vsync        | Very High         |
| **2** | Critical         | Compositor, kernel threads      | High              |
| **3** | Gaming           | Game render loop, physics       | Normal (baseline) |
| **4** | Interactive      | Browsers, editors, desktop apps | Lower             |
| **5** | Batch            | Compilers, builds, nice'd tasks | Low               |
| **6** | Background       | Encoders, backup, bulk work     | Lowest            |

### Tier Timing Parameters

| Tier  | Wait Budget (AQM) | Starvation Limit | Slice Multiplier  | Quantum (2ms default) |
| :---- | :---------------- | :--------------- | :---------------- | :-------------------- |
| **0** | 100µs             | 5ms              | 0.70x (717/1024)  | 1.4ms                 |
| **1** | 750µs             | 3ms              | 0.80x (819/1024)  | 1.6ms                 |
| **2** | 2ms               | 4ms              | 0.90x (922/1024)  | 1.8ms                 |
| **3** | 4ms               | 8ms              | 1.00x (1024/1024) | 2.0ms                 |
| **4** | 8ms               | 16ms             | 1.10x (1126/1024) | 2.2ms                 |
| **5** | 20ms              | 40ms             | 1.20x (1229/1024) | 2.4ms                 |
| **6** | ∞                 | 100ms            | 1.30x (1331/1024) | 2.6ms                 |

_Default: `--quantum 2000` (2ms)_

### Tier Classification Logic

Tasks are classified based on their **sparse score** (0-100) and **runtime behavior**:

| Sparse Score | Avg Runtime | Tier Assignment               | Behavior                       |
| :----------- | :---------- | :---------------------------- | :----------------------------- |
| 100          | < 50µs      | **Tier 0** (Critical Latency) | Ultra-short bursts (Input)     |
| 100          | < 500µs     | **Tier 1** (Realtime)         | Very short, consistent (Audio) |
| 90-99        | Any         | **Tier 2** (Critical)         | Short bursts (Compositor)      |
| 70-89        | Any         | **Tier 3** (Gaming)           | Bursty, interactive (Games)    |
| 50-69        | Any         | **Tier 4** (Interactive)      | Normal behavior (Browsers)     |
| 30-49        | Any         | **Tier 5** (Batch)            | Longer runs (Compilers)        |
| 0-29         | Any         | **Tier 6** (Background)       | Continuous CPU usage           |

### Sparse Score Calculation

The sparse score measures how "bursty" a task is:

```c
/* Higher is better (more sparse = shorter waits = more responsive) */
sparse_score = 100 - (avg_runtime / sparse_threshold);
```

| CLI Option               | Default | Effect                                             |
| :----------------------- | :------ | :------------------------------------------------- |
| `--sparse-threshold 125` | 125     | Gaming-optimized (shorter tasks score higher)      |
| `--sparse-threshold 50`  | --      | Aggressive (only very short tasks get high scores) |
| `--sparse-threshold 250` | --      | Relaxed (longer tasks still get decent scores)     |

**Example with `--sparse-threshold 50`**:

- Task with 25µs avg runtime → Score = 100 - (25/50) = 99.5 → **Tier 2**
- Task with 100µs avg runtime → Score = 100 - (100/50) = 98 → **Tier 2**
- Task with 500µs avg runtime → Score = 100 - (500/50) = 90 → **Tier 2**
- Task with 1ms avg runtime → Score = 100 - (1000/50) = 80 → **Tier 3**

### Demotion Behavior

Tasks that misbehave get demoted to prevent starvation of other tasks:

| Condition                          | Action                  | Purpose                      |
| :--------------------------------- | :---------------------- | :--------------------------- |
| Runtime > Starvation Limit         | Force preemption        | Safety net for runaway tasks |
| Wait time > Wait Budget (repeated) | Demote to next tier     | Prevent queue bloat          |
| nice value > 0                     | Start at Batch tier     | Respect user priority hints  |
| nice value < 0                     | Cap at Interactive tier | Prevent abuse                |

#### Per-Tier Demotion Targets

| Current Tier           | Demotes To        | When                                   |
| :--------------------- | :---------------- | :------------------------------------- |
| **0** Critical Latency | **1** Realtime    | Runtime > 5ms or wait budget exceeded  |
| **1** Realtime         | **2** Critical    | Runtime > 3ms or wait budget exceeded  |
| **2** Critical         | **3** Gaming      | Runtime > 4ms or wait budget exceeded  |
| **3** Gaming           | **4** Interactive | Runtime > 8ms or wait budget exceeded  |
| **4** Interactive      | **5** Batch       | Runtime > 16ms or wait budget exceeded |
| **5** Batch            | **6** Background  | Runtime > 40ms or wait budget exceeded |
| **6** Background       | (none)            | Cannot demote further                  |

### Preemption Matrix

### Preemption Policy

`scx_cake` deliberately restricts preemption to ensure frame consistency for gaming workloads.

**Preemption Logic:**

1.  **Only Tier 0 (Critical Latency) can preempt.** This ensures mouse/keyboard input is processed immediately.
2.  **Only Tiers 4, 5, 6 can be preempted.** Interactive, Batch, and Background tasks yield to input.
3.  **Tiers 1, 2, 3 are Protected.** Realtime, Critical, and Gaming tasks are **never** preempted by `scx_cake`. They run until they sleep or exhaust their quantum.

| Triggering Tier          | Preempts Victim Tiers | Mechanism                              |
| :----------------------- | :-------------------- | :------------------------------------- |
| **0** (Critical Latency) | **4, 5, 6**           | Active `kick_cpu` (Instant Preemption) |
| **1 - 6**                | None                  | Wait for natural timeslice expire      |

**Impact**: Input (Tier 0) can preempt a Browser (Tier 4) instantly, but will **wait** for the Game Loop (Tier 3) to yield naturally. This prevents input processing from tearing game frames.

### Comparison: scx_cake vs. EEVDF

`scx_cake` fundamentally differs from the kernel's default EEVDF (Earliest Eligible Virtual Deadline First) scheduler.

| Feature                      | EEVDF (Kernel Default)           | scx_cake                                   |
| :--------------------------- | :------------------------------- | :----------------------------------------- |
| **Primary Goal**             | Fairness & Throughput            | **Latency & Responsiveness**               |
| **Scheduling Metric**        | Virtual Deadline (Lag)           | **Behavioral Tier** (Sparse Score)         |
| **Timeslice**                | Dynamic (Proportional)           | **Fixed Quantum** (Tier-Scaled)            |
| **Preemption**               | When Lag > Slice                 | **Instant** (Higher Tier Always Wins)      |
| **Classification Mechanism** | Nice Values (Weights)            | **Automatic Classification** + Nice Caps   |
| **Starvation Logic**         | Guaranteed Service (Fair)        | **Force Kill** (Unfair - preemption limit) |
| **Wait Queue**               | Single Red-Black Tree (O(log n)) | **7 Per-Tier FIFOs** (O(1))                |

**Key Differences**:

1.  **Fairness vs. Speed**: EEVDF spends cycles calculating "Virtual Time" to ensure every task gets its fair share. `scx_cake` abandons fairness math entirely; if a Game Thread needs the CPU, it takes it from a Compiler immediately, no calculations asked.
2.  **Lag vs. Tiers**: EEVDF tracks "Lag" (how much a task "deserves" to run). `scx_cake` ignores what a task deserves and only cares about what it _is doing_ (e.g., "Is it bursting?").
3.  **Complexity**: EEVDF uses a Red-Black Tree (expensive to maintain). `scx_cake` uses simple FIFOs (queues) and direct hardware dispatch.

---

## 4. Performance Optimizations

This section documents the key performance concepts that make `scx_cake` fast. Each optimization targets a specific hardware or software bottleneck.

### Understanding CPU Cycles

Every operation in the scheduler costs CPU cycles. On a 5 GHz 9800X3D:

- **1 cycle** = 0.2 nanoseconds
- **100 cycles** = 20 nanoseconds
- Context switches cost **1000+ cycles**

The goal is to minimize cycles in the **hot path** (the code executed on every scheduling decision).

| Operation Type       | Typical Cost | Example               |
| :------------------- | :----------- | :-------------------- |
| Register operation   | 1 cycle      | `a + b`               |
| L1 cache read        | 3-4 cycles   | Reading task context  |
| L2 cache read        | 12-15 cycles | Map lookup miss       |
| L3 cache read        | 30-50 cycles | Cross-core data       |
| TSC read             | 15-25 cycles | `bpf_ktime_get_ns()`  |
| Integer division     | 20-80 cycles | `x / 20`              |
| Branch misprediction | 15-20 cycles | `if/else` wrong path  |
| Atomic operation     | 10-50 cycles | `__sync_fetch_and_or` |

---

### A. Timestamp Caching (`scx_bpf_now()`)

**The Problem**: Reading time is expensive.

`bpf_ktime_get_ns()` reads the hardware TSC (Time Stamp Counter), which requires:

1. A serializing instruction (stops pipeline)
2. Reading a hardware register
3. Cost: ~15-25 cycles per call

**The Solution**: Use `scx_bpf_now()` which reads the cached `rq->clock` that the kernel already maintains.

```c
/* OLD: Hardware TSC read - ~15-25 cycles */
u64 now = bpf_ktime_get_ns();

/* NEW: Cached rq->clock - ~3-5 cycles */
u64 now = scx_bpf_now();
```

**Impact**: ~40-80 cycles saved per task (4 call sites × ~10-20 cycles each).

---

### B. Cache Line Optimization & Wait-Free Design

**The Problem**: False sharing destroys performance on multi-core systems.

**The Solution**: We isolate frequently-updated atomics on separate cache lines and use **Wait-Free** structures where possible.

```c
struct {
    union {
        u8  as_bytes[64];   /* Wait-Free Write */
        u64 as_chunks[8];   /* Fast Scan Read */
    };
} idle_map SEC(".bss") __attribute__((aligned(64)));
```

**Why this works**:

- `as_bytes[cpu] = 1` is a simple store. No `LOCK` prefix. No bus locking.
- `as_chunks[0]` reads 8 bytes at once.
- Alignment ensures no two CPUs contend for the same cache line unless they are neighbors (rare).

### C. Idle Path Streamlining

**The Problem**: Redundant operations on the idle path delay CPU sleep.

**The Solution**: We stripped the idle path (`cake_update_idle`) down to a **single instruction**.

- **Removed**: `victim_mask` updates (moved to `cake_running`)
- **Removed**: Scoreboard updates (deleted feature)
- **Kept**: Single byte write to `idle_map`

**Impact**: The CPU transitions to idle state ~40 cycles faster.

### D. Division-Free Arithmetic (Bitwise Magic)

**The Problem**: Integer division is slow (20-80 cycles).

**The Solution**: Replace division with reciprocal multiplication.

```c
/* Division by 20 for tier bucketing */
/* Math: 3277/65536 ≈ 0.05004 ≈ 1/20 */
u32 bucket = (score * 3277) >> 16;
```

### E. Branchless Programming

**The Problem**: Branch misprediction costs ~15-20 cycles.

**The Solution**: Use signed masks and bitwise logic.

```c
/* XOR-Blend Logic (cake_running) */
u64 selector = -(s64)is_victim;  // 0 or 0xFF...
u64 new_mask = clear_mask ^ (diff & selector);
```

### F. Pre-Computed Values

**The Problem**: Calculating tiers on wake-up adds latency.

**The Solution**: Move all math to `cake_stopping` (the "Cold Path").

- When a task stops, we calculate its _next_ tier based on what it just did.
- When it wakes up, we just load the value.

---

## 5. HPC Patterns & Industry Best Practices

The optimizations in `scx_cake` are informed by high-performance computing research:

### Confirmed Patterns (Already Implemented)

| Pattern                            | Source          | Optimization                                   |
| :--------------------------------- | :-------------- | :--------------------------------------------- |
| **Wait-Free Data Structures**      | LMAX Disruptor  | Dual-View `idle_map` (Byte Write / Chunk Read) |
| **Memory Level Parallelism (MLP)** | Modern CPU Arch | "Cluster Bomb" parallel loads in `select_cpu`  |
| **Fused Load-Compute-Store**       | Kernel Design   | Single-burst updates in `cake_stopping`        |
| **No Dynamic Allocation**          | NASA JPL        | Pre-allocated maps (zero `malloc` in hot path) |
| **Division-Free Math**             | Algorithmica    | `x * magic >> shift` replacement               |
| **Cache Line Padding**             | LMAX Disruptor  | 64-byte alignment for global masks             |
| **Branchless Logic**               | HPC Research    | Signed-mask conditionals                       |

### Key References

- **Algorithmica "Algorithms for Modern Hardware"**: Cache lines, branchless programming.
- **LMAX Disruptor**: Mechanical Sympathy, Lock-free queues.
- **NASA JPL "Power of 10"**: Deterministic C execution.

---

## 6. Experimental Findings

> [!WARNING] > **Performance Disclaimer**: The results below are from a specific test system (AMD Ryzen 7 9800X3D). Your results may vary based on CPU architecture (Intel vs. AMD), core count, and Game/OS version.

### A. Performance Wins ✅

| Optimization                 | Status     | Impact (Speculative)                       | Date     |
| :--------------------------- | :--------- | :----------------------------------------- | :------- |
| **Wait-Free Dual-View Map**  | **Active** | Replaced atomic bitset with byte-store     | Dec 2025 |
| **MLP "Cluster Bomb"**       | **Active** | Parallelized memory loads (Latency Hiding) | Jan 2026 |
| **Direct Dispatch (+Last)**  | **Active** | Skips kernel re-queueing (SCX_ENQ_LAST)    | Initial  |
| **Fused Load-Compute-Store** | **Active** | Reduced register pressure in `stopping`    | Jan 2026 |
| **Pre-computed Tier Math**   | **Active** | Moved math to cold path                    | Initial  |

### B. Performance Regressions & Lessons Learned ⚠️

| Experiment               | Result                    | Resolution                              |
| :----------------------- | :------------------------ | :-------------------------------------- |
| **1ms Starvation Limit** | **Stutter (1% Low drop)** | Reverted to 5ms (Tier 0 default)        |
| **Single DSQ**           | **Contention**            | Split into 7 per-tier queues            |
| **Atomic Bitmask (Old)** | **False Sharing**         | Replaced with Wait-Free Byte Map        |
| **Vtime Fairness**       | **Latency Spike**         | Removed entirely (Anti-Fairness design) |

### C. The "1% Low" Regression (Case Study)

- **Experiment**: Tightened Critical Latency starvation limit to 1ms
- **Result**: 1% Low FPS dropped from 180 → 120
- **Analysis**: Legitimate heavy input frames occasionally take >1ms (e.g. initial mouse movement).
- **Correction**: Relaxed to 5ms, restored performance.
- **Lesson**: **Over-optimization kills stability.** Input handling needs breathing room.

### E. Performance Baseline (9800X3D)

| Metric                     | scx_cake                 |
| :------------------------- | :----------------------- |
| Scheduler Overhead         | **~0.15% (Negligible)**  |
| Dispatch Latency           | **~10-40 cycles (Est.)** |
| 1% Low FPS (Arc Raiders)\* | **~233 FPS**             |

_\*Benchmark run on CachyOS 6.18, RTX 4090, 4K High Settings. See Disclaimer._

### F. Benchmarking

#### Test Methodology

- **Tool**: [MangoHud](https://github.com/flightlessmango/MangoHud)
- **Scenario**: Controlled firing range movement (30s loop)

#### Results History

| Date     | Build               | 1% Low FPS  | Notes             |
| :------- | :------------------ | :---------- | :---------------- |
| Jan 2026 | **Wait-Free + MLP** | **233 FPS** | Best Result       |
| Dec 2025 | Cache Line Padding  | ~210 FPS    | Stable            |
| Dec 2025 | 1ms Regression      | 120 FPS     | Failed Experiment |

---

## 7. Usage

### Quick Start

```bash
git clone https://github.com/RitzDaCat/scx_cake.git
cd scx_cake
./build.sh
sudo ./start.sh
```

### Monitoring (Verbose Mode)

```bash
sudo ./start.sh -v
```

In verbose mode, watch for:

- **Max Wait**: Should be <2ms for Gaming tier
- **StarvPreempt**: If high, system is actively suppressing heavy tasks
- **DirectDispatch%**: Should be >90%

### CLI Options

| Option               | Default        | Description                                |
| :------------------- | :------------- | :----------------------------------------- |
| `--quantum`          | 2000 (2ms)     | Base timeslice in microseconds             |
| `--new-flow-bonus`   | 8000 (8ms)     | Bonus slice for newly woken tasks          |
| `--sparse-threshold` | 50             | Threshold for sparse score calculation (‰) |
| `--starvation`       | 100000 (100ms) | Global starvation limit in microseconds    |
| `--verbose` / `-v`   | off            | Enable TUI monitoring                      |
| `--interval`         | 1000           | Stats update interval in milliseconds      |

### Recommended Testing Command

```bash
sudo ./start.sh --quantum 2000 --sparse-threshold 50
```

**Output when started:**

```
scx_cake scheduler started
  Quantum:          2000 µs
  New flow bonus:   8000 µs
  Sparse threshold: 50‰
  Starvation limit: 100000 µs
```

---

## 8. License & Acknowledgments

**License**: GPL-2.0

**Inspiration**:

- [CAKE (Common Applications Kept Enhanced)](https://www.bufferbloat.net/projects/codel/wiki/Cake/) - Queue management philosophy
- [sched_ext](https://github.com/sched-ext/scx) - BPF scheduler framework
- [Algorithmica HPC Book](https://en.algorithmica.org/hpc/) - Performance optimization patterns

**Test Hardware**: AMD Ryzen 7 9800X3D, 96GB DDR5, NVIDIA RTX 4090, CachyOS 6.18
