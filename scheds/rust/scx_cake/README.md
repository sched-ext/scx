# scx_cake: Low-Latency Gaming Scheduler for User Inputs & 1% Lows

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: 6.12+](https://img.shields.io/badge/Kernel-6.12%2B-green.svg?style=flat-square)](https://kernel.org)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg?style=flat-square)]()
[![AI Usage: Verified](https://img.shields.io/badge/AI%20Usage-Verified-purple.svg?style=flat-square)]()

> **ABSTRACT**: `scx_cake` is an experimental BPF CPU scheduler designed for **gaming workloads**.
>
> - **7-Tier Priority System** — Classifies tasks by behavior, not nice values
> - **Sparse Score** — Tracks task "burstiness" (0-100) to identify latency-sensitive work
> - **ETD (Empirical Topology Discovery)** — Measures real inter-core latency at startup for surgical CPU selection
> - **Latency Over Fairness** — Ultra-fast tasks (<50µs) preempt instantly for low input lag; lower DSQs get larger timeslices to support strong 1% lows

---

> [!WARNING]
> **EXPERIMENTAL SOFTWARE**
> This scheduler is experimental and intended for use with `sched_ext` on Linux Kernel 6.12+. Performance may vary depending on hardware and user configuration.

> [!NOTE]
> **AI TRANSPARENCY**
> Large Language Models were used for theorycrafting and optimization pattern matching. All implementation details and logical structures have been human-verified and benchmarked for correctness.

---

## Navigation

- [1. Quick Start](#1-quick-start)
- [2. The scx_cake Philosophy](#2-the-scx_cake-philosophy)
- [3. The 7-Tier System](#3-the-7-tier-system)
- [4. Technical Architecture](#4-technical-architecture)
- [5. Configuration (CLI)](#5-configuration-cli)
- [6. Expected Performance](#6-expected-performance)
- [Appendix: Vocabulary](#appendix-vocabulary)

---

## 1. Quick Start

```bash
# Prerequisites: Linux Kernel 6.12+ with sched_ext, Rust toolchain

# Clone and build
git clone https://github.com/sched-ext/scx.git
cd scx && cargo build --release -p scx_cake

# Run (requires root)
sudo ./target/release/scx_cake
```

**Modes:**

- **Default**: Runs silently
- **Verbose (`-v`)**: Launches TUI showing real-time stats

---

## 2. The scx_cake Philosophy

Modern schedulers (like EEVDF or CFS) are designed for **Fairness** and **Throughput**. They ensure that if you run a game and a compiler simultaneously, both receive an equal 50% share of CPU time.

**For gaming, this is fundamentally wrong.**

---

## 3. The 7-Tier System

`scx_cake` does not use "Nice" values to determining priority. Instead, it observes **behavior**.

### Dynamic Classification

`scx_cake` classifies tasks by observing their runtime behavior and assigning a **Sparse Score** (0-100).

1.  **Score Calculation**:
    - **Growth (+4)**: If a task yields quickly (run time < sparse threshold), its score increases.
    - **Decay (-6)**: If a task runs long (run time > sparse threshold), its score decreases.

2.  **The "Float" Effect**:
    - **Inputs (Tier 0)**: Mouse/Keyboard threads run for very short bursts (<50µs). Their score pins at **100**. Because they possess both a perfect score AND extremely low average runtime, they pass the **Latency Gate** into Tier 0.
    - **Games (Tier 3)**: Game loops run longer (e.g., 2ms) to render frames. Their score "floats" down and stabilizes in the **Gaming Tier**. This gives them a **larger timeslice** (2.0ms vs 1.4ms) to perform heavy work while still being protected from background noise.
    - **Background (Tier 6)**: Compilers run continuously. Their score drops to **0**. They receive the **largest timeslice** (2.6ms) for raw throughput but are strictly preemptible.

### Tier Classification Table

| Tier  | Name                 | Typical Workload               | Preemption Rights                   |
| :---- | :------------------- | :----------------------------- | :---------------------------------- |
| **0** | **Critical Latency** | Mouse driver, Keyboard input   | **Can Preempt Tiers 4-6 Instantly** |
| **1** | **Realtime**         | PipeWire, Audio threads        | Protected (Cannot be preempted)     |
| **2** | **Critical**         | Compositors (Wayland/X11)      | Protected                           |
| **3** | **Gaming**           | Main game loop, Render thread  | Protected                           |
| **4** | **Interactive**      | Web Browsers, Discord, Editors | Preemptible by T0                   |
| **5** | **Batch**            | Compilers (cargo, gcc)         | Preemptible by T0                   |
| **6** | **Background**       | Encoders, indexing services    | Preemptible by T0                   |

### Tier Mechanics (Gaming Profile Defaults)

Each tier has different rules for how long it can run (`Quantum`) and when it gets forcibly stopped (`Starvation`).

_Calculated with Base Quantum = 2000µs (2ms)_

| Tier  | Quantum Multiplier | Effective Slice | Starvation Limit | Wait Budget |
| :---- | :----------------: | :-------------: | :--------------: | :---------: |
| **0** |        0.7x        |    **1.4ms**    |       5ms        |    100µs    |
| **1** |        0.8x        |    **1.6ms**    |       3ms        |    750µs    |
| **2** |        0.9x        |    **1.8ms**    |       4ms        |     2ms     |
| **3** |        1.0x        |    **2.0ms**    |       8ms        |     4ms     |
| **4** |        1.1x        |    **2.2ms**    |       16ms       |     8ms     |
| **5** |        1.2x        |    **2.4ms**    |       40ms       |    20ms     |
| **6** |        1.3x        |    **2.6ms**    |      100ms       |    None     |

> **Note**: Higher tiers (0-2) get _smaller_ slices to ensure they yield the CPU frequently, keeping the system responsive. Lower tiers get _larger_ slices to improve cache efficiency and throughput.

---

## 4. Technical Architecture

`scx_cake` is built for speed. The hot path (Wakeup → Select CPU → Dispatch) is optimized to run in as few CPU cycles as possible (~70-120 cycles total).

### Wait-Free Topology Maps

Traditional schedulers use atomic locks or spinlocks to find an idle CPU. `scx_cake` uses a **Wait-Free Dual-View Map**:

- **Writers (Idle CPUs)**: Write a single byte (`u8`) to their slot. No locking required.
- **Readers (Scheduler)**: Read 8 bytes (`u64`) at a time to scan 8 CPUs in a single instruction.
  This allows finding an idle CPU in effectively zero latency without contention.

### Pre-Computed Decision Hints

Expensive math (division, tier calculation) is effectively banned from the hot path.

- Tier logic is calculated when a task **stops** (the cold path).
- The result is stored in the task context.
- When the task wakes up, the scheduler performs a simple integer load to know where it goes.

### Direct Dispatch

If a task is waking up on a CPU that is currently idle, `scx_cake` bypasses the global queue entirely and "Direct Dispatches" the task to that CPU. This skips the overhead of enqueueing, global accounting, and dequeueing.

---

## 5. Configuration (CLI)

`scx_cake` comes with built-in profiles, but every parameter can be fine-tuned via CLI arguments.

### Profiles (`--profile, -p`)

| Profile   | Quantum | Starvation | Description                                          |
| :-------- | :-----: | :--------: | :--------------------------------------------------- |
| `gaming`  |   2ms   |   100ms    | **(Default)** Balanced for most games.               |
| `esports` |   1ms   |    50ms    | Aggressive. Extreme responsiveness, higher overhead. |
| `legacy`  |   4ms   |   200ms    | Relaxed. Better for older CPUs or battery saving.    |
| `default` |   2ms   |   100ms    | Alias for `gaming`.                                  |

### Arguments

| Argument                        | Default       | Description                                   |
| :------------------------------ | :------------ | :-------------------------------------------- |
| `--profile, -p <PROFILE>`       | `gaming`      | Select a preset profile.                      |
| `--quantum <us>`                | profile-based | Base time slice in microseconds.              |
| `--sparse-threshold <permille>` | profile-based | Burst detection sensitivity (0-1000).         |
| `--new-flow-bonus <us>`         | profile-based | Extra time for newly woken tasks.             |
| `--starvation <us>`             | profile-based | Max run time before forced preemption.        |
| `--verbose, -v`                 | `false`       | Enable TUI monitoring interface.              |
| `--interval <secs>`             | `1`           | TUI refresh interval (only with `--verbose`). |

**Example:**

```bash
# Run with Esports profile
sudo scx_cake -p esports

# Gaming profile with custom starvation limit
sudo scx_cake --starvation 60000 -v
```

---

## 6. Expected Performance

Performance varies by hardware and workload. `scx_cake` targets:

- **Better Framerate** — Reduced scheduling overhead allows more CPU time for game logic
- **Improved 1% Lows** — Consistent frame delivery through priority-based dispatch
- **Uninhibited User Inputs** — Mouse/keyboard processing is not blocked by game load

### Tested Hardware & Benchmarks

| Component | Specification              |
| :-------- | :------------------------- |
| CPU       | AMD Ryzen 7 9800X3D        |
| Kernel    | Linux 6.12+ with sched_ext |

**Benchmarks Used:**

- [schbench](https://github.com/brendangregg/schbench) — Scheduler latency microbenchmark
- Arc Raiders — AAA game stress testing
- Splitgate 2 — Competitive FPS latency testing

> [!NOTE]
> Throughput workloads (compilers, render farms) will perform **worse** than CFS/EEVDF. This scheduler prioritizes responsiveness over raw throughput.

---

## Appendix: Vocabulary

Terms used throughout `scx_cake` code and documentation.

### Scheduler & Kernel Terms

| Term                | Definition                                                                                   |
| :------------------ | :------------------------------------------------------------------------------------------- |
| **BPF (eBPF)**      | _Berkeley Packet Filter_. Technology for running custom code safely inside the Linux kernel. |
| **sched_ext (SCX)** | Linux kernel framework (v6.12+) enabling custom BPF schedulers.                              |
| **DSQ**             | _Dispatch Queue_. Queue mechanism `sched_ext` uses to hold tasks waiting for a CPU.          |
| **kfunc**           | _Kernel Function_. Kernel function exposed for BPF programs to call.                         |
| **UEI**             | _User Exit Info_. Mechanism for BPF schedulers to report exit reasons to userspace.          |
| **RoData**          | _Read-Only Data_. Constant configuration in BPF, zero-cost at runtime.                       |
| **Quantum**         | Time slice a task is allotted before a scheduling decision is made.                          |
| **Tier**            | Classification level determining a task's priority and scheduling parameters.                |
| **Preemption**      | Forcibly interrupting a running task to switch to higher-priority work.                      |
| **Context Switch**  | Saving one task's CPU state and loading another's (~1000+ cycles).                           |

### CPU Topology

| Term        | Definition                                                                                        |
| :---------- | :------------------------------------------------------------------------------------------------ |
| **ETD**     | _Empirical Topology Discovery_. Measures real inter-core latency at startup via CAS ping-pong.    |
| **SMT**     | _Simultaneous Multi-Threading_. Two logical CPUs sharing one physical core (AMD: 2 threads/core). |
| **CCD**     | _Core Complex Die_. Physical chiplet containing cores (9800X3D has 1 CCD with 8 cores).           |
| **CCX**     | _Core Complex_. Subset of cores sharing L3 cache within a CCD.                                    |
| **LLC**     | _Last Level Cache_. Typically L3 cache; cores in same LLC communicate faster.                     |
| **Sibling** | The SMT partner of a logical CPU (shares physical core).                                          |

### Algorithms & Concepts

| Term             | Definition                                                                              |
| :--------------- | :-------------------------------------------------------------------------------------- |
| **AQM**          | _Active Queue Management_. Networking technique adapted here via Wait Budgets.          |
| **Bufferbloat**  | High latency caused by large, full queues. `scx_cake` fights this on the CPU side.      |
| **DRR++**        | _Deficit Round Robin++_. Algorithm balancing fair queuing with strict priority.         |
| **EMA**          | _Exponential Moving Average_. Lightweight algorithm to track historical runtime.        |
| **Sparse Score** | 0-100 metric tracking task "burstiness". High score = yields often (latency-sensitive). |

### Data Packing & Fusion

| Term             | Definition                                                                             |
| :--------------- | :------------------------------------------------------------------------------------- |
| **Nibble**       | 4 bits. Half a byte. Used for compact storage (e.g., tier in 3 bits).                  |
| **Fused Config** | Multiple parameters packed into one 64-bit word for single-load access.                |
| **Quad Packing** | Storing 4 values in one register (e.g., prev_cpu, wake_flags, tier, score in 64 bits). |
| **State Fusion** | Combining related fields into a union for atomic 64-bit read/write.                    |
| **Load Fusion**  | Issuing multiple independent loads simultaneously to hide memory latency.              |

### Bitwise & Low-Level Optimization

| Term            | Definition                                                                         |
| :-------------- | :--------------------------------------------------------------------------------- |
| **Bitwise Ops** | Operations on individual bits (AND, OR, XOR, shifts). 1 cycle vs 10+ for division. |
| **Bitmask**     | Integer where each bit represents a boolean (e.g., 64-bit mask for 64 CPUs).       |
| **CTZ**         | _Count Trailing Zeros_. Finds first set bit in O(1). Used for idle CPU scan.       |
| **De Bruijn**   | Mathematical sequence enabling branchless bit-scan without hardware CTZ.           |
| **TTAS**        | _Test-and-Test-and-Set_. Check before atomic to avoid cache line bouncing.         |
| **Branchless**  | Code avoiding `if/else` to prevent CPU pipeline stalls from misprediction.         |

### Performance Architecture

| Term                | Definition                                                                      |
| :------------------ | :------------------------------------------------------------------------------ |
| **Hot Path**        | Code executed on every scheduling decision. Must be optimized.                  |
| **Cold Path**       | Infrequent code (task init, tier recalc). Can be slower.                        |
| **ILP**             | _Instruction Level Parallelism_. CPU executing multiple instructions per cycle. |
| **MLP**             | _Memory Level Parallelism_. Issuing multiple memory loads to hide RAM latency.  |
| **Wait-Free**       | Algorithm where every thread makes progress without locks or spinning.          |
| **Direct Dispatch** | Bypassing global DSQ to assign task directly to a CPU's local queue.            |
| **False Sharing**   | Performance penalty when CPUs fight over the same 64-byte cache line.           |
| **Cache Line**      | 64-byte block of memory. Smallest unit CPU loads from RAM.                      |

### Gaming & Performance Metrics

| Term                 | Definition                                                                         |
| :------------------- | :--------------------------------------------------------------------------------- |
| **Input Latency**    | Time from physical input (mouse click) to frame updating on screen.                |
| **1% Lows**          | Average framerate of slowest 1% of frames. Key metric for measuring stutter.       |
| **Frametime**        | Time to render one frame (16.6ms = 60 FPS). Consistency matters more than average. |
| **Throughput**       | Raw work done over time. Opposite of latency optimization.                         |
| **Wait Budget**      | Max time a task waits in queue before intervention.                                |
| **Starvation Limit** | Hard runtime ceiling. Tasks exceeding this are forcibly preempted.                 |

---

**License**: GPL-2.0  
**Maintainer**: RitzDaCat
