# scx_cake: Low-Latency Gaming Scheduler

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: 6.16+](https://img.shields.io/badge/Kernel-6.16%2B-green.svg?style=flat-square)](https://kernel.org)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg?style=flat-square)]()
[![AI Usage: Verified](https://img.shields.io/badge/AI%20Usage-Verified-purple.svg?style=flat-square)]()

> **ABSTRACT**: `scx_cake` is an experimental BPF CPU scheduler explicitly designed for **gaming workloads**. It prioritizes low-latency tasks—such as user inputs and game render loops—over background throughput. By utilizing a 7-tier classification system and abandoning traditional "fairness" for strict latency prioritization, it aims to eliminate stutter and maximize responsiveness.

---

> [!WARNING] > **EXPERIMENTAL SOFTWARE**
> This scheduler is experimental and intended for use with `sched_ext` on Linux Kernel 6.16+. Usage may result in system instability.

> [!NOTE] > **AI TRANSPARENCY**
> Large Language Models were used for theorycrafting and optimization pattern matching. All implementation details and logical structures have been human-verified and benchmarked for correctness.

---

## Navigation

- [1. Vocabulary (Terminology)](#1-vocabulary-terminology)
- [2. The scx_cake Philosophy](#2-the-scx_cake-philosophy)
- [3. The 7-Tier System](#3-the-7-tier-system)
- [4. Technical Architecture](#4-technical-architecture)
- [5. Installation & Usage](#5-installation--usage)
- [6. Configuration (CLI)](#6-configuration-cli)
- [7. Expected Performance](#7-expected-performance)

---

## 1. Vocabulary (Terminology)

Understanding `scx_cake` requires familiarity with these specific terms appearing in our code and documentation.

### Scheduler & Kernel Terms

| Term                | Definition                                                                                                            |
| :------------------ | :-------------------------------------------------------------------------------------------------------------------- |
| **BPF (eBPF)**      | _Berkeley Packet Filter_. A technology allowing us to run this custom scheduler inside the Linux Kernel safely.       |
| **DSQ**             | _Dispatch Queue_. The internal queue mechanism `sched_ext` uses to hold tasks waiting for a CPU.                      |
| **kfunc**           | _Kernel Function_. A specific function inside the Linux kernel exposed for BPF programs to call (e.g., to read time). |
| **sched_ext (SCX)** | The Linux Kernel framework (v6.12+) that enables custom BPF schedulers like `scx_cake`.                               |
| **UEI**             | _User Exit Info_. Standard mechanism for BPF schedulers to report exit reasons to userspace.                          |
| **RoData**          | _Read-Only Data_. Cached configuration memory in BPF that avoids expensive variable reads.                            |
| **Quantum**         | The time slice a task is allotted to run on the CPU before a scheduling decision is made.                             |
| **Tier**            | A classification level assigned to a task that determines its priority and scheduling parameters.                     |
| **Preemption**      | The act of forcibly interrupting a running task to switch to a higher-priority task immediately.                      |
| **Context Switch**  | The expensive process of saving one task's CPU state and loading another's (~1000+ cycles).                           |

### Algorithms & Concepts

| Term            | Definition                                                                                                  |
| :-------------- | :---------------------------------------------------------------------------------------------------------- |
| **AQM**         | _Active Queue Management_. Networking technique (preventing bufferbloat) adapted here via Wait Budgets.     |
| **Bufferbloat** | High latency caused by large, full queues. `scx_cake` fights this on the CPU.                               |
| **DRR++**       | _Deficit Round Robin++_. The scheduling algorithm CAKE uses to balance fair queuing with strict priority.   |
| **EMA**         | _Exponential Moving Average_. A lightweight algorithm used to track historical runtime with minimal memory. |

### Optimization & Architecture

| Term                         | Definition                                                                                                      |
| :--------------------------- | :-------------------------------------------------------------------------------------------------------------- |
| **Hot Path**                 | The critical code path executed on _every_ scheduling decision (Wakeup → Select → Dispatch). Must be optimized. |
| **ILP**                      | _Instruction Level Parallelism_. Optimizing code so the CPU executes multiple instructions per clock cycle.     |
| **MLP**                      | _Memory Level Parallelism_. Structuring code to issue multiple memory loads simultaneously to hide RAM latency. |
| **Cluster Bomb**             | _Local Term_. Strategy of issuing all independent memory loads immediately at function entry to maximize MLP.   |
| **Fused Load-Compute-Store** | Grouping all reads, then all math, then all writes into distinct phases to hide latency (Pipeling).             |
| **Wait-Free**                | An algorithm guarantees that every thread makes progress in a finite number of steps (no locks, no spinning).   |
| **Store Buffer**             | Hardware component that holds pending writes, allowing "Wait-Free" visibility without locking.                  |
| **Direct Dispatch**          | Bypassing the global DSQ to assign a task directly to a specific CPU's local queue (fastest path).              |
| **False Sharing**            | Performance penalty when different CPUs fight over the same 64-byte "Cache Line" of memory.                     |
| **Branchless**               | Coding style that avoids `if/else` checks to prevent CPU pipeline stalls (mispredictions).                      |
| **Superscalar**              | CPU architecture capability to execute more than one instruction per clock cycle.                               |
| **Tree Reduction**           | Parallelizing logical operations (like bitwise OR) to reduce dependency chain depth.                            |
| **CTZ**                      | _Count Trailing Zeros_. CPU instruction to find the first set bit in a mask efficiently (O(1)).                 |

### Gaming & Performance Metrics

| Term                 | Definition                                                                                            |
| :------------------- | :---------------------------------------------------------------------------------------------------- |
| **Input Latency**    | The time delay between a physical input (mouse click) and the frame updating on screen.               |
| **1% Lows**          | The average framerate of the slowest 1% of frames. A key metric for measuring "stutter".              |
| **Frametime**        | The time it takes to render a single frame (e.g., 16.6ms for 60 FPS). Consistency is key.             |
| **Sparse Score**     | A 0-100 metric tracking how "bursty" a task is. High score = yields often (good for latency).         |
| **Throughput**       | The total amount of raw work done over time (e.g., compiling code). Opposite of latency optimization. |
| **Wait Budget**      | The max time a task waits in queue before `scx_cake` intervenes to prevent starvation.                |
| **Starvation Limit** | The hard runtime wall. If a task runs longer than this without yielding, it is killed (preempted).    |

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

## 5. Installation & Usage

### Prerequisites

- Linux Kernel **6.16+** (with `CONFIG_SCHED_CLASS_EXT` enabled/module loaded).
- Recent Rust toolchain (`cargo`).

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/RitzDaCat/scx_cake.git
cd scx_cake

# 2. Build the scheduler
cargo build --release

# 3. Run the scheduler (requires root/sudo)
sudo ./target/release/scx_cake
```

### Modes

- **Default**: Runs silently.
- **Verbose (`-v`)**: Launches a terminal UI (TUI) showing real-time stats, per-tier dispatch counts, and wait times.

---

## 6. Configuration (CLI)

`scx_cake` comes with built-in profiles, but every parameter can be fine-tuned via CLI arguments.

### Profiles (`--profile`)

| Profile   | Description                                                          |
| :-------- | :------------------------------------------------------------------- |
| `gaming`  | **(Default)** Balanced 2ms quantum. Good for most games.             |
| `esports` | Aggressive 1ms quantum. Extreme responsiveness, higher CPU overhead. |
| `legacy`  | Relaxed 4ms quantum. Better for older CPUs or battery saving.        |

### Arguments

| Argument                        | Default  | Description                                        |
| :------------------------------ | :------- | :------------------------------------------------- |
| `--quantum <us>`                | `2000`   | The base time slice in microseconds.               |
| `--sparse-threshold <permille>` | `50`     | Sensitivty of "burst" detection (0-1000). 50 = 5%. |
| `--new-flow-bonus <us>`         | `8000`   | Extra time given to new tasks to start up.         |
| `--starvation <us>`             | `100000` | Global starvation limit (100ms).                   |
| `--verbose`                     | `false`  | Enable the TUI monitoring interface.               |

**Example:**

```bash
# Run with Esports settings but a custom starvation limit
sudo ./target/release/scx_cake --profile esports --starvation 60000
```

---

## 7. Expected Performance

While performance varies by hardware, `scx_cake` generally targets:

- **Reduced Stutter**: Improved 1% and 0.1% low FPS.
- **Input Latency**: Reduced mouse/keyboard processing delay.
- **Throughput**: **Lower** than CFS/EEVDF. Do not use this scheduler for compiling kernels or render farms; it is designed for _responsiveness_, not maximum throughput.

> **Hardware Verified On**: AMD Ryzen 7 9800X3D.

---

**License**: GPL-2.0  
**Maintainer**: RitzDaCat
