# Simulator Framework for sched_ext Schedulers

## Status: Phase 1 Complete

| Phase | Target Scheduler | Status | Tests |
|-------|-----------------|--------|-------|
| Phase 1 | scx_simple | **Done** | 10/10 pass |
| Phase 2 | scx_central, scx_qmap | Planned | - |
| Phase 3 | scx_lavd | Planned | - |

---

## Context

sched_ext schedulers are BPF programs that replace the Linux scheduler. Testing them currently requires running on a live kernel, which introduces measurement noise, Heisenberg effects, and interference from other workloads. The **scx_simulator** crate provides a **deterministic discrete-event simulator** that compiles scheduler BPF C code as regular userspace C and drives it through scheduling cycles with scripted fake tasks.

**Prior art in this repo**: PR #2281 (merged) added a unit-test framework at `lib/scxtest/` that compiles BPF code as userspace C with stubbed kfuncs. It tests individual static functions, not full scheduling cycles. The simulator builds on its compilation infrastructure but adds a full simulation engine.

---

## Related Work

A survey of the Rust ecosystem for CPU state modeling found no direct precedent for OS-scheduler-level CPU simulation. Existing work falls into distinct categories that informed our design choices.

### Instruction-Level CPU Emulators

**[riscv_emu_rust](https://docs.rs/riscv_emu_rust/latest/x86_64-apple-darwin/src/riscv_emu_rust/cpu.rs.html)** models full processor state (32 integer registers, 32 FP registers, 4096 CSRs, privilege modes, MMU) with a `tick()` fetch-decode-execute loop over 116 instructions. Its `Cpu` struct carries a `wfi: bool` (Wait For Interrupt) field as the closest analog to an idle state. **[pveentjer/Rust-based-ARM-emulator](https://github.com/pveentjer/Rust-based-ARM-emulator)** goes further with pipelined, superscalar, and out-of-order execution using Tomasulo's algorithm. Both operate at a much lower abstraction level than scheduler simulation -- they model individual instructions rather than scheduling decisions.

**Takeaway**: We don't need register-level or pipeline-level modeling. Our `SimCpu` only tracks `current_task` and `local_dsq`, which is the right abstraction for scheduling behavior.

### Hypervisor vCPU Models (rust-vmm / Firecracker)

The **[rust-vmm](https://github.com/rust-vmm/vmm-reference)** ecosystem (Firecracker, crosvm, Cloud Hypervisor) models vCPU state for KVM interaction. A [CPU model crate was proposed](https://lists.opendev.org/archives/list/rust-vmm@lists.opendev.org/thread/5TQ7B5ZCGVM62XSJKUYO32VZY5HVUQNY/?sort=date) on the rust-vmm mailing list for managing CPUID leaves, MSRs, and XSAVE areas -- focused on CPU feature enumeration for live migration, not scheduling state machines. **[Firecracker](https://github.com/firecracker-microvm/firecracker)** uses a `StateMachine` trait for vCPU lifecycle (created/running/paused/destroyed), a similar granularity to our work but tightly coupled to KVM.

**Takeaway**: Hypervisor vCPU lifecycle is structurally similar to our `TaskState` enum, but their concerns (KVM ioctl orchestration, CPUID filtering, migration) are entirely different from scheduling simulation.

### Register Abstraction Crates

**[aarch64-cpu](https://docs.rs/aarch64-cpu/latest/aarch64_cpu/)** provides type-safe wrappers around AArch64 system registers using the `tock-registers` crate, with `Readable`/`Writeable` traits and a field composition API (`CNTHCTL_EL2.write(CNTHCTL_EL2::EL1PCEN::SET + ...)`). Designed for bare-metal ARM code, not simulation.

**Takeaway**: The register-field abstraction pattern could be useful in Phase 3 if we need to simulate cpuperf or power state registers, but is not needed now.

### Typestate Pattern for State Machines

The **[Typestate Pattern](https://cliffle.com/blog/rust-typestate/)** encodes state into the type system, so invalid transitions are compile-time errors:

```rust
struct Cpu<S: CpuState> { inner: CpuInner, _state: PhantomData<S> }
struct Idle;
struct Running;
impl Cpu<Idle>    { fn dispatch(self, task: Task) -> Cpu<Running> { ... } }
impl Cpu<Running> { fn preempt(self) -> Cpu<Idle> { ... } }
```

This is documented in the [Embedded Rust Book](https://doc.rust-lang.org/beta/embedded-book/static-guarantees/state-machines.html) for GPIO peripherals. The tradeoff is that typestate prevents heterogeneous collections -- you can't have `Vec<Cpu<_>>` with CPUs in different states, which is a requirement for our simulator.

**Takeaway**: We use a runtime `enum TaskState` and `Option<i32>` for CPU occupancy instead. The typestate pattern is too rigid for a simulation where N CPUs must coexist in different states within a single container.

### Discrete Event Simulation Frameworks

**[desru](https://docs.rs/desru/latest/desru/)** is a minimal Rust DES framework with `Event` and `EventScheduler` types backed by a priority queue. It explicitly states it "will not provide implementations of simulation tools" -- just the core event loop. The **[Shadow network simulator](https://shadow.github.io/docs/rust/scheduler/index.html)** uses a `scheduler` crate for parallel host simulation in its DES, but this is thread pool infrastructure, not process scheduling.

**[Type-Safe Discrete Simulation in Rust](https://dev.to/elshize/type-safe-discrete-simulation-in-rust-3n7d)** describes using phantom types and `Any`-based type erasure for component event systems, but doesn't address OS scheduling specifically.

**Takeaway**: No existing DES crate provides OS scheduling primitives. We implemented our own event loop with `BinaryHeap<Reverse<Event>>` and domain-specific event types (`TaskWake`, `SliceExpired`, `TaskPhaseComplete`), which is straightforward and avoids unnecessary abstraction.

### OS Scheduler Simulators

The GitHub topic [cpu-simulation](https://github.com/topics/cpu-simulation) lists only one Rust project (a RISC-V cycle-accurate simulator). Most OS scheduler simulators are academic C/C++/Python projects implementing textbook algorithms (FCFS, RR, SJF). None target real kernel scheduler code compiled for userspace execution.

**Takeaway**: Our approach of compiling actual BPF scheduler code as userspace C and driving it through a simulation engine is novel -- no existing tool does this. The closest analog is the `lib/scxtest/` unit-test framework already in this repo, which we extend from function-level testing to full scheduling-cycle simulation.

---

## Architecture Overview

```
+------------------------------------------------------+
|                Rust Simulator Engine                  |
|                                                      |
|  +----------+ +----------+ +----------+ +--------+  |
|  | Event    | | CPU      | | Task     | | Trace  |  |
|  | Queue    | | State    | | State    | | Log    |  |
|  +----------+ +----------+ +----------+ +--------+  |
|  +----------+ +----------+ +----------------------+  |
|  | DSQ      | | Idle CPU | | BPF Map Backing      |  |
|  | Manager  | | Tracker  | | Storage              |  |
|  +----------+ +----------+ +----------------------+  |
|                                                      |
|  +--------------------------------------------------+|
|  |     Kfunc Implementations (#[no_mangle])         ||
|  |  scx_bpf_dsq_insert, scx_bpf_select_cpu_dfl,    ||
|  |  scx_bpf_dsq_move_to_local, bpf_map_lookup_elem ||
|  +------------------------+-------------------------+|
|                           | C calls kfuncs            |
|  +------------------------v-------------------------+|
|  |     Scheduler Ops (extern "C" from C code)       ||
|  |  simple_select_cpu, simple_enqueue, ...           ||
|  +------------------------+-------------------------+|
|                           | Compiled together         |
|  +------------------------v-------------------------+|
|  |     Scheduler C Code (scx_simple.bpf.c)          ||
|  |     compiled as userspace C via wrapper           ||
|  +--------------------------------------------------+|
+------------------------------------------------------+
```

**Two FFI boundaries**:
- **Rust -> C**: Simulator calls scheduler ops (select_cpu, enqueue, dispatch, etc.)
- **C -> Rust**: Scheduler calls kfuncs (scx_bpf_dsq_insert, etc.) which are `#[no_mangle] extern "C"` Rust functions accessing simulator state via thread-local

**Determinism guarantees**:
- No real time: all time is simulated via a logical clock
- No real concurrency: events processed sequentially (single-threaded)
- No real randomness: `bpf_get_prandom_u32()` uses a deterministic xorshift32 PRNG
- No real CPUs: simulated CPU state machines

---

## Phase 1: scx_simple Simulator [DONE]

### Files Created

```
rust/scx_simulator/
├── Cargo.toml
├── build.rs                         # Compiles scheduler C code via cc crate
├── csrc/
│   ├── sim_wrapper.h                # Overrides BPF_STRUCT_OPS, SCX_OPS_DEFINE,
│   │                                # undoes CO-RE enum macros + compat macros
│   ├── sim_task.h                   # task_struct accessor declarations
│   ├── sim_task.c                   # task_struct alloc/free + field get/set
│   └── simple_wrapper.c             # #includes scx_simple.bpf.c via sim_wrapper.h
├── src/
│   ├── lib.rs                       # Public API, re-exports
│   ├── engine.rs                    # Event-driven simulation loop
│   ├── cpu.rs                       # SimCpu state
│   ├── task.rs                      # SimTask, TaskBehavior, Phase
│   ├── dsq.rs                       # Dispatch queue implementation
│   ├── kfuncs.rs                    # All kfunc implementations + thread-local state
│   ├── trace.rs                     # Trace event recording
│   ├── scenario.rs                  # Scenario builder API
│   └── ffi.rs                       # extern "C" declarations for scheduler ops + task accessors
└── tests/
    ├── simple_basic.rs              # 4 tests: single task, multi task, multi CPU, determinism
    ├── simple_fairness.rs           # 3 tests: equal weight, 2:1 weight, 3-way weight
    └── simple_preemption.rs         # 3 tests: slice preemption, interleaving, sleep/wake
```

Workspace root `Cargo.toml` modified to add `rust/scx_simulator` member.

### Build System (`build.rs`)

Uses `cc` crate to compile:
1. `lib/scxtest/` C files (overrides.c, scx_test_map.c, scx_test_cpumask.c) - reused from existing unit test framework
2. `csrc/sim_task.c` - task_struct accessor functions
3. `csrc/simple_wrapper.c` - the scheduler itself

Include paths (same as `rust/scx_bpf_unittests/build.rs` plus our `csrc/`):
```
lib/scxtest/
scheds/include/
scheds/include/lib
scheds/vmlinux/
scheds/vmlinux/arch/x86/
scheds/include/bpf-compat/
libbpf-sys headers
csrc/
```

Compiler flags: `-DSCX_BPF_UNITTEST` (reuse existing guards)

### C Wrapper Approach

`csrc/sim_wrapper.h` includes `common.bpf.h` to set the header guard, then undoes two layers of BPF-specific macro indirection:

1. **CO-RE enum macros** from `enums.autogen.bpf.h` -- all ~30 `#define SCX_* __SCX_*` macros that redirect enum constants to weak variables (which default to 0 in userspace)
2. **Compat wrapper macros** from `compat.bpf.h` -- macros like `scx_bpf_dsq_insert` that wrap kfunc calls with `bpf_ksym_exists()` ternary fallbacks
3. **BPF_STRUCT_OPS** -- redefined to produce plain C functions with `__attribute__((used))`
4. **SCX_OPS_DEFINE** -- redefined to nothing (no struct_ops registration in simulator)

`csrc/simple_wrapper.c` includes `sim_wrapper.h` then `scx_simple.bpf.c`. Because `common.bpf.h`'s header guard is already set, the scheduler's re-include is skipped, and all our overridden macros take effect.

### task_struct Management

Since we use the real vmlinux.h, `struct task_struct` is the full kernel struct (thousands of bytes). Managed via C accessor functions in `csrc/sim_task.c` that provide field-level get/set operations callable from Rust FFI.

Note: `sim_task.c` cannot include `<stdlib.h>` or `<string.h>` because they conflict with vmlinux.h type definitions. It forward-declares `calloc`, `free`, and `memcpy` instead.

### Core Rust Types

#### `SimulatorState` (kfuncs.rs) - Shared state accessed via thread-local

```rust
pub struct SimulatorState {
    pub cpus: Vec<SimCpu>,
    pub dsqs: DsqManager,
    pub current_cpu: i32,
    pub direct_dispatch_cpu: Option<u32>,
    pub trace: Trace,
    pub clock: u64,
    pub task_raw_to_pid: HashMap<usize, i32>,
    pub prng_state: u32,
}
```

Kfuncs access this via `with_sim(|sim| ...)` which reads a thread-local `RefCell<Option<*mut SimulatorState>>`. The pointer is installed by `enter_sim()` before each scheduler ops call and removed by `exit_sim()` afterward.

#### `SimTask` (task.rs) - Scripted task with behavior phases

```rust
pub struct SimTask {
    raw: *mut c_void,              // Heap-allocated C task_struct
    pub pid: i32,
    pub behavior: TaskBehavior,    // Vec<Phase> + repeat flag
    pub phase_idx: usize,
    pub run_remaining_ns: u64,
    pub state: TaskState,          // Sleeping | Runnable | Running { cpu } | Exited
    pub enabled: bool,
    pub prev_cpu: i32,
}
```

#### `SimCpu` (cpu.rs) - Minimal CPU model

```rust
pub struct SimCpu {
    pub id: u32,
    pub current_task: Option<i32>,
    pub local_dsq: VecDeque<i32>,
}
```

#### `DsqManager` / `Dsq` (dsq.rs) - Dispatch queues with FIFO and vtime ordering

Uses `BTreeMap<(u64, i32), i32>` for vtime-ordered queues and `VecDeque<i32>` for FIFO.

### Implemented Kfuncs

| Kfunc | Status | Notes |
|-------|--------|-------|
| `scx_bpf_create_dsq` | Done | Creates DSQ in DsqManager |
| `scx_bpf_select_cpu_dfl` | Done | Prefers prev_cpu if idle, then any idle |
| `scx_bpf_dsq_insert` | Done | Handles SCX_DSQ_LOCAL, SCX_DSQ_LOCAL_ON |
| `scx_bpf_dsq_insert_vtime` | Done | BTreeMap-ordered insert |
| `scx_bpf_dsq_move_to_local` | Done | Pops from DSQ to CPU local DSQ |
| `scx_bpf_dsq_nr_queued` | Done | Returns queued count |
| `scx_bpf_now` | Done | Returns simulated clock |
| `bpf_get_smp_processor_id` | Done | Returns current_cpu from SimulatorState |
| `bpf_ktime_get_ns` | Done | Returns simulated clock |
| `sim_bpf_get_prandom_u32` | Done | Deterministic xorshift32 |
| `scx_bpf_kick_cpu` | Stub (no-op) | Phase 2 |
| `scx_bpf_error_bstr` | Done | Prints error message |
| `scx_bpf_task_cpu` | Done | Returns current_cpu |
| `scx_bpf_reenqueue_local` | Stub (no-op) | |
| `scx_bpf_put_cpumask` | Stub (no-op) | |
| `scx_bpf_destroy_dsq` | Stub (no-op) | |
| `bpf_rcu_read_lock/unlock` | Stub (no-op) | |
| `bpf_task_release` | Stub (no-op) | |
| `bpf_task_from_pid` | Stub (returns null) | |
| `bpf_map_lookup_elem` | C (lib/scxtest) | Reused from PR #2281 |

### Scheduling Lifecycle (Event Handlers)

**`handle_task_wake(pid)`**:
1. Set task state to Runnable, advance past Wake phases
2. Call `scheduler.select_cpu(task.raw, prev_cpu, wake_flags)`
3. If `direct_dispatch_cpu` was set (task inserted to `SCX_DSQ_LOCAL` in select_cpu): call `try_dispatch_and_run(dd_cpu)`
4. Else: call `scheduler.enqueue(task.raw, enq_flags)`, then `try_dispatch_and_run` on all idle CPUs

**`try_dispatch_and_run(cpu)`**:
1. If local DSQ empty: call `scheduler.dispatch(cpu, null)` (fills local DSQ via `scx_bpf_dsq_move_to_local`)
2. Pop from local DSQ, skip exited tasks
3. If got a task: `start_running(cpu, pid)`, else record `CpuIdle`

**`start_running(cpu, pid)`**:
1. Call `scheduler.enable` (first time only), then `scheduler.running`
2. Schedule either `SliceExpired` (at `clock + slice`) or `TaskPhaseComplete` (at `clock + remaining`)

**`handle_slice_expired(cpu)`**:
1. Deduct slice from `run_remaining_ns`, set `p->scx.slice = 0`
2. Call `scheduler.stopping(raw, true)` then `scheduler.enqueue(raw, 0)`
3. `try_dispatch_and_run(cpu)`

**`handle_task_phase_complete(cpu)`**:
1. Save `time_consumed`, set `p->scx.slice = original_slice - time_consumed`
2. Advance phase, call `scheduler.stopping(raw, still_runnable)`
3. Handle next phase (Sleep/Run/Wake/Exit), `try_dispatch_and_run(cpu)`

### Test Results (All Passing)

| Test File | Test | What It Verifies |
|-----------|------|-----------------|
| simple_basic.rs | `test_single_task_single_cpu` | 1 task, 1 CPU: completes with correct runtime |
| simple_basic.rs | `test_multiple_tasks_single_cpu` | 2 tasks, 1 CPU: both get scheduled, preemption occurs |
| simple_basic.rs | `test_multiple_cpus` | 2 tasks, 4 CPUs: tasks spread across CPUs |
| simple_basic.rs | `test_determinism` | Same scenario twice produces identical traces |
| simple_fairness.rs | `test_equal_weight_fairness` | 2 equal-weight tasks on 1 CPU: ~1:1 runtime ratio |
| simple_fairness.rs | `test_weighted_fairness` | Weight 200 vs 100 on 1 CPU: ~2:1 runtime ratio |
| simple_fairness.rs | `test_three_way_weighted_fairness` | Weights 300/200/100: proportional runtime |
| simple_preemption.rs | `test_slice_preemption` | Long-running task is preempted at slice boundary |
| simple_preemption.rs | `test_preemption_interleaving` | 2 tasks alternate via preemption on 1 CPU |
| simple_preemption.rs | `test_sleep_wake_cycle` | Run/Sleep phases produce correct timing |

---

## Phase 2: Extended Capabilities [PLANNED]

- **Cpumask operations**: Functional `bpf_cpumask_create/set/test/and/weight` in Rust
- **`scx_bpf_kick_cpu`**: Generate dispatch events on kicked CPUs (with `SCX_KICK_IDLE`, `SCX_KICK_PREEMPT`)
- **BPF timers**: `bpf_timer_init/set_callback/start` with events scheduled in the event queue
- **Tick simulation**: Periodic `ops.tick()` calls during task execution
- **Waker/wakee tracking**: `bpf_get_current_task_btf()` returns the currently running task
- **More task_struct fields**: `comm`, `flags`, `cpus_ptr`, `nr_cpus_allowed`
- **Target schedulers**: scx_central, scx_qmap, scx_flatcg

## Phase 3: LAVD Support [PLANNED]

- **Arena/SDT allocator**: `scx_task_alloc/free/data` with heap-backed per-task contexts
- **Topology simulation**: NUMA nodes, LLC domains, big/LITTLE cores, SMT siblings
- **Compute domains**: `cpdom_ctx` array initialization (normally done by LAVD's Rust userspace)
- **All LAVD kfuncs**: ~30+ kfuncs including cpuperf, cgroup, DSQ iteration, ringbuf
- **System statistics timer**: Simulated BPF timer firing every 10ms
- **Power management stubs**: Core compaction, frequency scaling
- **Introspection**: Ring buffer output for monitoring

---

## Implementation Notes

Issues discovered and resolved during Phase 1 implementation.

### BPF CO-RE Enum Variables (Root Cause of All Initial Test Failures)

**Problem**: All SCX constants (`SCX_DSQ_LOCAL`, `SCX_SLICE_DFL`, etc.) were 0 in the
compiled userspace code. This caused tasks to be dispatched to DSQ 0 with slice 0
instead of DSQ `SCX_DSQ_LOCAL` (0x8000000000000002) with slice 20ms.

**Root cause**: Two layers of macro indirection:

1. `scheds/include/scx/enums.autogen.bpf.h` (included via `common.bpf.h -> enums.bpf.h`):
   ```c
   const volatile u64 __SCX_DSQ_LOCAL __weak;
   #define SCX_DSQ_LOCAL __SCX_DSQ_LOCAL

   const volatile u64 __SCX_SLICE_DFL __weak;
   #define SCX_SLICE_DFL __SCX_SLICE_DFL
   ```
   These redefine ~30 enum constants as weak `const volatile u64` variables for BPF CO-RE
   relocation. In BPF programs, the BPF loader patches these at load time. In userspace,
   the weak variables have no strong definition and default to 0.

2. `scheds/include/scx/compat.bpf.h` (included via `common.bpf.h`):
   ```c
   #define scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags) \
       (bpf_ksym_exists(scx_bpf_dsq_insert) ? \
        scx_bpf_dsq_insert((p), (dsq_id), (slice), (enq_flags)) : \
        scx_bpf_dispatch___compat((p), (dsq_id), (slice), (enq_flags)))
   ```
   `bpf_ksym_exists(sym)` is defined as `!!sym` (checks if weak symbol address is non-null).

**Fix**: In `sim_wrapper.h`, after `#include <scx/common.bpf.h>`:
- `#undef` all ~30 enum macros from `enums.autogen.bpf.h`
- `#undef` the 4 compat macros (`scx_bpf_dsq_insert`, `scx_bpf_dsq_insert_vtime`,
  `scx_bpf_dsq_move_to_local`, `scx_bpf_now`)

This lets the compiler use the real vmlinux.h enum values and call our Rust kfuncs directly.

**Debug methodology**: Added eprintln traces -> observed dsq_id=0x0 and slice=0 -> disassembled
object code (`objdump -d -j .text.simple_select_cpu`) -> checked relocations (`objdump -r`) ->
found GOT references to `__SCX_DSQ_LOCAL` and `__SCX_SLICE_DFL` -> traced to `enums.autogen.bpf.h`.

### vmlinux.h / stdlib.h Type Conflicts

**Problem**: `sim_task.c` cannot include `<stdlib.h>` or `<string.h>` because they define
types (`u32`, `u64`, etc.) that conflict with vmlinux.h definitions.

**Fix**: Forward-declare the specific libc functions needed:
```c
extern void *calloc(unsigned long nmemb, unsigned long size);
extern void free(void *ptr);
extern void *memcpy(void *dst, const void *src, unsigned long n);
```

### LINUX_KERNEL_VERSION Symbol

**Problem**: `common.bpf.h` declares `extern int LINUX_KERNEL_VERSION __kconfig;` which
needs a definition in userspace.

**Fix**: Provide `int LINUX_KERNEL_VERSION = 0;` in `sim_task.c`.

### Slice Tracking for Vtime Accounting

**Problem**: `scx_simple`'s `simple_stopping()` calculates vtime charge as:
```c
p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
```
In the real kernel, `p->scx.slice` is decremented by tick handling as the task runs.
The simulator didn't update it, so vtime accounting was incorrect.

**Fix**:
- `handle_slice_expired`: Set `p->scx.slice = 0` before calling `stopping()` (full slice consumed)
- `handle_task_phase_complete`: Set `p->scx.slice = original_slice - time_consumed` before
  calling `stopping()` (partial slice consumed)

### Exited Task Guard

**Problem**: If a completed task's PID is still in a DSQ when the CPU tries to dispatch it,
`start_running` would attempt to run an exited task.

**Fix**: Check `TaskState::Exited` at the top of `start_running` and skip to the next task.
