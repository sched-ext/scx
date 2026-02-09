# Simulator Framework for sched_ext Schedulers

## Context

sched_ext schedulers are BPF programs that replace the Linux scheduler. Testing them currently requires running on a live kernel, which introduces measurement noise, Heisenberg effects, and interference from other workloads. We want a **deterministic discrete-event simulator** that compiles scheduler BPF C code as regular userspace C and drives it through scheduling cycles with scripted fake tasks.

**Prior art**: PR #2281 (merged) added a unit-test framework at `lib/scxtest/` that compiles BPF code as userspace C with stubbed kfuncs. It tests individual static functions, not full scheduling cycles. We build on its compilation infrastructure but add a full simulation engine.

**Phased approach**: Phase 1 targets `scx_simple` (152 lines, 8 ops, 5 kfuncs). Phase 2 adds richer capabilities (cpumask ops, timers, topology). Phase 3 targets `scx_lavd` (5000+ lines, 24 ops, 30+ kfuncs).

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                Rust Simulator Engine                  │
│                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │ Event    │ │ CPU      │ │ Task     │ │ Trace  │ │
│  │ Queue    │ │ State    │ │ State    │ │ Log    │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ DSQ      │ │ Idle CPU │ │ BPF Map Backing      │ │
│  │ Manager  │ │ Tracker  │ │ Storage              │ │
│  └──────────┘ └──────────┘ └──────────────────────┘ │
│                                                      │
│  ┌──────────────────────────────────────────────────┐│
│  │     Kfunc Implementations (#[no_mangle])         ││
│  │  scx_bpf_dsq_insert, scx_bpf_select_cpu_dfl,    ││
│  │  scx_bpf_dsq_move_to_local, bpf_map_lookup_elem ││
│  └───────────────────────┬──────────────────────────┘│
│                          │ C calls kfuncs             │
│  ┌───────────────────────┴──────────────────────────┐│
│  │     Scheduler Ops (extern "C" from C code)       ││
│  │  simple_select_cpu, simple_enqueue, ...           ││
│  └───────────────────────┬──────────────────────────┘│
│                          │ Compiled together          │
│  ┌───────────────────────┴──────────────────────────┐│
│  │     Scheduler C Code (scx_simple.bpf.c)          ││
│  │     compiled as userspace C via wrapper           ││
│  └──────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────┘
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

## Phase 1: scx_simple Simulator

### Directory Structure

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
    ├── simple_basic.rs              # Basic: tasks run and complete
    ├── simple_fairness.rs           # Weighted vtime fairness properties
    └── simple_preemption.rs         # Slice expiry and re-scheduling
```

### Build System (`build.rs`)

Uses `cc` crate to compile:
1. `lib/scxtest/` C files (overrides.c, scx_test_map.c, scx_test_cpumask.c) - reuse existing
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

`csrc/sim_wrapper.h` - included by scheduler wrappers:
```c
// First include the test infrastructure (overrides, map emulation)
#include <scx_test.h>
#include <scx_test_map.h>
#include <scx_test_cpumask.h>

// Include common.bpf.h to set its header guard and get type definitions
#include <scx/common.bpf.h>

// Undo BPF CO-RE enum macros (see "Implementation Notes" below)
#undef SCX_DSQ_LOCAL
#undef SCX_SLICE_DFL
// ... all ~30 enum macros

// Undo compat wrapper macros
#undef scx_bpf_dsq_insert
#undef scx_bpf_dsq_insert_vtime
#undef scx_bpf_dsq_move_to_local
#undef scx_bpf_now

// Override BPF_STRUCT_OPS to produce regular C functions
#undef BPF_STRUCT_OPS
#define BPF_STRUCT_OPS(name, args...) \
    __attribute__((used)) name(args)

#undef BPF_STRUCT_OPS_SLEEPABLE
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    __attribute__((used)) name(args)

// SCX_OPS_DEFINE creates a struct_ops registration - no-op in simulator
#undef SCX_OPS_DEFINE
#define SCX_OPS_DEFINE(name, ...)
```

`csrc/simple_wrapper.c`:
```c
#include "sim_wrapper.h"
#include "sim_task.h"
// The #include <scx/common.bpf.h> inside scx_simple.bpf.c is
// skipped due to header guard, so our overridden macros take effect
#include "scx_simple.bpf.c"
```

### task_struct Management

Since we use the real vmlinux.h, `struct task_struct` is the full kernel struct (potentially thousands of bytes). Managed via C accessor functions:

`csrc/sim_task.h` / `csrc/sim_task.c`:
```c
struct task_struct *sim_task_alloc(void);      // calloc(1, sizeof(struct task_struct))
void sim_task_free(struct task_struct *p);      // free(p)
size_t sim_task_struct_size(void);              // sizeof(struct task_struct)

// Field accessors for Rust
void sim_task_set_pid(struct task_struct *p, int pid);
void sim_task_set_weight(struct task_struct *p, u32 weight);
void sim_task_set_static_prio(struct task_struct *p, int prio);
void sim_task_set_nr_cpus_allowed(struct task_struct *p, int nr);

u64  sim_task_get_dsq_vtime(struct task_struct *p);
void sim_task_set_dsq_vtime(struct task_struct *p, u64 vtime);
u64  sim_task_get_slice(struct task_struct *p);
void sim_task_set_slice(struct task_struct *p, u64 slice);
u32  sim_task_get_weight(struct task_struct *p);
```

Note: `sim_task.c` cannot include `<stdlib.h>` or `<string.h>` because they conflict
with vmlinux.h type definitions. Instead, it forward-declares the few libc functions
it needs (`calloc`, `free`, `memcpy`).

### Core Rust Types

#### `engine.rs` - Simulation Loop

```rust
pub struct Simulator<S: Scheduler> {
    scheduler: S,
}
```

The simulator state is separated into `SimulatorState` (in `kfuncs.rs`) which is
shared with kfuncs via a thread-local pointer. Tasks are stored in a separate
`HashMap<i32, SimTask>` to avoid borrow conflicts.

Event loop pseudocode:
```
loop {
    event = events.pop()  // earliest event from min-heap
    if event.time > end_time: break
    clock = event.time
    match event {
        TaskWake { pid } => handle_task_wake(pid),
        SliceExpired { cpu } => handle_slice_expired(cpu),
        TaskPhaseComplete { cpu } => handle_task_phase_complete(cpu),
    }
}
```

#### `task.rs` - Task Model

```rust
pub struct SimTask {
    raw: *mut c_void,              // Heap-allocated task_struct
    pid: i32,
    behavior: TaskBehavior,
    phase_idx: usize,              // Current phase in behavior
    run_remaining_ns: u64,         // Remaining ns in current Run phase
    state: TaskState,              // Sleeping | Runnable | Running(cpu) | Exited
    enabled: bool,                 // Whether enable() has been called
    prev_cpu: i32,                 // Last CPU (for select_cpu prev_cpu)
}

pub struct TaskBehavior {
    pub phases: Vec<Phase>,
    pub repeat: bool,
}

pub enum Phase {
    Run(u64),                      // Run for N ns
    Sleep(u64),                    // Sleep for N ns
    Wake(i32),                     // Wake task with given pid
}

pub enum TaskState {
    Sleeping,
    Runnable,
    Running { cpu: u32 },
    Exited,
}
```

#### `cpu.rs` - CPU Model

```rust
pub struct SimCpu {
    pub id: u32,
    pub current_task: Option<i32>,   // pid of running task
    pub local_dsq: VecDeque<i32>,    // Local DSQ (FIFO)
}
```

#### `dsq.rs` - Dispatch Queues

```rust
pub struct DsqManager {
    dsqs: HashMap<u64, Dsq>,
}

pub struct Dsq {
    pub id: u64,
    pub vtime_tree: BTreeMap<(u64, i32), i32>,  // (vtime, pid) -> pid for vtime ordering
    pub fifo: VecDeque<i32>,                     // FIFO entries
}
```

DSQ operations:
- `create(dsq_id)`: Add empty DSQ to map
- `insert_fifo(dsq_id, pid)`: FIFO insert
- `insert_vtime(dsq_id, pid, vtime)`: Vtime-ordered insert
- `move_to_local(dsq_id, cpu)`: Pop head and push to CPU's local DSQ
- `nr_queued(dsq_id)`: Return count

Special DSQ IDs (from kernel):
- `SCX_DSQ_LOCAL` (0x8000000000000002): Insert to current CPU's local DSQ
- `SCX_DSQ_LOCAL_ON | cpu`: Insert to specific CPU's local DSQ
- `SCX_DSQ_GLOBAL` (0x8000000000000001): Global built-in DSQ

#### `kfuncs.rs` - Thread-Local State Pattern

```rust
use std::cell::RefCell;

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

thread_local! {
    static SIM_STATE: RefCell<Option<*mut SimulatorState>> = RefCell::new(None);
}

/// SAFETY: Must be called while Simulator is alive and pinned.
/// Only used during synchronous ops callback execution.
fn with_sim<F, R>(f: F) -> R
where
    F: FnOnce(&mut SimulatorState) -> R,
{
    SIM_STATE.with(|state| {
        let ptr = state.borrow().expect("simulator not initialized");
        let sim = unsafe { &mut *ptr };
        f(sim)
    })
}

// Install/remove simulator state for the duration of an ops call
pub unsafe fn enter_sim(state: &mut SimulatorState) { ... }
pub fn exit_sim() { ... }
```

Kfunc implementations (Phase 1 - only what scx_simple uses):

```rust
#[no_mangle]
pub extern "C" fn scx_bpf_create_dsq(dsq_id: u64, _node: i32) -> i32 { ... }

#[no_mangle]
pub extern "C" fn scx_bpf_select_cpu_dfl(
    p: *mut c_void, prev_cpu: i32, _wake_flags: u64, is_idle: *mut bool,
) -> i32 { ... }

#[no_mangle]
pub extern "C" fn scx_bpf_dsq_insert(
    p: *mut c_void, dsq_id: u64, slice: u64, enq_flags: u64,
) { ... }

#[no_mangle]
pub extern "C" fn scx_bpf_dsq_insert_vtime(
    p: *mut c_void, dsq_id: u64, slice: u64, vtime: u64, _enq_flags: u64,
) { ... }

#[no_mangle]
pub extern "C" fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool { ... }

#[no_mangle]
pub extern "C" fn scx_bpf_now() -> u64 { ... }

#[no_mangle]
pub extern "C" fn bpf_get_smp_processor_id() -> u32 { ... }

#[no_mangle]
pub extern "C" fn sim_bpf_get_prandom_u32() -> u32 { ... } // deterministic xorshift32
```

#### `trace.rs` - Event Tracing

```rust
pub struct TraceEvent {
    pub time_ns: u64,
    pub cpu: u32,
    pub kind: TraceKind,
}

pub enum TraceKind {
    TaskScheduled { pid: i32 },
    TaskPreempted { pid: i32 },
    TaskSlept { pid: i32 },
    TaskWoke { pid: i32 },
    TaskCompleted { pid: i32 },
    CpuIdle,
}
```

The `Trace` struct provides analysis methods:
- `total_runtime(pid)`: Sum of intervals between TaskScheduled and the next stop event
- `schedule_count(pid)`: Number of times the task was scheduled
- `idle_count(cpu)`: Number of times a CPU went idle
- `dump()`: Pretty-print the trace

#### `scenario.rs` - Scenario Builder

```rust
pub struct Scenario {
    pub nr_cpus: u32,
    pub tasks: Vec<TaskDef>,
    pub duration_ns: u64,
}

impl Scenario {
    pub fn builder() -> ScenarioBuilder { ... }
}

impl ScenarioBuilder {
    pub fn cpus(mut self, n: u32) -> Self { ... }
    pub fn task(mut self, def: TaskDef) -> Self { ... }
    pub fn duration(mut self, ns: u64) -> Self { ... }
    pub fn build(self) -> Scenario { ... }
}
```

#### `ffi.rs` - Scheduler Ops Trait + FFI Declarations

```rust
pub trait Scheduler {
    unsafe fn init(&self) -> i32;
    unsafe fn select_cpu(&self, p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32;
    unsafe fn enqueue(&self, p: *mut c_void, enq_flags: u64);
    unsafe fn dispatch(&self, cpu: i32, prev: *mut c_void);
    unsafe fn running(&self, p: *mut c_void);
    unsafe fn stopping(&self, p: *mut c_void, runnable: bool);
    unsafe fn enable(&self, p: *mut c_void);
    // Optional callbacks with default no-op implementations:
    unsafe fn quiescent(&self, _p: *mut c_void, _deq_flags: u64) {}
    unsafe fn runnable(&self, _p: *mut c_void, _enq_flags: u64) {}
}

pub struct ScxSimple;
impl Scheduler for ScxSimple { ... }
```

### Scheduling Lifecycle (Event Handlers)

**`handle_task_wake(pid)`**:
```
1. Set task state to Runnable
2. Advance past any Wake phases to reach the next Run phase
3. Set current_cpu context to the task's prev_cpu
4. Call scheduler.select_cpu(task.raw, prev_cpu, wake_flags)
5. If direct_dispatch_cpu was set (task inserted to SCX_DSQ_LOCAL in select_cpu):
   - That CPU now has the task on its local DSQ
   - Call try_dispatch_and_run(dd_cpu) to start running
6. Else: call scheduler.enqueue(task.raw, enq_flags)
   - Scheduler inserts to a DSQ via kfuncs
   - For each idle CPU: call try_dispatch_and_run(cpu)
```

**`try_dispatch_and_run(cpu)`**:
```
1. If CPU already running something: return
2. If local DSQ empty: call scheduler.dispatch(cpu, null)
   - Scheduler calls scx_bpf_dsq_move_to_local() which populates local DSQ
3. Pop from local DSQ
4. If got a task: start_running(cpu, pid)
5. Else: CPU goes/stays idle (record CpuIdle trace event)
```

**`start_running(cpu, pid)`**:
```
1. Check task is not Exited (skip if so, try next from DSQ)
2. Set task state to Running { cpu }, set current_task on CPU
3. Call scheduler.enable(task.raw) [only on first schedule]
4. Call scheduler.running(task.raw)
5. Read slice from p->scx.slice and remaining work from run_remaining_ns
6. Schedule event:
   if remaining == 0:
     -> TaskPhaseComplete immediately
   elif slice <= remaining:
     -> SliceExpired at clock + slice
   else:
     -> TaskPhaseComplete at clock + remaining
```

**`handle_slice_expired(cpu)`**:
```
1. task = current task on cpu
2. Deduct slice from task.run_remaining_ns
3. Record TaskPreempted trace event
4. Set p->scx.slice = 0 (full slice consumed, for vtime accounting)
5. Call scheduler.stopping(task.raw, true)  // still runnable
6. Call scheduler.enqueue(task.raw, 0)      // re-enqueue
7. try_dispatch_and_run(cpu)                // get next task
```

**`handle_task_phase_complete(cpu)`** (task finishes its Run phase):
```
1. task = current task on cpu
2. Save time_consumed = run_remaining_ns, original_slice = p->scx.slice
3. Advance to next phase in task.behavior
4. Set p->scx.slice = original_slice - time_consumed (for vtime accounting)
5. Call scheduler.stopping(task.raw, still_runnable)
6. Handle next phase:
   - Sleep(duration): task sleeps, schedule TaskWake at clock + duration
   - Run(_): task goes directly to re-enqueue
   - Wake(target_pid): wake target, advance to next phase
   - None (no repeat): task exits
7. try_dispatch_and_run(cpu)
```

### Kfuncs Required for Phase 1 (scx_simple)

| Kfunc | Implementation | Notes |
|-------|---------------|-------|
| `scx_bpf_create_dsq` | Rust - create DSQ in DsqManager | Returns 0 on success |
| `scx_bpf_select_cpu_dfl` | Rust - find idle CPU, prefer prev | Sets `*is_idle` |
| `scx_bpf_dsq_insert` | Rust - FIFO insert to DSQ | Handles SCX_DSQ_LOCAL |
| `scx_bpf_dsq_insert_vtime` | Rust - vtime insert to DSQ | BTreeMap ordered |
| `scx_bpf_dsq_move_to_local` | Rust - pop from DSQ to local | Returns bool |
| `scx_bpf_dsq_nr_queued` | Rust - count queued tasks | Returns i32 |
| `scx_bpf_now` | Rust - return sim clock | |
| `bpf_get_smp_processor_id` | Rust - return current_cpu | Thread-local |
| `bpf_ktime_get_ns` | Rust - return sim clock | |
| `scx_bpf_kick_cpu` | No-op stub | Phase 2 |
| `scx_bpf_error_bstr` | Print error, don't panic | |
| `bpf_map_lookup_elem` | C (lib/scxtest) - existing impl | Map emulation from PR #2281 |

All other kfuncs fall through to `__weak` stubs in `lib/scxtest/overrides.c`.

### Example Test Scenario

```rust
#[test]
fn test_simple_two_tasks_fairness() {
    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "heavy".into(),
            pid: 1,
            weight: 100,      // default weight (nice 0)
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],  // 20ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "light".into(),
            pid: 2,
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration(100_000_000)  // 100ms
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);

    // Both tasks should get roughly equal CPU time
    let t1_runtime = trace.total_runtime(1);
    let t2_runtime = trace.total_runtime(2);
    let ratio = t1_runtime as f64 / t2_runtime as f64;
    assert!((0.9..=1.1).contains(&ratio),
        "Expected ~equal runtime, got ratio {ratio}");
}

#[test]
fn test_simple_weighted_fairness() {
    let scenario = Scenario::builder()
        .cpus(1)  // single CPU forces contention
        .task(TaskDef {
            name: "high-weight".into(), pid: 1, weight: 200,
            behavior: TaskBehavior { phases: vec![Phase::Run(50_000_000)], repeat: true },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "low-weight".into(), pid: 2, weight: 100,
            behavior: TaskBehavior { phases: vec![Phase::Run(50_000_000)], repeat: true },
            start_time_ns: 0,
        })
        .duration(200_000_000)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);

    // Weight-200 task should get ~2x the runtime of weight-100 task
    let t1_runtime = trace.total_runtime(1);
    let t2_runtime = trace.total_runtime(2);
    let ratio = t1_runtime as f64 / t2_runtime as f64;
    assert!((1.8..=2.2).contains(&ratio),
        "Expected ~2:1 ratio, got {ratio}");
}
```

---

## Phase 2: Extended Capabilities (future)

- **Cpumask operations**: Functional `bpf_cpumask_create/set/test/and/weight` in Rust
- **Per-CPU context**: `bpf_get_smp_processor_id()` properly tracks which simulated CPU is active
- **BPF timers**: `bpf_timer_init/set_callback/start` with events scheduled in the event queue
- **`scx_bpf_kick_cpu`**: Generate dispatch events on kicked CPUs (with `SCX_KICK_IDLE`, `SCX_KICK_PREEMPT`)
- **Tick simulation**: Periodic `ops.tick()` calls during task execution
- **Waker/wakee tracking**: `bpf_get_current_task_btf()` returns the currently running task
- **More task_struct fields**: `comm`, `flags`, `cpus_ptr`, `nr_cpus_allowed`
- **Target schedulers**: scx_central, scx_qmap, scx_flatcg

## Phase 3: LAVD Support (future)

- **Arena/SDT allocator**: `scx_task_alloc/free/data` with heap-backed per-task contexts
- **Topology simulation**: NUMA nodes, LLC domains, big/LITTLE cores, SMT siblings
- **Compute domains**: `cpdom_ctx` array initialization (normally done by LAVD's Rust userspace)
- **All LAVD kfuncs**: ~30+ kfuncs including cpuperf, cgroup, DSQ iteration, ringbuf
- **System statistics timer**: Simulated BPF timer firing every 10ms
- **Power management stubs**: Core compaction, frequency scaling
- **Introspection**: Ring buffer output for monitoring

---

## Verification

### Phase 1 Checks
1. **Compilation**: `cargo build` successfully compiles scx_simple.bpf.c as userspace C
2. **Smoke test**: Single task on single CPU runs to completion, trace shows expected events
3. **Fairness test**: Two equal-weight tasks on 1 CPU get equal runtime
4. **Weight test**: 2:1 weight ratio produces ~2:1 runtime ratio
5. **Multi-CPU**: Tasks spread across CPUs; idle CPUs get utilized
6. **Determinism**: Same scenario produces identical trace on repeated runs
7. **Sleep/wake**: Tasks that sleep and wake produce correct timing in trace

### Key Files to Modify/Create
- `rust/scx_simulator/` - entire new crate (all files listed above)
- `Cargo.toml` (workspace root) - add `rust/scx_simulator` to workspace members

### Key Files to Reuse (read-only)
- `lib/scxtest/overrides.h` - BPF builtin neutralization
- `lib/scxtest/overrides.c` - `__weak` kfunc stubs
- `lib/scxtest/scx_test_map.h/c` - BPF map emulation
- `lib/scxtest/scx_test_cpumask.h/c` - cpumask emulation
- `lib/scxtest/kern_types.h` - integer type aliases
- `scheds/vmlinux/arch/x86/vmlinux.h` - kernel type definitions
- `scheds/include/scx/common.bpf.h` - SCX macros and kfunc declarations
- `scheds/c/scx_simple.bpf.c` - the scheduler under test

---

## Implementation Notes

These notes capture issues discovered and resolved during implementation.

### BPF CO-RE Enum Variables (Root Cause of All Test Failures)

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
   In userspace, `scx_bpf_dsq_insert` (our Rust kfunc) has a non-null address, so the
   check passes, but the macro expansion still goes through the ternary operator, and the
   `___compat` variant declarations are `__ksym __weak` symbols that may cause link issues.

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
