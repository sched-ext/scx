# scx_chaos
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_chaos` is a specialized `sched_ext` scheduler designed to amplify race conditions and timing-dependent bugs by intentionally introducing controlled chaos into the scheduling process. Unlike conventional schedulers that optimize for throughput and latency, scx_chaos deliberately degrades performance in configurable ways to stress-test applications and expose hidden concurrency bugs.

The scheduler is built on top of `scx_p2dq` (Pick-2 Dispatch Queue), reusing its core scheduling logic as a baseline while layering chaos injection mechanisms on top. It operates system-wide but supports targeting specific processes and their descendants through PPID-based filtering.

**Key design principles:**
- **Controlled chaos**: Every chaos mechanism has a configurable probability (frequency) and magnitude, allowing fine-grained control over how aggressively the system is perturbed.
- **Composable traits**: Multiple chaos traits can be enabled simultaneously, each with independent probability settings.
- **Process targeting**: Chaos can be restricted to a specific process tree, leaving the rest of the system unaffected for stability.
- **Observable**: A per-CPU statistics system tracks how many times each chaos trait fires, enabling users to verify that chaos is actually being applied.

## Architecture/Design

### Layered Architecture

scx_chaos is structured in three layers:

1. **Base scheduler (p2dq)**: Provides the fundamental scheduling infrastructure -- CPU selection, dispatch queues, vtime-based fairness, topology awareness, and idle management. scx_chaos includes p2dq's BPF code with `#define P2DQ_CREATE_STRUCT_OPS 0`, suppressing p2dq's struct_ops definition so that chaos can define its own.

2. **Chaos BPF layer** (`main.bpf.c`): Intercepts key scheduling callbacks (`select_cpu`, `enqueue`, `dispatch`, `runnable`, `running`, `tick`, `init_task`) and injects chaos behaviors. Delegates non-chaos work to `p2dq_*_impl()` functions.

3. **Userspace orchestrator** (`lib.rs`, `main.rs`): Parses CLI arguments, configures BPF rodata, manages the BPF skeleton lifecycle, attaches kprobes, spawns the target process, and runs the stats server.

### Data Structures

**`chaos_task_ctx`** (BPF task-local storage):
```c
struct chaos_task_ctx {
    enum chaos_match      match;         // process targeting match result
    enum chaos_trait_kind next_trait;     // trait selected for next enqueue
    enum chaos_trait_kind pending_trait;  // trait set by kprobe, consumed on wakeup
    u64                   enq_flags;     // saved enqueue flags for delayed tasks
    u64                   p2dq_vtime;    // saved p2dq vtime before delay DSQ insertion
};
```

This per-task context is stored in a `BPF_MAP_TYPE_TASK_STORAGE` map (`chaos_task_ctxs`), lazily created via `lookup_create_chaos_task_ctx()`. The `match` field caches the PPID-targeting decision so the expensive parent-walk only happens once per task (in `chaos_init_task`).

**`chaos_match` flags** (bitfield):
| Flag | Value | Meaning |
|------|-------|---------|
| `CHAOS_MATCH_UNKNOWN` | 0 | Not yet evaluated |
| `CHAOS_MATCH_COMPLETE` | 1 | Evaluation has been performed |
| `CHAOS_MATCH_EXCLUDED` | 2 | Task is excluded from chaos |
| `CHAOS_MATCH_HAS_PARENT` | 4 | Task is a descendant of the target PID |

**`chaos_trait_kind` enum**:
| Variant | Description |
|---------|-------------|
| `CHAOS_TRAIT_NONE` | No chaos applied |
| `CHAOS_TRAIT_RANDOM_DELAYS` | Insert random scheduling delay |
| `CHAOS_TRAIT_CPU_FREQ` | Scale CPU frequency down |
| `CHAOS_TRAIT_DEGRADATION` | Reduce time slice (performance degradation) |
| `CHAOS_TRAIT_KPROBE_RANDOM_DELAYS` | Random delay triggered by kprobe hit |

### BPF Maps

| Map Name | Type | Purpose |
|----------|------|---------|
| `chaos_task_ctxs` | `BPF_MAP_TYPE_TASK_STORAGE` | Per-task chaos context (match state, pending traits) |
| `chaos_stats` | `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU counters for each stat type (7 entries) |
| `chaos_timers` | `BPF_MAP_TYPE_ARRAY` | BPF timers for periodic delay-DSQ checking |

### Delay DSQs

scx_chaos creates per-CPU "delay DSQs" with IDs derived from `CHAOS_DSQ_BASE | cpu_idx` (where `CHAOS_DSQ_BASE = 1 << 16 = 65536`). These are vtime-ordered dispatch queues where tasks are parked when a random delay is applied. The vtime key is set to `now + random_delay`, so tasks naturally become eligible for dispatch after their delay expires.

### Userspace Types

**`Trait` enum** (Rust side):
Represents a configured chaos trait with its parameters. Each variant maps to a `chaos_trait_kind` constant and carries a `frequency` (probability 0.0-1.0) plus trait-specific parameters.

**`Builder` struct**:
Encapsulates all configuration needed to construct a `Scheduler`: the list of `Trait`s, kprobe configuration, p2dq options, PPID targeting, and verbosity level. The `Builder` handles BPF skeleton loading, rodata configuration, and kprobe attachment.

**`Scheduler` struct**:
The live scheduler instance. Owns the BPF skeleton (via `Pin<Rc<SkelWithObject>>`), the struct_ops link, kprobe links, the arena allocator, and the stats server. The `SkelWithObject` pattern uses `MaybeUninit<OpenObject>` with a `PhantomPinned` marker to safely self-reference the BPF open object from the skeleton with a `'static` lifetime.

## Chaos Injection Mechanisms

### Trait Selection: The Probability Wheel

The core trait selection algorithm in `choose_chaos()` uses a **cumulative frequency array** encoded as fixed-point u32 values. Each trait's probability is converted from a float (0.0-1.0) to a 32-bit fixed-point number via `frequency * 2^32`. The array is structured as cumulative thresholds:

```
freq_array[NONE] = U32_MAX - sum(other frequencies)
freq_array[1] = freq_array[0] + freq_array[1]
freq_array[2] = freq_array[1] + freq_array[2]
...
```

At selection time, `choose_chaos()` generates a single `bpf_get_prandom_u32()` roll and iterates the array with `#pragma unroll`, returning the first index where `roll <= threshold`. This gives O(1) selection with a single random number regardless of how many traits are configured.

If a task is `CHAOS_MATCH_EXCLUDED`, `choose_chaos()` short-circuits and returns `CHAOS_TRAIT_NONE` immediately.

### Random Delays

**Mechanism**: When `CHAOS_TRAIT_RANDOM_DELAYS` is selected, the task is diverted from normal p2dq dispatch into a per-CPU delay DSQ. The function `enqueue_random_delay()` computes a future timestamp:

```c
u64 vtime = bpf_ktime_get_ns() + chaos_get_uniform_u64(min_ns, max_ns);
scx_bpf_dsq_insert_vtime(p, get_cpu_delay_dsq(-1), 0, vtime, enq_flags);
```

The task's p2dq vtime is saved in `taskc->p2dq_vtime` before diversion, so it can be restored later.

**Dispatch recovery**: In `chaos_dispatch()`, before calling `p2dq_dispatch_impl()`, the scheduler walks the current CPU's delay DSQ. For each task whose `dsq_vtime <= now`, it restores the p2dq vtime and completes the deferred p2dq enqueue via `async_p2dq_enqueue_weak()` followed by `complete_p2dq_enqueue_move()`, which uses `scx_bpf_dsq_move` (or compat fallbacks) to move the task from the delay DSQ into the appropriate p2dq DSQ.

**Timer-based kicking**: A BPF timer (`CHAOS_TIMER_CHECK_QUEUES`) periodically scans all per-CPU delay DSQs. The callback `chaos_timer_check_queues_callback()` iterates over all CPUs, calling `check_dsq_times()` for each. If a task's delay has expired:
- If it is past the slack window (`chaos_timer_check_queues_slack_ns`, default 2.5ms), issue `SCX_KICK_PREEMPT` to force immediate rescheduling.
- If it is merely past due, issue `SCX_KICK_IDLE` to wake the CPU if idle.

The timer reschedules itself adaptively: at the next expected expiry time (clamped between `chaos_timer_check_queues_min_ns` (500us) and `chaos_timer_check_queues_max_ns` (2ms)), or at the maximum interval if no delayed tasks are pending.

**Random number generation**: `chaos_get_prandom_u64_limit()` implements **Lemire's nearly-divisionless algorithm** (Algorithm 5 from the paper) adapted for BPF constraints (no 128-bit arithmetic, bounded loops with `bpf_repeat(CHAOS_MAX_RAND_ATTEMPTS)` where `CHAOS_MAX_RAND_ATTEMPTS = 512`). This provides uniform random numbers in an arbitrary range without modulo bias.

### CPU Frequency Scaling

**Mechanism**: When `CHAOS_TRAIT_CPU_FREQ` is selected, the `chaos_running()` callback sets the CPU performance level to `cpu_freq_min` via `scx_bpf_cpuperf_set()`. When any other trait (or no trait) is active, the CPU is set to `cpu_freq_max`. This creates intermittent slowdowns at the hardware level.

**Important interaction**: When CPU frequency chaos is enabled, the userspace builder disables p2dq's own frequency control (`rodata.p2dq_config.freq_control = false`) to avoid conflicting cpuperf settings.

### Performance Degradation

**Mechanism**: When `CHAOS_TRAIT_DEGRADATION` is selected, the enqueue path modifies the p2dq enqueue promise before completing it. The `degradation_frac7` parameter (0-128) is a 7-bit fractional scale factor:

- For FIFO promises: `slice_ns = (degradation_frac7 << 7) * slice_ns >> 7`
- For vtime promises: both `vtime` and `slice_ns` are scaled by the same factor

This effectively multiplies the time slice by `degradation_frac7 / 128`. A value of 64 means halving the slice. A value of 128 means no change. Values below 128 reduce the slice, causing the task to be preempted sooner and rescheduled more frequently, simulating resource contention.

### Kprobe-Based Delays

**Mechanism**: This is a two-phase system:

1. **Kprobe trigger phase**: A generic BPF kprobe handler (`SEC("kprobe/generic")`) is attached to user-specified kernel functions. When the probed function is called, the handler rolls against `kprobe_delays_freq_frac32` and, if successful, sets `taskc->pending_trait = CHAOS_TRAIT_KPROBE_RANDOM_DELAYS`.

2. **Scheduling phase**: In `chaos_tick()`, if the current task has `pending_trait == CHAOS_TRAIT_KPROBE_RANDOM_DELAYS`, its `scx.slice` is set to 0, forcing an immediate reschedule. In `chaos_runnable()`, the `pending_trait` is transferred to `next_trait`, which is then consumed in `chaos_enqueue()` to apply the delay.

**Kprobe validation**: Before attaching, `validate_kprobes()` reads `available_filter_functions` from the tracefs mount to verify that all requested kernel function names exist.

**Autoattach suppression**: The `generic` BPF program has autoattach disabled via `bpf_program__set_autoattach(..., false)`. Kprobes are manually attached per function name in `attach_kprobes()`.

## Scheduling Hot Path (BPF Callbacks)

### `chaos_init` (sleepable)

1. Creates per-CPU delay DSQs: `scx_bpf_create_dsq(CHAOS_DSQ_BASE | i, node_id)` for each CPU.
2. Initializes the `CHAOS_TIMER_CHECK_QUEUES` timer with `CLOCK_BOOTTIME`.
3. Sets the timer callback to `chaos_timer_check_queues_callback`.
4. Starts the timer with the max interval.
5. Delegates to `p2dq_init_impl()`.

### `chaos_init_task` (sleepable)

1. Delegates to `p2dq_init_task_impl()`.
2. Calls `calculate_chaos_match()` to determine if the task should be targeted for chaos.

### `chaos_select_cpu`

1. Looks up the task's chaos context.
2. If `next_trait` is `CHAOS_TRAIT_RANDOM_DELAYS` or `CHAOS_TRAIT_KPROBE_RANDOM_DELAYS`, returns `prev_cpu` without calling p2dq. This is critical: p2dq's `select_cpu` may directly dispatch the task (bypassing `enqueue`), which would prevent the delay from being applied.
3. Otherwise, delegates to `p2dq_select_cpu_impl()`.

### `chaos_runnable`

1. Looks up the task's chaos context.
2. If `pending_trait` is set (from a kprobe hit), transfers it to `next_trait` and clears `pending_trait`.
3. Otherwise, calls `choose_chaos()` to probabilistically select a trait for this wakeup cycle.

### `chaos_enqueue`

This is the most complex callback. The flow is:

1. Look up the task's chaos context. Save `p->scx.dsq_vtime` to `taskc->p2dq_vtime`.
2. Call `async_p2dq_enqueue()` to get an **enqueue promise** -- p2dq's deferred dispatch decision.
3. If the promise is `COMPLETE` (direct dispatch already happened), return immediately.
4. If the promise is `FAILED`, jump to cleanup.
5. If `next_trait` is `RANDOM_DELAYS` or `KPROBE_RANDOM_DELAYS`, call `enqueue_chaotic()`:
   - Insert the task into the per-CPU delay DSQ with a future vtime.
   - On success, jump to cleanup (destroying the p2dq promise since it won't be fulfilled).
6. If `next_trait` is `DEGRADATION`, modify the promise in-place:
   - Scale down `slice_ns` for FIFO promises.
   - Scale down both `vtime` and `slice_ns` for vtime promises.
7. Complete the p2dq enqueue promise via `complete_p2dq_enqueue()`.

The cleanup path calls `destroy_p2dq_enqueue_promise()`, which kicks the CPU with `SCX_KICK_IDLE` if the promise had already cleared the CPU's idle bit (to avoid leaving a CPU in a stale idle state).

### `chaos_dispatch`

1. Walk the current CPU's delay DSQ (`get_cpu_delay_dsq(-1)` resolves to the current CPU).
2. For each task with `dsq_vtime <= now`:
   - Restore `p->scx.dsq_vtime` from `taskc->p2dq_vtime`.
   - Call `async_p2dq_enqueue_weak()` to re-derive the p2dq dispatch decision.
   - Move the task from the delay DSQ to the p2dq target DSQ via `complete_p2dq_enqueue_move()`.
3. Delegate to `p2dq_dispatch_impl()` for normal dispatch.

### `chaos_running`

1. Delegates to `p2dq_running_impl()` for base scheduling bookkeeping.
2. If `next_trait` is `CHAOS_TRAIT_CPU_FREQ` and `cpu_freq_min > 0`, sets the CPU performance to the minimum frequency.
3. Otherwise, if `cpu_freq_max > 0`, restores the CPU to maximum frequency.

### `chaos_tick`

1. Checks if the task has `pending_trait == CHAOS_TRAIT_KPROBE_RANDOM_DELAYS`.
2. If so, zeroes `p->scx.slice` to force immediate rescheduling, which will trigger the runnable/enqueue path where the delay is applied.

### Struct Ops Registration

```c
SCX_OPS_DEFINE(chaos,
    .dispatch    = chaos_dispatch,
    .enqueue     = chaos_enqueue,
    .init        = chaos_init,
    .init_task   = chaos_init_task,
    .runnable    = chaos_runnable,
    .select_cpu  = chaos_select_cpu,
    .tick        = chaos_tick,
    .update_idle = p2dq_update_idle,    // delegated directly
    .exit_task   = p2dq_exit_task,      // delegated directly
    .exit        = p2dq_exit,           // delegated directly
    .running     = chaos_running,
    .stopping    = p2dq_stopping,       // delegated directly
    .set_cpumask = p2dq_set_cpumask,    // delegated directly
    .timeout_ms  = 30000,
    .name        = "chaos");
```

Callbacks that do not need chaos interception (`update_idle`, `exit_task`, `exit`, `stopping`, `set_cpumask`) are wired directly to p2dq implementations.

## Configuration/Modes

### CLI Arguments

The command line is organized into argument groups:

**Random Delays** (`RandomDelayArgs`):
- `--random-delay-frequency <FLOAT>` -- Probability (0.0-1.0) of applying a delay on each wakeup
- `--random-delay-min-us <MICROSECONDS>` -- Minimum delay duration
- `--random-delay-max-us <MICROSECONDS>` -- Maximum delay duration
- These three options are co-required (specifying one requires specifying all)

**CPU Frequency** (`CpuFreqArgs`):
- `--cpufreq-frequency <FLOAT>` -- Probability of scaling frequency down
- `--cpufreq-min <FREQ>` -- Minimum CPU frequency (cpuperf units)
- `--cpufreq-max <FREQ>` -- Maximum CPU frequency (cpuperf units)

**Performance Degradation** (`PerfDegradationArgs`):
- `--degradation-frequency <FLOAT>` -- Probability of degradation
- `--degradation-frac7 <0-128>` -- Degradation scale factor (7-bit fixed point, default 0)

**Kprobe Random Delays** (`KprobeArgs`):
- `--kprobes-for-random-delays <FUNCTIONS...>` -- Kernel function names to attach kprobes
- `--kprobe-random-delay-frequency <FLOAT>` -- Probability per kprobe hit (default 0.1)
- `--kprobe-random-delay-min-us <MICROSECONDS>` -- Minimum kprobe-induced delay
- `--kprobe-random-delay-max-us <MICROSECONDS>` -- Maximum kprobe-induced delay

**General Scheduling** (`P2dqOpts`):
- All p2dq tuning options are exposed (except ATQs which are explicitly unsupported)

**Process Targeting**:
- `--ppid-targeting` (default: true) -- Focus chaos on the target process tree
- `--pid <PID>` -- Monitor a specific existing PID; exit when it terminates
- Trailing `-- <COMMAND> [ARGS...]` -- Spawn a child process under the scheduler

**Execution Control**:
- `--repeat-failure` -- Restart the child command on non-zero exit
- `--repeat-success` -- Restart the child command on zero exit
- `--stats <SECONDS>` -- Enable periodic stats printing
- `--monitor <SECONDS>` -- Stats-only mode (no scheduler launched)
- `-v` / `--verbose` -- Increase verbosity (repeatable)

### PPID Targeting

PPID targeting controls which tasks receive chaos injection. The mechanism uses `calculate_chaos_match()` which walks the `real_parent` chain of each task up to `CHAOS_NUM_PPIDS_CHECK` (1,048,576) levels:

| Mode | BPF Rodata | Behavior |
|------|-----------|----------|
| No targeting | `ppid_targeting_ppid = -1` | All tasks receive chaos |
| `--pid <PID>` | `ppid_targeting_inclusive = true`, `ppid_targeting_ppid = PID` | PID and all descendants receive chaos |
| `-- command` | `ppid_targeting_inclusive = false`, `ppid_targeting_ppid = self_pid` | Only children of the scheduler process receive chaos; the scheduler itself is excluded |

The match result is cached in `taskc->match` with the `CHAOS_MATCH_COMPLETE` bit, and intermediate ancestors' match results are also propagated to avoid redundant walks for sibling tasks.

### Promise-Based Enqueue

scx_chaos uses p2dq's **enqueue promise** abstraction to intercept and modify dispatch decisions without duplicating p2dq's logic. The flow is:

1. `async_p2dq_enqueue()` computes where the task should go but returns a `struct enqueue_promise` instead of immediately dispatching.
2. The promise can be of kind `FIFO`, `VTIME`, `ATQ_FIFO`, `ATQ_VTIME`, `DHQ_VTIME`, `COMPLETE`, or `FAILED`.
3. Chaos can inspect and modify the promise (e.g., scaling `slice_ns` for degradation).
4. `complete_p2dq_enqueue()` fulfills the promise, actually dispatching the task.
5. For delayed tasks, `destroy_p2dq_enqueue_promise()` cleans up the promise and handles idle-bit restoration.

## Userspace Side

### Skeleton Management

The `SkelWithObject` struct uses a pinned `Rc` with `PhantomPinned` to safely manage the BPF skeleton's self-referential lifetime. The pattern is:

1. Allocate an `Rc<MaybeUninit<SkelWithObject>>`.
2. Extract a `&'static mut MaybeUninit<OpenObject>` via unsafe transmute (safe because the `Rc` is pinned and the struct is never moved).
3. Open, configure, and load the BPF skeleton using the stable reference.
4. Initialize the `RwLock<BpfSkel>` field in-place.
5. Pin the `Rc` and return it.

The `RwLock` wrapper allows shared read access from the stats collection path while maintaining exclusive write access for skeleton mutation during setup.

### Arena Allocator

scx_chaos implements the `scx_userspace_arena::alloc::Allocator` trait via `ArenaAllocator`, which delegates allocation/deallocation to BPF programs (`scx_userspace_arena_alloc_pages` and `scx_userspace_arena_free_pages`). This is wrapped in a `HeapAllocator` for ergonomic use. The arena is initialized after skeleton loading with `ArenaLib::init()`.

### Process Lifecycle Management

The `run()` function orchestrates the full lifecycle:

1. **Ctrl-C handler**: Sets a shared `Mutex<bool>` + `Condvar` shutdown flag.
2. **Monitor-only mode**: If `--monitor` is specified, launches `stats::monitor()` and returns.
3. **Stats thread**: If `--stats` is specified, spawns a background thread running `stats::monitor()`.
4. **Scheduler thread**: Spawns a thread that iterates `BuilderIterator` (currently yields exactly one `Builder`), constructs the `Scheduler`, and calls `observe()`.
5. **PID monitoring**: If `--pid` is given, polls `kill(pid, 0)` every 100ms; signals shutdown when the process exits.
6. **Child process management**: If `-- command` is given, spawns the child and polls `try_wait()` every 100ms. Handles restart logic based on `--repeat-failure` and `--repeat-success`.
7. **Shutdown coordination**: Signals the shutdown condvar and joins all threads.

### Stats System

The `Metrics` struct tracks seven counters, all read from the `chaos_stats` percpu BPF map:

| Metric | BPF Source | Description |
|--------|-----------|-------------|
| `trait_random_delays` | `CHAOS_STAT_TRAIT_RANDOM_DELAYS` | Scheduling delays applied |
| `trait_cpu_freq` | `CHAOS_STAT_TRAIT_CPU_FREQ` | CPU frequency reductions |
| `trait_degradation` | `CHAOS_STAT_TRAIT_DEGRADATION` | Slice degradations |
| `chaos_excluded` | `CHAOS_STAT_CHAOS_EXCLUDED` | Tasks excluded by targeting |
| `chaos_skipped` | `CHAOS_STAT_CHAOS_SKIPPED` | Trait roll selected NONE |
| `kprobe_random_delays` | `CHAOS_STAT_KPROBE_RANDOM_DELAYS` | Kprobe-triggered delays |
| `timer_kicks` | `CHAOS_STAT_TIMER_KICKS` | Timer-initiated CPU kicks |

Stats are served via the `scx_stats` framework with a delta-based reader: each read returns the difference from the previous read, giving per-interval rates rather than cumulative totals.

`get_metrics()` sums each per-CPU counter across all CPUs by reading the percpu map with `lookup_percpu()` and summing the byte-decoded u64 values.

## Compatibility

The BPF code uses compat macros for kernel API transitions:

- `__COMPAT_chaos_scx_bpf_dsq_move` / `__COMPAT_chaos_scx_bpf_dsq_move_set_slice` / `__COMPAT_chaos_scx_bpf_dsq_move_set_vtime` / `__COMPAT_chaos_scx_bpf_dsq_move_vtime`: These check `bpf_ksym_exists()` at runtime to select between the newer `scx_bpf_dsq_move*` APIs and the older `scx_bpf_dispatch_from_dsq*___compat` fallbacks.

The README notes that scx_chaos "has very limited backward compatibility" with older kernels. It requires a modern kernel with full `sched_ext` support.

## Limitations and Caveats

- **ATQs not supported**: The userspace `main.rs` explicitly rejects `--atq-enabled` with `bail!("ATQs not supported")`. The BPF side also errors on `ATQ_FIFO`, `ATQ_VTIME`, and `DHQ_VTIME` promise kinds.
- **CPU ID linearity assumption**: `get_cpu_delay_dsq()` assumes CPU IDs are linear integers, with a TODO noting this should use topology-mapped linear IDs.
- **Degradation for direct dispatch**: The degradation trait may not work for affinitized tasks because p2dq can perform direct dispatch in `select_cpu`, bypassing `enqueue` entirely.
- **Kprobe danger**: The README warns that kprobe-based delays are "the most likely to break your system" since they inject delays in arbitrary kernel code paths.
- **Experimental status**: The scheduler is explicitly marked as experimental and not intended for production use.
