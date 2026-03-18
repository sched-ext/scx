# PMU / bpf_perf_event_read_value in BPF_PROG_TYPE_STRUCT_OPS Programs

Research date: 2026-03-18

## Summary

`bpf_perf_event_read_value` (BPF helper #55) **cannot be called from
`BPF_PROG_TYPE_STRUCT_OPS` programs**. The kernel verifier rejects such
programs with:

    program of this type cannot use helper bpf_perf_event_read_value#55

This is a fundamental architectural restriction in the BPF subsystem, not
a bug. No public kernel patch or kfunc currently extends perf event reading
to struct_ops programs. The scx PMU library (`scx/lib/pmu.bpf.c`) contains
the canonical workaround: separate tracing programs that share data via BPF
maps.

## Kernel Architecture: Why Helper #55 Is Restricted

### How BPF helper availability works

Each BPF program type has a `get_func_proto` callback in its
`bpf_verifier_ops`. When the verifier encounters a helper call, it calls
`get_func_proto(func_id, prog)` to check if the helper is allowed.

Helper #55 (`bpf_perf_event_read_value`) is defined in
`kernel/trace/bpf_trace.c` and exposed via `bpf_tracing_func_proto()`.
Only tracing-type program types call into this function:

- `BPF_PROG_TYPE_KPROBE`
- `BPF_PROG_TYPE_TRACEPOINT`
- `BPF_PROG_TYPE_PERF_EVENT`
- `BPF_PROG_TYPE_RAW_TRACEPOINT` / `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE`
- `BPF_PROG_TYPE_TRACING` (fentry, fexit, fmod_ret, tp_btf)

### struct_ops helper resolution

`BPF_PROG_TYPE_STRUCT_OPS` programs get their helpers differently. The
`bpf_struct_ops` verifier_ops delegates to the subsystem-specific
`st_ops->get_func_proto` callback. Each struct_ops subsystem (e.g.,
`tcp_congestion_ops`, `sched_ext_ops`) can define its own allowed helpers.

However, sched_ext's `get_func_proto` (in `kernel/sched/ext.c`) only
exposes sched_ext-specific kfuncs and the base helper set from
`bpf_base_func_proto()`. It does **not** include any tracing helpers.

The base helper set includes: map operations, spin locks, timers, ktime,
ringbuf, task storage, percpu helpers, etc. -- but NOT perf event helpers.

### No known kernel patches

Web searches across kernel mailing lists (lore.kernel.org), kernel
documentation, and BPF-related forums found:

- **No patches** proposing to add `bpf_perf_event_read_value` to
  struct_ops programs
- **No kfunc** that wraps perf event reading for arbitrary program types
- **No discussion** of extending struct_ops helper sets to include
  tracing helpers

This makes sense architecturally: perf event reading requires the program
to run in a context where the perf event array is meaningful (i.e., a
tracing context on a specific CPU), and the kernel developers have chosen
to enforce this at the verifier level.

## The scx PMU Library Workaround

### Architecture: tracing programs + shared maps

The C scx PMU library (`scx/lib/pmu.bpf.c`) solves this with a two-layer
architecture:

**Layer 1: Tracing programs** (can call helper #55)
```c
SEC("?tp_btf/sched_switch")
int scx_pmu_switch_tc(u64 *ctx) { ... }

SEC("?fentry/scx_tick")
int scx_pmu_tick_tc(u64 *ctx) { ... }
```

These programs are marked with `?` prefix, meaning autoload=false by
default in libbpf. The scheduler userspace must explicitly enable them
via `set_autoload(true)`.

- `scx_pmu_switch_tc`: attached to `tp_btf/sched_switch`, calls
  `scx_pmu_event_stop(prev)` and `scx_pmu_event_start(next, false)` on
  every context switch
- `scx_pmu_tick_tc`: attached to `fentry/scx_tick`, calls
  `scx_pmu_event_start(current, true)` on every scheduler tick

Both call `bpf_perf_event_read_value()` internally (via the
`scx_pmu_event_start` / `scx_pmu_event_stop` functions) -- this is legal
because they are tracing program types.

**Layer 2: Shared data via BPF maps**

Counter data is stored in:
- `scx_pmu_tasks` (`BPF_MAP_TYPE_TASK_STORAGE`): per-task counter
  snapshots (`start[]`, `agg[]`, generation)
- `scx_pmu_map` (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`): perf event fds
  installed by userspace

**Layer 3: struct_ops programs** (read from maps only)

The struct_ops scheduler callbacks (e.g., `cosmos_stopping`) call
`scx_pmu_read()` which only reads from the task storage map -- it never
calls helper #55 directly.

```c
// In struct_ops callback -- safe, no helper #55 call:
scx_pmu_read(p, perf_config, &delta, true);
```

### How scx_layered wires it up correctly

`scx_layered` is the reference implementation that uses this pattern
correctly:

```rust
// In main.rs, before loading:
skel.progs.scx_pmu_switch_tc.set_autoload(membw_tracking);
skel.progs.scx_pmu_tick_tc.set_autoload(membw_tracking);
```

This enables the tracing programs when memory bandwidth tracking is
requested. The struct_ops callbacks then call only `scx_pmu_read()` to
fetch accumulated counter values from the shared task storage map.

### How scx_cosmos is currently broken

`scx_cosmos` does NOT enable the tracing programs. Its `main.rs` has no
`set_autoload` calls for `scx_pmu_switch_tc` or `scx_pmu_tick_tc`.
Instead, it calls `scx_pmu_event_start` and `scx_pmu_event_stop` directly
from its struct_ops callbacks:

```c
// In cosmos_running (struct_ops callback):
if (perf_config)
    scx_pmu_event_start(p, false);   // calls bpf_perf_event_read_value!

// In cosmos_stopping (struct_ops callback):
if (perf_config) {
    scx_pmu_event_stop(p);           // calls bpf_perf_event_read_value!
    update_counters(p, tctx, cpu);
}
```

Because `scx_pmu_event_start` and `scx_pmu_event_stop` call helper #55
internally, and they're being called from struct_ops context, the BPF
verifier would reject this if `perf_config != 0`. The `__weak` annotation
on these functions means the linker includes them, but the verifier still
validates all reachable code paths.

In practice, cosmos works around this by only compiling these functions
into the BPF object via `add_source("../../../lib/pmu.bpf.c")` in
`build.rs`. The `__weak` functions and the `SEC("?...")` tracing programs
are included in the object file, but:
1. The tracing programs have autoload=false (the `?` prefix)
2. The `__weak` functions that call helper #55 are linked but are only
   safe to call from tracing program context

When `perf_config == 0`, the `if (perf_config)` guards prevent the code
from reaching the helper #55 calls, so the verifier may not reject the
program (dead code elimination or the verifier's path-sensitive analysis
may prune those paths). But when `perf_config != 0`, this will fail
verifier validation.

## Possible Solutions

### 1. Wire up tracing programs (like scx_layered)

The correct approach matching the C PMU library's design:

- Enable `scx_pmu_switch_tc` and `scx_pmu_tick_tc` via `set_autoload(true)`
- Remove direct calls to `scx_pmu_event_start`/`scx_pmu_event_stop` from
  struct_ops callbacks
- Only call `scx_pmu_read()` from struct_ops callbacks (reads from map)

This is the approach `scx_layered` uses and is the intended architecture.

### 2. Kernel patch: add helper #55 to struct_ops

A kernel patch could add `bpf_perf_event_read_value` to the struct_ops
helper set by having `bpf_struct_ops_get_func_proto()` or the
sched_ext-specific `get_func_proto` return the helper's func_proto for
`BPF_FUNC_perf_event_read_value`.

**Status**: No such patch exists or has been proposed. This would likely
face resistance because:
- struct_ops programs run in scheduler context, not tracing context
- The perf subsystem interaction has subtle requirements about context
- The tracing program workaround already exists and works

### 3. New kfunc for perf event reading

A kfunc (kernel function callable from BPF) could be created that wraps
perf event reading and is flagged as callable from struct_ops programs.

**Status**: No such kfunc exists. The kfunc mechanism is the modern way
to extend BPF capabilities, but no one has proposed a perf-event-reading
kfunc for struct_ops.

### 4. Userspace polling (fallback)

Instead of reading perf counters from BPF, read them from userspace on a
timer and push the values into a BPF map. This is less precise (sampling
rather than per-context-switch) but requires no tracing programs.

## Conclusion

The restriction is inherent to the BPF architecture and there are no known
efforts to change it. The canonical workaround -- separate tracing programs
sharing data via BPF maps -- is well-established in the scx PMU library and
demonstrated by `scx_layered`. For the aya-rs pure Rust port, the same
pattern should be followed: load separate tracing BPF programs alongside the
struct_ops scheduler, with shared maps for counter data.

## Files Referenced

| File | Description |
|------|-------------|
| `scx/lib/pmu.bpf.c` | C PMU library: tracing programs + shared maps |
| `scx/scheds/include/lib/pmu.h` | PMU library header |
| `scx/scheds/rust/scx_cosmos/src/bpf/main.bpf.c` | Cosmos BPF: calls PMU functions from struct_ops |
| `scx/scheds/rust/scx_cosmos/src/main.rs` | Cosmos userspace: sets up perf events, no tracing prog autoload |
| `scx/scheds/rust/scx_cosmos/build.rs` | Cosmos build: links pmu.bpf.c via add_source |
| `scx/scheds/rust/scx_layered/src/main.rs` | Layered: correctly enables tracing programs |
| `scx/rust/scx_ebpf/src/pmu.rs` | Rust eBPF PMU wrapper: documents the limitation |
| `.beads/issues/aya-49.md` | Issue tracking this limitation |
