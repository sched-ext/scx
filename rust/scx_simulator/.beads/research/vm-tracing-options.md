# VM Tracing Options for `--real-run vm` Executions

## Executive Summary

This document explores options for tracing scheduler behavior during `scxsim --real-run vm` executions. The challenge is capturing detailed scheduling decisions inside a virtme-ng VM while minimizing interference with the workload. We explore wprof, scxtop tracing, ftrace/bpftrace, and CPU isolation techniques.

---

## 1. What is wprof?

**Repository**: https://github.com/facebookexperimental/wprof

**Overview**: wprof is a BPF-based profiler that captures kernel scheduler events and outputs them in Perfetto format. It's designed for high-fidelity tracing of scheduling behavior with minimal overhead.

### Key Features

1. **Two Output Modes**:
   - **TrackEvent Mode** (default): Rich metadata including sched_ext layer_id, dsq_id, perf counter deltas, compound delay tracking, and stack traces
   - **FtraceEvent Mode** (`--emit-sched-view`): Standard Perfetto format compatible with UI, but loses sched_ext metadata

2. **Events Captured**:
   - ONCPU slices (task on-CPU periods)
   - WAKER/WAKEE instants (wakeup relationships)
   - PREEMPTOR/PREEMPTEE instants (preemption tracking)
   - TIMER events (perf timer ticks)
   - FORK/EXEC/EXIT/FREE (process lifecycle)
   - HARDIRQ/SOFTIRQ/WQ (interrupt tracking)
   - IPI (inter-processor interrupts)

3. **Usage**:
   ```bash
   # FtraceEvent mode (currently recommended for scxtop compatibility)
   sudo ./wprof --emit-sched-view -o trace.proto

   # TrackEvent mode (preserves sched_ext metadata)
   sudo ./wprof -o trace.proto
   ```

4. **scxtop Integration**: scxtop can parse and analyze wprof traces via its MCP interface. See `/home/newton/work/multi_scx/scx1/tools/scxtop/WPROF_COMPATIBILITY_GUIDE.md`.

### Limitations for VM Use

- wprof requires BPF, which needs CAP_BPF/CAP_PERFMON or root inside the VM
- BPF overhead from wprof itself could affect scheduling behavior if running on the same CPUs as the workload
- This motivates CPU isolation for the tracer

---

## 2. CPU Isolation Approaches

The goal: Reserve one CPU core exclusively for tracing (pinned wprof/bpftrace) so it doesn't interfere with the workload.

### 2.1 Using `isolcpus` Kernel Parameter

**Approach**: Pass `isolcpus=N` to the VM kernel to exclude CPU N from the scheduler's general domain.

**How vng supports this**:
```bash
vng -r --cpus 4 --memory 4G --append "isolcpus=3" --exec '...'
```

The `--append` flag passes additional kernel boot parameters. This is the cleanest approach as the kernel itself excludes the CPU.

**Pros**:
- Kernel-level isolation, strongest guarantee
- The scheduler won't schedule workload tasks on the isolated CPU
- Works with any sched_ext scheduler

**Cons**:
- The isolated CPU won't be visible to the sched_ext scheduler's topology view
- May confuse schedulers that expect a certain number of CPUs
- Requires explicit pinning of the tracer to the isolated CPU

**Example**:
```bash
# Launch VM with CPU 3 isolated
vng -r --cpus 4 --memory 4G \
    --append "isolcpus=3" \
    --exec 'scx_simple & sleep 1; taskset -c 3 wprof --emit-sched-view -o /tmp/trace.proto & TRACER=$!; taskset -c 0-2 rt-app workload.json; kill $TRACER'
```

### 2.2 Using cgroups/cpusets

**Approach**: Create a cpuset cgroup that excludes the tracing CPU, and run the workload in that cgroup.

**Inside VM**:
```bash
# Create cpuset for workload (CPUs 0-2)
mkdir -p /sys/fs/cgroup/cpuset/workload
echo "0-2" > /sys/fs/cgroup/cpuset/workload/cpus
echo "0" > /sys/fs/cgroup/cpuset/workload/mems
echo $$ > /sys/fs/cgroup/cpuset/workload/tasks

# Run workload in this cgroup
rt-app workload.json
```

**Pros**:
- Flexible, can adjust at runtime
- Works with standard Linux tools

**Cons**:
- Requires cgroup setup in VM init script
- Not as strong as `isolcpus` (load balancer may still consider the CPU)
- More complex scripting

### 2.3 Using `taskset` Only

**Approach**: Pin workload to CPUs 0..N-1 and tracer to CPU N using taskset.

```bash
taskset -c 0-2 rt-app workload.json &
taskset -c 3 wprof --emit-sched-view -o trace.proto
```

**Pros**:
- Simple, no kernel parameters needed
- Works without special VM setup

**Cons**:
- The scheduler still sees all CPUs
- Scheduler may make decisions assuming CPU 3 is available
- Not true isolation, just affinity pinning
- The tracer's BPF programs run on all CPUs anyway

### 2.4 Recommendation: `isolcpus` + `taskset`

**Best approach for VM tracing**:

1. Use `--cpus N+1` where N is the workload CPU count
2. Pass `--append "isolcpus=N"` to isolate the last CPU
3. Pin the tracer to CPU N with `taskset -c N`
4. Let the workload run on CPUs 0..N-1 (scheduler won't see CPU N)

**Modified `run_vm()` signature**:
```rust
pub fn run_vm(
    workload_path: &Path,
    scheduler: &str,
    nr_cpus: u32,
    trace_output: Option<&Path>,  // If Some, enable tracing
) -> Result<(), String>
```

---

## 3. Alternative Tracing Approaches

### 3.1 scxtop BPF Tracing

**Location**: `/home/newton/work/multi_scx/scx1/tools/scxtop/src/bpf/main.bpf.c`

scxtop has comprehensive BPF programs that trace:
- `sched_switch`, `sched_wakeup`, `sched_waking`, `sched_wakeup_new`
- `sched_migrate_task`, `sched_process_fork`, `sched_process_exec`, `sched_process_exit`
- `softirq_entry/exit`, `ipi_send_cpu`
- kprobes on `scx_bpf_*` functions (dsq_insert, dispatch, kick_cpu, etc.)

**Usage in VM**:
```bash
sudo scxtop trace -d 5000 -o trace.proto -s
```

**Output**: Perfetto-format protobuf traces analyzable with scxtop MCP or ui.perfetto.dev.

**Pros**:
- Already integrated with scx ecosystem
- Captures sched_ext-specific events (DSQ latency, vtime, layer IDs)
- MCP interface for programmatic analysis

**Cons**:
- scxtop binary needs to be available in VM
- Requires daemon mode for some features

### 3.2 bpftrace Scripts

**Existing scripts**:
- `/home/newton/work/multi_scx/scx1/rust/scx_simulator/scripts/trace_scx_ops.bt` - Traces sched_class callbacks and kfuncs
- `/home/newton/work/multi_scx/scx1/scripts/scxtop.bt` - Interactive DSQ and latency monitoring

**trace_scx_ops.bt captures**:
- sched_class entry points (select_task_rq, enqueue_task, dequeue_task, balance, etc.)
- kfunc fexits (scx_bpf_dispatch, scx_bpf_pick_idle_cpu, scx_bpf_kick_cpu, etc.)
- Lifecycle tracepoints (sched_switch, sched_wakeup)

**Usage**:
```bash
sudo bpftrace trace_scx_ops.bt 4 > trace.log 2>&1 &
```

**Pros**:
- Lightweight, single script
- Captures ops-level events (what the simulator models)
- Human-readable text output

**Cons**:
- Text format, not directly comparable to simulator trace
- Known issue: kprobe entries can't extract PIDs due to BPF complexity limits (sim-c5dbf)

### 3.3 perf sched

**Commands**:
```bash
# Record scheduling events
perf sched record -- rt-app workload.json

# Analyze latencies
perf sched latency

# Show timeline
perf sched map
```

**Pros**:
- Standard Linux tool, no BPF required
- Good latency analysis

**Cons**:
- No sched_ext-specific information
- Heavyweight file format

### 3.4 ftrace / trace-cmd

**Location**: `/home/newton/work/multi_scx/scx1/scripts/sched_ftrace.py`

Simple ftrace-based tracing via `/sys/kernel/tracing/`:
```bash
# Enable sched_switch event
echo 1 > /sys/kernel/tracing/events/sched/sched_switch/enable
echo 1 > /sys/kernel/tracing/tracing_on

# Read trace
cat /sys/kernel/tracing/trace_pipe
```

**trace-cmd**:
```bash
trace-cmd record -e sched:sched_switch -e sched:sched_wakeup
trace-cmd report
```

**Pros**:
- Low overhead, in-kernel buffering
- No BPF needed

**Cons**:
- Limited to ftrace events, no sched_ext specifics
- Text format

### 3.5 Scheduler Stats (scx_stats)

**Overview**: sched_ext schedulers can expose statistics via a Unix socket at `/var/run/scx/root/stats`.

**From scxtop**: `stats://scheduler/raw` resource provides raw JSON statistics.

**Pros**:
- Zero tracing overhead
- Aggregate statistics (not per-event)
- Scheduler-specific metrics (layer stats, DSQ depths, etc.)

**Cons**:
- Aggregates only, no individual events
- Scheduler must implement scx_stats

---

## 4. Output Format Considerations

### 4.1 Simulator's Internal Format

**Location**: `/home/newton/work/multi_scx/scx1/rust/scx_simulator/crates/scx_simulator/src/trace.rs`

The simulator records `TraceEvent` with:
- `time_ns`: TimeNs (simulated nanoseconds)
- `cpu`: CpuId
- `kind`: TraceKind enum

**TraceKind variants**:
- High-level: `TaskScheduled`, `TaskPreempted`, `TaskYielded`, `TaskSlept`, `TaskWoke`, `TaskCompleted`, `CpuIdle`
- Ops-level: `PutPrevTask`, `SelectTaskRq`, `EnqueueTask`, `Balance`, `PickTask`, `SetNextTask`
- Kfunc-level: `DsqInsert`, `DsqInsertVtime`, `DsqMoveToLocal`, `KickCpu`, `Tick`

### 4.2 Comparison Formats

For comparing sim vs real:

1. **Perfetto JSON**: Both simulator (`write_perfetto_json`) and real tracing (wprof, scxtop) can output Perfetto format. View side-by-side in ui.perfetto.dev.

2. **Event-by-Event Comparison**: Need to align by logical event type rather than timestamp. Compare sequences like:
   - Sim: ENQUEUE(pid=1) -> BALANCE -> DSQ_INSERT(pid=1) -> PICK(pid=1) -> SCHED(pid=1)
   - Real: enqueue_task -> balance -> scx_bpf_dispatch -> sched_switch

3. **Statistical Comparison**: Compare aggregate metrics:
   - Total runtime per task
   - Schedule count per task
   - DSQ latencies
   - CPU utilization distribution

### 4.3 Recommended Approach

1. **Real tracing**: Use `trace_scx_ops.bt` (modified to output structured format) or wprof with `--emit-sched-view`

2. **Format conversion**: Write a parser that converts real trace to simulator's `TraceKind` events

3. **Comparison tool**: Implement `compare.rs` (already exists at `/home/newton/work/multi_scx/scx1/rust/scx_simulator/crates/scx_simulator/tests/compare.rs`) to diff traces

---

## 5. Existing scx Tooling

### 5.1 In `/home/newton/work/multi_scx/scx1/scripts/`

| Script | Purpose |
|--------|---------|
| `dsq_lat.bt` | DSQ latency tracing |
| `freq_trace.bt` | CPU frequency tracing |
| `process_runqlat.bt` | Per-process runqueue latency |
| `sched_ftrace.py` | Simple ftrace-based sched_switch capture |
| `scxtop.bt` | Interactive DSQ and CPU monitoring |
| `slicesnoop.bt` | Slice allocation tracing |
| `vtime_dist.bt` | Virtual time distribution |

### 5.2 In `/home/newton/work/multi_scx/scx1/rust/scx_simulator/scripts/`

| Script | Purpose |
|--------|---------|
| `trace_scx_ops.bt` | Comprehensive sched_class + kfunc tracing |
| `run_real.sh` | Run workload with scheduler + bpftrace on host |

### 5.3 scxtop MCP Capabilities

scxtop's MCP interface provides:
- Real-time event streaming (`events://stream`)
- Perfetto trace loading and analysis
- CPU/DSQ/process statistics
- Perf profiling with symbolization

---

## 6. Implementation Recommendations

### Phase 1: Basic VM Tracing

1. **Modify `real_run.rs`** to support `--trace` flag
2. **Use `isolcpus`** approach:
   - Pass `--cpus {nr_cpus + 1}` to vng
   - Pass `--append "isolcpus={nr_cpus}"` to isolate last CPU
3. **Run `trace_scx_ops.bt`** pinned to isolated CPU
4. **Copy trace out** of VM via shared filesystem

### Phase 2: Structured Output

1. **Modify `trace_scx_ops.bt`** to output JSON or structured format
2. **Write trace parser** to convert to simulator `TraceKind`
3. **Implement comparison** logic in `compare.rs`

### Phase 3: Perfetto Integration

1. **Use wprof** if available for richer traces
2. **Use scxtop trace** mode for scx-specific metadata
3. **Load both sim and real traces** in ui.perfetto.dev for visual comparison

### Phase 4: Statistical Validation

1. **Compare key metrics**: runtime, latency percentiles, migration counts
2. **Detect divergences**: cases where sim and real behavior differ significantly
3. **Identify simulator gaps**: behaviors present in real but not modeled

---

## 7. Open Questions

1. **BPF overhead**: How much does the tracer affect scheduling decisions? Need to measure with and without tracing.

2. **Clock synchronization**: Simulator uses logical time, real traces use wall clock. How to align for comparison?

3. **Event granularity**: Simulator records ops-level events, but may miss kernel-internal state transitions. Is this sufficient for validation?

4. **sched_ext metadata**: Should we use wprof TrackEvent mode (preserves layer_id, dsq_id) even though scxtop support is incomplete?

5. **VM overhead**: virtme-ng adds virtualization overhead. Does this affect scheduling behavior enough to invalidate comparisons?

---

## References

- wprof repository: https://github.com/facebookexperimental/wprof
- systing repository: https://github.com/josefbacik/systing
- scxtop WPROF_COMPATIBILITY_GUIDE.md: `/home/newton/work/multi_scx/scx1/tools/scxtop/WPROF_COMPATIBILITY_GUIDE.md`
- scxtop PERFETTO_TRACE_ANALYSIS.md: `/home/newton/work/multi_scx/scx1/tools/scxtop/docs/PERFETTO_TRACE_ANALYSIS.md`
- Simulator trace format: `/home/newton/work/multi_scx/scx1/rust/scx_simulator/crates/scx_simulator/src/trace.rs`
- virtme-ng documentation: `vng --help`, `man vng`
