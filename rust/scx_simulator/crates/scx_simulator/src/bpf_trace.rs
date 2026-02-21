//! Parser for real kernel BPF traces captured via trace_scx_ops.bt.
//!
//! This module parses the bpftrace output format produced by `scripts/trace_scx_ops.bt`
//! into structured events that can be analyzed using the same metrics as simulated traces.
//!
//! # Trace Format
//!
//! The bpftrace script produces three types of lines:
//! - `TIMESTAMP_NS cpu=N >> EVENT` - sched_class entry (kprobe)
//! - `TIMESTAMP_NS cpu=N .. EVENT key=value...` - kfunc call + return (fexit)
//! - `TIMESTAMP_NS cpu=N == EVENT key=value...` - lifecycle tracepoint
//!
//! # Example
//!
//! ```text
//! 3176115603 cpu=1 == sched_switch prev_pid=0 prev_comm=swapper/1 prev_state=0 next_pid=2 next_comm=kthreadd
//! 3180712939 cpu=1 == sched_wakeup pid=2 comm=kthreadd target_cpu=1
//! 4921218597 cpu=3 >> select_task_rq
//! 4921220123 cpu=3 .. select_cpu_dfl pid=753 prev_cpu=2 ret=3
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};

use crate::stats::{CpuStats, DistributionStats, TaskStats, TraceStats};
use crate::types::{CpuId, DsqId, Pid, TimeNs};

/// A parsed event from the BPF trace.
#[derive(Debug, Clone)]
pub struct BpfTraceEvent {
    /// Timestamp in nanoseconds (kernel monotonic clock).
    pub time_ns: TimeNs,
    /// CPU on which the event occurred.
    pub cpu: CpuId,
    /// The kind of event.
    pub kind: BpfEventKind,
}

/// The type of BPF trace event.
#[derive(Debug, Clone)]
pub enum BpfEventKind {
    // ----- Sched-class entry points (kprobe >>) -----
    /// select_task_rq entry (ops.select_cpu will be called).
    SelectTaskRq,
    /// enqueue_task entry (ops.runnable then ops.enqueue).
    EnqueueTask,
    /// dequeue_task entry (ops.quiescent or ops.dequeue).
    DequeueTask,
    /// balance entry (ops.dispatch to fill local DSQ).
    Balance,
    /// set_next_task entry (ops.running - task starts executing).
    SetNextTask,
    /// put_prev_task entry (ops.stopping - task stops executing).
    PutPrevTask,
    /// task_tick entry (ops.tick - periodic scheduler tick).
    TaskTick,

    // ----- Kfunc calls (fexit ..) -----
    /// scx_bpf_select_cpu_dfl call completed.
    SelectCpuDfl {
        pid: Pid,
        prev_cpu: CpuId,
        ret_cpu: CpuId,
    },
    /// scx_bpf_dispatch (FIFO insert into a DSQ).
    Dispatch {
        pid: Pid,
        dsq_id: DsqId,
        slice_ns: TimeNs,
        enq_flags: u64,
    },
    /// scx_bpf_dispatch_vtime (vtime-ordered insert).
    DispatchVtime {
        pid: Pid,
        dsq_id: DsqId,
        slice_ns: TimeNs,
        vtime: u64,
        enq_flags: u64,
    },
    /// scx_bpf_pick_idle_cpu call completed.
    PickIdleCpu { flags: u64, ret_cpu: i32 },
    /// scx_bpf_pick_any_cpu call completed.
    PickAnyCpu { flags: u64, ret_cpu: i32 },
    /// scx_bpf_kick_cpu call completed.
    KickCpu { target_cpu: CpuId, flags: u64 },
    /// scx_bpf_task_cpu call completed.
    TaskCpu { pid: Pid, ret_cpu: CpuId },
    /// scx_bpf_consume call completed.
    Consume { dsq_id: DsqId, success: bool },
    /// scx_bpf_create_dsq call completed.
    CreateDsq { dsq_id: DsqId, node: i32, ret: i32 },
    /// scx_bpf_dsq_nr_queued call completed.
    DsqNrQueued { dsq_id: DsqId, ret: i32 },
    /// scx_bpf_task_cgroup call completed.
    TaskCgroup { pid: Pid },
    /// scx_bpf_task_running call completed.
    TaskRunning { pid: Pid, ret: bool },
    /// scx_bpf_reenqueue_local call completed.
    ReenqueueLocal { count: u32 },

    // ----- Lifecycle tracepoints (== sched_*) -----
    /// sched_switch tracepoint - context switch between tasks.
    SchedSwitch {
        prev_pid: Pid,
        prev_comm: String,
        prev_state: i64,
        next_pid: Pid,
        next_comm: String,
    },
    /// sched_wakeup tracepoint - task woken up.
    SchedWakeup {
        pid: Pid,
        comm: String,
        target_cpu: CpuId,
    },

    /// Unknown or unparseable event line.
    Unknown { raw: String },
}

/// A complete BPF trace parsed from the bpftrace output.
#[derive(Debug, Clone, Default)]
pub struct BpfTrace {
    events: Vec<BpfTraceEvent>,
    /// Task names learned from sched_switch/sched_wakeup events.
    task_names: HashMap<Pid, String>,
    /// Minimum timestamp seen (for normalizing to relative time).
    min_time_ns: Option<TimeNs>,
    /// Maximum timestamp seen.
    max_time_ns: Option<TimeNs>,
}

impl BpfTrace {
    /// Parse a BPF trace from a reader.
    pub fn parse<R: Read>(reader: R) -> Result<Self, String> {
        let buf = BufReader::new(reader);
        let mut trace = BpfTrace::default();

        for (line_no, line_result) in buf.lines().enumerate() {
            let line = line_result.map_err(|e| format!("line {}: {}", line_no + 1, e))?;
            let line = line.trim();

            // Skip empty lines and header/footer
            if line.is_empty()
                || line.starts_with("Attached")
                || line.starts_with("Tracing")
                || line.starts_with("Done.")
                || line.starts_with('#')
                || line.starts_with('E')
                || line.starts_with('I')
            {
                continue;
            }

            if let Some(event) = parse_line(line) {
                // Track task names
                match &event.kind {
                    BpfEventKind::SchedSwitch {
                        prev_pid,
                        prev_comm,
                        next_pid,
                        next_comm,
                        ..
                    } => {
                        if prev_pid.0 != 0 && !prev_comm.is_empty() {
                            trace.task_names.insert(*prev_pid, prev_comm.clone());
                        }
                        if next_pid.0 != 0 && !next_comm.is_empty() {
                            trace.task_names.insert(*next_pid, next_comm.clone());
                        }
                    }
                    BpfEventKind::SchedWakeup { pid, comm, .. } => {
                        if pid.0 != 0 && !comm.is_empty() {
                            trace.task_names.insert(*pid, comm.clone());
                        }
                    }
                    _ => {}
                }

                // Track time bounds
                match trace.min_time_ns {
                    Some(min) => trace.min_time_ns = Some(min.min(event.time_ns)),
                    None => trace.min_time_ns = Some(event.time_ns),
                }
                match trace.max_time_ns {
                    Some(max) => trace.max_time_ns = Some(max.max(event.time_ns)),
                    None => trace.max_time_ns = Some(event.time_ns),
                }

                trace.events.push(event);
            }
        }

        Ok(trace)
    }

    /// Parse a BPF trace from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
        Self::parse(file)
    }

    /// Get all events in chronological order.
    pub fn events(&self) -> &[BpfTraceEvent] {
        &self.events
    }

    /// Get the task name for a PID, or None if unknown.
    pub fn task_name(&self, pid: Pid) -> Option<&str> {
        self.task_names.get(&pid).map(String::as_str)
    }

    /// Get the duration of the trace in nanoseconds.
    pub fn duration_ns(&self) -> TimeNs {
        match (self.min_time_ns, self.max_time_ns) {
            (Some(min), Some(max)) => max.saturating_sub(min),
            _ => 0,
        }
    }

    /// Get the number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Compute TraceStats from this BPF trace.
    ///
    /// This extracts the same metrics as `TraceStats::from_trace()` but from
    /// real kernel trace data, enabling comparison between simulated and real.
    pub fn compute_stats(&self) -> TraceStats {
        let mut stats = TraceStats::default();

        // Track state for computing durations
        let mut task_running_since: HashMap<Pid, TimeNs> = HashMap::new();
        let mut task_last_scheduled: HashMap<Pid, TimeNs> = HashMap::new();
        let mut cpu_last_tick: HashMap<CpuId, TimeNs> = HashMap::new();

        // For tracking direct dispatch (select_cpu -> dispatch -> enqueue)
        let mut pending_select_cpu: HashMap<Pid, TimeNs> = HashMap::new();
        let mut pending_direct_dispatch: HashMap<Pid, bool> = HashMap::new();

        for event in &self.events {
            // Ensure CPU entry exists
            stats.cpus.entry(event.cpu).or_insert_with(|| CpuStats {
                cpu: event.cpu,
                ..Default::default()
            });

            match &event.kind {
                BpfEventKind::SchedSwitch {
                    prev_pid,
                    prev_state,
                    next_pid,
                    ..
                } => {
                    // Previous task stopped running
                    if prev_pid.0 != 0 {
                        let task_stats =
                            stats.tasks.entry(*prev_pid).or_insert_with(|| TaskStats {
                                pid: *prev_pid,
                                ..Default::default()
                            });

                        // Compute run duration
                        if let Some(start_time) = task_running_since.remove(prev_pid) {
                            let duration = event.time_ns.saturating_sub(start_time);
                            task_stats.run_duration.add(duration);
                        }

                        // Categorize why it stopped
                        // prev_state: 0=RUNNING (preempted), 1=INTERRUPTIBLE, 2=UNINTERRUPTIBLE
                        match *prev_state {
                            0 => task_stats.preempt_count += 1,
                            1 | 2 => task_stats.sleep_count += 1,
                            _ => {}
                        }
                    }

                    // Next task started running
                    if next_pid.0 != 0 {
                        let task_stats =
                            stats.tasks.entry(*next_pid).or_insert_with(|| TaskStats {
                                pid: *next_pid,
                                ..Default::default()
                            });

                        task_stats.schedule_count += 1;
                        task_running_since.insert(*next_pid, event.time_ns);

                        // Compute inter-arrival time
                        if let Some(last_time) = task_last_scheduled.get(next_pid) {
                            let interval = event.time_ns.saturating_sub(*last_time);
                            task_stats.inter_arrival.add(interval);
                        }
                        task_last_scheduled.insert(*next_pid, event.time_ns);
                    }

                    // Track idle periods (switching to swapper)
                    if next_pid.0 == 0 {
                        let cpu_stats = stats.cpus.get_mut(&event.cpu).unwrap();
                        cpu_stats.idle_count += 1;
                    }
                }

                BpfEventKind::SchedWakeup { .. } => {
                    // Wakeup doesn't directly map to our stats, but could be
                    // used for future latency analysis
                }

                BpfEventKind::SelectTaskRq => {
                    // Mark that we're in select_cpu for potential direct dispatch tracking
                }

                BpfEventKind::SelectCpuDfl { pid, .. } => {
                    pending_select_cpu.insert(*pid, event.time_ns);
                    pending_direct_dispatch.insert(*pid, false);
                }

                BpfEventKind::Balance => {
                    let cpu_stats = stats.cpus.get_mut(&event.cpu).unwrap();
                    cpu_stats.balance_count += 1;
                }

                BpfEventKind::Dispatch { pid, dsq_id, .. } => {
                    stats.dsq_insert_count += 1;

                    // Check if this is a direct dispatch (LOCAL DSQ during select_cpu)
                    if (dsq_id.is_local() || dsq_id.is_local_on())
                        && pending_select_cpu.contains_key(pid)
                    {
                        pending_direct_dispatch.insert(*pid, true);
                    }
                }

                BpfEventKind::DispatchVtime { .. } => {
                    stats.dsq_insert_vtime_count += 1;
                }

                BpfEventKind::EnqueueTask => {
                    // Note: we don't have the pid from the kprobe entry alone
                    // This would need correlation with select_cpu_dfl events
                }

                BpfEventKind::TaskTick => {
                    let cpu_stats = stats.cpus.get_mut(&event.cpu).unwrap();
                    cpu_stats.tick_count += 1;

                    // Compute tick interval
                    if let Some(last_tick) = cpu_last_tick.get(&event.cpu) {
                        let interval = event.time_ns.saturating_sub(*last_tick);
                        cpu_stats.tick_interval.add(interval);
                    }
                    cpu_last_tick.insert(event.cpu, event.time_ns);
                }

                BpfEventKind::KickCpu { .. } => {
                    stats.kick_cpu_count += 1;
                }

                BpfEventKind::Consume { success, .. } => {
                    if *success {
                        stats.dsq_move_to_local_count += 1;
                    }
                }

                _ => {}
            }
        }

        // Clean up any direct dispatch tracking for tasks that had select_cpu
        for (pid, was_direct) in pending_direct_dispatch {
            let task_stats = stats.tasks.entry(pid).or_insert_with(|| TaskStats {
                pid,
                ..Default::default()
            });

            if was_direct {
                task_stats.direct_dispatch_count += 1;
            } else if pending_select_cpu.contains_key(&pid) {
                task_stats.enqueue_count += 1;
            }
        }

        stats.duration_ns = self.duration_ns();
        stats
    }
}

/// Parse a single line from the bpftrace output.
fn parse_line(line: &str) -> Option<BpfTraceEvent> {
    // Format: TIMESTAMP_NS cpu=N {>>|..|==} EVENT [key=value ...]
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() < 4 {
        return None;
    }

    let time_ns: TimeNs = parts[0].parse().ok()?;
    let cpu = parse_cpu(parts[1])?;
    let marker = parts[2];
    let rest = parts[3];

    let kind = match marker {
        ">>" => parse_kprobe_event(rest),
        ".." => parse_kfunc_event(rest),
        "==" => parse_tracepoint_event(rest),
        _ => Some(BpfEventKind::Unknown {
            raw: line.to_string(),
        }),
    }?;

    Some(BpfTraceEvent { time_ns, cpu, kind })
}

/// Parse cpu=N format.
fn parse_cpu(s: &str) -> Option<CpuId> {
    let n = s.strip_prefix("cpu=")?;
    Some(CpuId(n.parse().ok()?))
}

/// Parse kprobe (>>) events.
fn parse_kprobe_event(s: &str) -> Option<BpfEventKind> {
    let event_name = s.split_whitespace().next()?;
    Some(match event_name {
        "select_task_rq" => BpfEventKind::SelectTaskRq,
        "enqueue_task" => BpfEventKind::EnqueueTask,
        "dequeue_task" => BpfEventKind::DequeueTask,
        "balance" => BpfEventKind::Balance,
        "set_next_task" => BpfEventKind::SetNextTask,
        "put_prev_task" => BpfEventKind::PutPrevTask,
        "task_tick" => BpfEventKind::TaskTick,
        _ => BpfEventKind::Unknown { raw: s.to_string() },
    })
}

/// Parse kfunc (..) events.
fn parse_kfunc_event(s: &str) -> Option<BpfEventKind> {
    let mut parts = s.split_whitespace();
    let event_name = parts.next()?;
    let kvs = parse_key_values(parts);

    Some(match event_name {
        "select_cpu_dfl" => BpfEventKind::SelectCpuDfl {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
            prev_cpu: CpuId(
                kvs.get("prev_cpu")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            ),
            ret_cpu: CpuId(kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(0)),
        },
        "dispatch" => BpfEventKind::Dispatch {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
            dsq_id: DsqId(kvs.get("dsq").and_then(|v| v.parse().ok()).unwrap_or(0)),
            slice_ns: kvs.get("slice").and_then(|v| v.parse().ok()).unwrap_or(0),
            enq_flags: kvs
                .get("enq_flags")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        },
        "dispatch_vtime" => BpfEventKind::DispatchVtime {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
            dsq_id: DsqId(kvs.get("dsq").and_then(|v| v.parse().ok()).unwrap_or(0)),
            slice_ns: kvs.get("slice").and_then(|v| v.parse().ok()).unwrap_or(0),
            vtime: kvs.get("vtime").and_then(|v| v.parse().ok()).unwrap_or(0),
            enq_flags: kvs
                .get("enq_flags")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        },
        "pick_idle_cpu" => BpfEventKind::PickIdleCpu {
            flags: kvs.get("flags").and_then(|v| v.parse().ok()).unwrap_or(0),
            ret_cpu: kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(-1),
        },
        "pick_any_cpu" => BpfEventKind::PickAnyCpu {
            flags: kvs.get("flags").and_then(|v| v.parse().ok()).unwrap_or(0),
            ret_cpu: kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(-1),
        },
        "kick_cpu" => BpfEventKind::KickCpu {
            target_cpu: CpuId(kvs.get("target").and_then(|v| v.parse().ok()).unwrap_or(0)),
            flags: kvs.get("flags").and_then(|v| v.parse().ok()).unwrap_or(0),
        },
        "task_cpu" => BpfEventKind::TaskCpu {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
            ret_cpu: CpuId(kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(0)),
        },
        "consume" => BpfEventKind::Consume {
            dsq_id: DsqId(kvs.get("dsq").and_then(|v| v.parse().ok()).unwrap_or(0)),
            success: kvs
                .get("ret")
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0)
                != 0,
        },
        "create_dsq" => BpfEventKind::CreateDsq {
            dsq_id: DsqId(kvs.get("dsq").and_then(|v| v.parse().ok()).unwrap_or(0)),
            node: kvs.get("node").and_then(|v| v.parse().ok()).unwrap_or(-1),
            ret: kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(-1),
        },
        "dsq_nr_queued" => BpfEventKind::DsqNrQueued {
            dsq_id: DsqId(kvs.get("dsq").and_then(|v| v.parse().ok()).unwrap_or(0)),
            ret: kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(0),
        },
        "task_cgroup" => BpfEventKind::TaskCgroup {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
        },
        "task_running" => BpfEventKind::TaskRunning {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
            ret: kvs
                .get("ret")
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0)
                != 0,
        },
        "reenqueue_local" => BpfEventKind::ReenqueueLocal {
            count: kvs.get("ret").and_then(|v| v.parse().ok()).unwrap_or(0),
        },
        _ => BpfEventKind::Unknown { raw: s.to_string() },
    })
}

/// Parse tracepoint (==) events.
fn parse_tracepoint_event(s: &str) -> Option<BpfEventKind> {
    let mut parts = s.split_whitespace();
    let event_name = parts.next()?;
    let kvs = parse_key_values(parts);

    Some(match event_name {
        "sched_switch" => BpfEventKind::SchedSwitch {
            prev_pid: Pid(kvs
                .get("prev_pid")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)),
            prev_comm: kvs.get("prev_comm").unwrap_or(&"").to_string(),
            prev_state: kvs
                .get("prev_state")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            next_pid: Pid(kvs
                .get("next_pid")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)),
            next_comm: kvs.get("next_comm").unwrap_or(&"").to_string(),
        },
        "sched_wakeup" => BpfEventKind::SchedWakeup {
            pid: Pid(kvs.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0)),
            comm: kvs.get("comm").unwrap_or(&"").to_string(),
            target_cpu: CpuId(
                kvs.get("target_cpu")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            ),
        },
        _ => BpfEventKind::Unknown { raw: s.to_string() },
    })
}

/// Parse key=value pairs from the remaining parts of a line.
fn parse_key_values<'a>(parts: impl Iterator<Item = &'a str>) -> HashMap<&'a str, &'a str> {
    parts.filter_map(|kv| kv.split_once('=')).collect()
}

/// Comparison results between two trace sources.
#[derive(Debug, Clone)]
pub struct TraceComparisonResult {
    /// Stats from the baseline (typically real kernel trace).
    pub baseline: TraceStats,
    /// Stats from the comparison (typically simulated trace).
    pub comparison: TraceStats,
    /// Per-metric differences.
    pub differences: TraceDifferences,
}

/// Quantified differences between two traces.
#[derive(Debug, Clone, Default)]
pub struct TraceDifferences {
    /// Difference in total schedule events (comparison - baseline).
    pub schedule_count_diff: i64,
    /// Difference in DSQ insert counts.
    pub dsq_insert_diff: i64,
    /// Difference in kick_cpu counts.
    pub kick_cpu_diff: i64,
    /// Difference in balance call counts.
    pub balance_diff: i64,
    /// Difference in idle event counts.
    pub idle_diff: i64,
    /// Mean run duration difference (as percentage).
    pub run_duration_mean_diff_pct: f64,
    /// Run duration variance ratio (comparison / baseline).
    pub run_duration_variance_ratio: f64,
    /// Tick interval variance ratio.
    pub tick_interval_variance_ratio: f64,
}

impl TraceComparisonResult {
    /// Compare a BPF trace (baseline) with simulated TraceStats.
    pub fn compare_bpf_vs_sim(bpf_trace: &BpfTrace, sim_stats: &TraceStats) -> Self {
        let baseline = bpf_trace.compute_stats();
        let comparison = sim_stats.clone();
        let differences = compute_differences(&baseline, &comparison);

        Self {
            baseline,
            comparison,
            differences,
        }
    }

    /// Compare two TraceStats directly.
    pub fn compare_stats(baseline: TraceStats, comparison: TraceStats) -> Self {
        let differences = compute_differences(&baseline, &comparison);
        Self {
            baseline,
            comparison,
            differences,
        }
    }

    /// Print a comparison report to stderr.
    pub fn print_report(&self) {
        eprintln!("\n=== Real vs Simulated Trace Comparison ===\n");

        eprintln!("--- Duration ---");
        eprintln!(
            "  Baseline (real):    {:.3}ms",
            self.baseline.duration_ns as f64 / 1_000_000.0
        );
        eprintln!(
            "  Comparison (sim):   {:.3}ms",
            self.comparison.duration_ns as f64 / 1_000_000.0
        );
        eprintln!();

        eprintln!("--- Event Counts ---");
        let total_baseline_schedules: usize =
            self.baseline.tasks.values().map(|t| t.schedule_count).sum();
        let total_comparison_schedules: usize = self
            .comparison
            .tasks
            .values()
            .map(|t| t.schedule_count)
            .sum();
        eprintln!(
            "  Schedule events:    {} vs {} ({:+})",
            total_baseline_schedules,
            total_comparison_schedules,
            self.differences.schedule_count_diff
        );
        eprintln!(
            "  DSQ inserts:        {} vs {} ({:+})",
            self.baseline.dsq_insert_count,
            self.comparison.dsq_insert_count,
            self.differences.dsq_insert_diff
        );
        eprintln!(
            "  Kick CPU calls:     {} vs {} ({:+})",
            self.baseline.kick_cpu_count,
            self.comparison.kick_cpu_count,
            self.differences.kick_cpu_diff
        );
        eprintln!();

        eprintln!("--- Run Duration Statistics ---");
        for (pid, baseline_task) in &self.baseline.tasks {
            if let Some(comparison_task) = self.comparison.tasks.get(pid) {
                if baseline_task.run_duration.count > 0 && comparison_task.run_duration.count > 0 {
                    eprintln!("  Task PID={}:", pid.0);
                    eprintln!(
                        "    Mean: {:.3}ms (real) vs {:.3}ms (sim)",
                        baseline_task.run_duration.mean() / 1_000_000.0,
                        comparison_task.run_duration.mean() / 1_000_000.0
                    );
                    eprintln!(
                        "    Stddev: {:.3}ms (real) vs {:.3}ms (sim)",
                        baseline_task.run_duration.stddev() / 1_000_000.0,
                        comparison_task.run_duration.stddev() / 1_000_000.0
                    );
                }
            }
        }
        eprintln!();

        eprintln!("--- Realism Assessment ---");
        if self.differences.run_duration_variance_ratio < 0.1 {
            eprintln!(
                "  [!] Run duration variance is {:.1}x lower in simulation",
                1.0 / self.differences.run_duration_variance_ratio.max(0.001)
            );
            eprintln!("      Real systems have more timing jitter from interrupts/overhead");
        }
        if self.differences.tick_interval_variance_ratio < 0.1 {
            eprintln!(
                "  [!] Tick interval variance is {:.1}x lower in simulation",
                1.0 / self.differences.tick_interval_variance_ratio.max(0.001)
            );
            eprintln!("      Real tick intervals vary due to system load");
        }
        eprintln!();
    }
}

fn compute_differences(baseline: &TraceStats, comparison: &TraceStats) -> TraceDifferences {
    let total_baseline_schedules: i64 = baseline
        .tasks
        .values()
        .map(|t| t.schedule_count as i64)
        .sum();
    let total_comparison_schedules: i64 = comparison
        .tasks
        .values()
        .map(|t| t.schedule_count as i64)
        .sum();

    let total_baseline_balance: i64 = baseline.cpus.values().map(|c| c.balance_count as i64).sum();
    let total_comparison_balance: i64 = comparison
        .cpus
        .values()
        .map(|c| c.balance_count as i64)
        .sum();

    let total_baseline_idle: i64 = baseline.cpus.values().map(|c| c.idle_count as i64).sum();
    let total_comparison_idle: i64 = comparison.cpus.values().map(|c| c.idle_count as i64).sum();

    // Compute aggregate run duration stats
    let mut baseline_run_duration = DistributionStats::new();
    let mut comparison_run_duration = DistributionStats::new();
    for ts in baseline.tasks.values() {
        if ts.run_duration.count > 0 {
            // Aggregate the mean as a representative value
            baseline_run_duration.add(ts.run_duration.mean() as TimeNs);
        }
    }
    for ts in comparison.tasks.values() {
        if ts.run_duration.count > 0 {
            comparison_run_duration.add(ts.run_duration.mean() as TimeNs);
        }
    }

    let run_duration_mean_diff_pct = if baseline_run_duration.mean() > 0.0 {
        (comparison_run_duration.mean() - baseline_run_duration.mean())
            / baseline_run_duration.mean()
            * 100.0
    } else {
        0.0
    };

    let run_duration_variance_ratio = if baseline_run_duration.stddev() > 0.0 {
        comparison_run_duration.stddev() / baseline_run_duration.stddev()
    } else {
        1.0
    };

    // Tick interval variance
    let mut baseline_tick_variance = DistributionStats::new();
    let mut comparison_tick_variance = DistributionStats::new();
    for cs in baseline.cpus.values() {
        if cs.tick_interval.count > 0 {
            baseline_tick_variance.add(cs.tick_interval.stddev() as TimeNs);
        }
    }
    for cs in comparison.cpus.values() {
        if cs.tick_interval.count > 0 {
            comparison_tick_variance.add(cs.tick_interval.stddev() as TimeNs);
        }
    }

    let tick_interval_variance_ratio = if baseline_tick_variance.mean() > 0.0 {
        comparison_tick_variance.mean() / baseline_tick_variance.mean()
    } else {
        1.0
    };

    TraceDifferences {
        schedule_count_diff: total_comparison_schedules - total_baseline_schedules,
        dsq_insert_diff: comparison.dsq_insert_count as i64 - baseline.dsq_insert_count as i64,
        kick_cpu_diff: comparison.kick_cpu_count as i64 - baseline.kick_cpu_count as i64,
        balance_diff: total_comparison_balance - total_baseline_balance,
        idle_diff: total_comparison_idle - total_baseline_idle,
        run_duration_mean_diff_pct,
        run_duration_variance_ratio,
        tick_interval_variance_ratio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TRACE: &str = r#"
Attached 24 probes
Tracing sched_ext ops + kfuncs on CPUs 0-3. Ctrl-C to stop.

1000000 cpu=0 == sched_switch prev_pid=0 prev_comm=swapper/0 prev_state=0 next_pid=100 next_comm=worker-0
2000000 cpu=0 == sched_switch prev_pid=100 prev_comm=worker-0 prev_state=0 next_pid=0 next_comm=swapper/0
2500000 cpu=1 == sched_wakeup pid=100 comm=worker-0 target_cpu=1
3000000 cpu=1 == sched_switch prev_pid=0 prev_comm=swapper/1 prev_state=0 next_pid=100 next_comm=worker-0
4000000 cpu=1 >> task_tick
5000000 cpu=1 == sched_switch prev_pid=100 prev_comm=worker-0 prev_state=1 next_pid=0 next_comm=swapper/1

Done. Captured ops + kfunc trace.
"#;

    #[test]
    fn test_parse_sample_trace() {
        let trace = BpfTrace::parse(SAMPLE_TRACE.as_bytes()).unwrap();
        assert!(!trace.is_empty());
        assert!(trace.len() >= 5);
    }

    #[test]
    fn test_task_names_extracted() {
        let trace = BpfTrace::parse(SAMPLE_TRACE.as_bytes()).unwrap();
        assert_eq!(trace.task_name(Pid(100)), Some("worker-0"));
    }

    #[test]
    fn test_duration_computed() {
        let trace = BpfTrace::parse(SAMPLE_TRACE.as_bytes()).unwrap();
        // From 1_000_000 to 5_000_000 = 4_000_000 ns
        assert_eq!(trace.duration_ns(), 4_000_000);
    }

    #[test]
    fn test_compute_stats() {
        let trace = BpfTrace::parse(SAMPLE_TRACE.as_bytes()).unwrap();
        let stats = trace.compute_stats();

        // Should have stats for task 100
        assert!(stats.tasks.contains_key(&Pid(100)));
        let task = &stats.tasks[&Pid(100)];
        assert_eq!(task.schedule_count, 2); // Scheduled twice
        assert_eq!(task.preempt_count, 1); // Once with prev_state=0
        assert_eq!(task.sleep_count, 1); // Once with prev_state=1

        // CPU 1 should have 1 tick
        assert!(stats.cpus.contains_key(&CpuId(1)));
        let cpu1 = &stats.cpus[&CpuId(1)];
        assert_eq!(cpu1.tick_count, 1);
    }

    #[test]
    fn test_parse_kfunc_events() {
        let trace_data = r#"
1000000 cpu=0 .. select_cpu_dfl pid=123 prev_cpu=1 ret=0
2000000 cpu=0 .. dispatch pid=123 dsq=9223372036854775810 slice=5000000 enq_flags=0
3000000 cpu=0 .. kick_cpu target=1 flags=2
"#;
        let trace = BpfTrace::parse(trace_data.as_bytes()).unwrap();
        assert_eq!(trace.len(), 3);

        match &trace.events()[0].kind {
            BpfEventKind::SelectCpuDfl {
                pid,
                prev_cpu,
                ret_cpu,
            } => {
                assert_eq!(pid.0, 123);
                assert_eq!(prev_cpu.0, 1);
                assert_eq!(ret_cpu.0, 0);
            }
            other => panic!("unexpected event: {:?}", other),
        }

        match &trace.events()[1].kind {
            BpfEventKind::Dispatch { pid, dsq_id, .. } => {
                assert_eq!(pid.0, 123);
                assert!(dsq_id.is_local()); // SCX_DSQ_LOCAL = 0x8000000000000002
            }
            other => panic!("unexpected event: {:?}", other),
        }

        match &trace.events()[2].kind {
            BpfEventKind::KickCpu { target_cpu, flags } => {
                assert_eq!(target_cpu.0, 1);
                assert_eq!(*flags, 2);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn test_comparison_result() {
        let trace = BpfTrace::parse(SAMPLE_TRACE.as_bytes()).unwrap();
        let bpf_stats = trace.compute_stats();

        // Create a simple simulated stats for comparison
        let mut sim_stats = TraceStats::default();
        sim_stats.duration_ns = 4_000_000;
        sim_stats.tasks.insert(
            Pid(100),
            TaskStats {
                pid: Pid(100),
                schedule_count: 2,
                ..Default::default()
            },
        );

        let result = TraceComparisonResult::compare_stats(bpf_stats, sim_stats);
        assert_eq!(result.differences.schedule_count_diff, 0);
    }
}
