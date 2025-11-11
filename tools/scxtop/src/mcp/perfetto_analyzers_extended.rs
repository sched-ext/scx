// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Extended scheduler analyses: task states, preemption, wakeup chains, latency breakdown

use super::perfetto_parser::{Percentiles, PerfettoTrace};
use perfetto_protos::ftrace_event::ftrace_event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Aggregation mode for task state analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationMode {
    /// Show per-thread statistics (TID level)
    PerThread,
    /// Aggregate by process (TGID level) - combines all threads in a process
    PerProcess,
}

impl Default for AggregationMode {
    fn default() -> Self {
        Self::PerThread
    }
}

/// Analyzes task state transitions and time spent in each state
pub struct TaskStateAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl TaskStateAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze task states for all or specific process/thread
    pub fn analyze_task_states(
        &self,
        pid_filter: Option<i32>,
        aggregation_mode: AggregationMode,
    ) -> Vec<TaskStateStats> {
        let mut task_trackers: HashMap<i32, TaskStateTracker> = HashMap::new();

        // Get trace duration for final stats calculation
        let (start_ts, end_ts) = self.trace.time_range();
        let trace_duration_ns = end_ts.saturating_sub(start_ts);

        // Collect all events from all CPUs and sort by timestamp
        // This is critical - processing events per-CPU causes time to jump backwards
        // for threads that migrate between CPUs
        let mut all_events = Vec::new();
        for cpu in 0..self.trace.num_cpus() {
            let cpu_events = self.trace.get_events_by_cpu(cpu as u32);
            all_events.extend(cpu_events.iter());
        }

        // Sort all events by timestamp
        all_events.sort_by_key(|e| e.event.timestamp.unwrap_or(0));

        // Process events in chronological order
        for event_with_idx in all_events {
            if let Some(ts) = event_with_idx.event.timestamp {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::SchedSwitch(switch)) => {
                        // Handle prev task being scheduled off
                        if let (Some(prev_pid), Some(prev_state)) =
                            (switch.prev_pid, switch.prev_state)
                        {
                            if prev_pid > 0 {
                                let tracker = task_trackers.entry(prev_pid).or_insert_with(|| {
                                    TaskStateTracker::new(
                                        prev_pid,
                                        switch.prev_comm.clone().unwrap_or_default(),
                                    )
                                });

                                // Classify task state when scheduled off
                                let new_state = classify_task_state(prev_state);
                                tracker.enter_state(new_state, ts);

                                // Check if preemption was voluntary
                                if prev_state == 0 {
                                    tracker.involuntary_switches += 1;
                                } else {
                                    tracker.voluntary_switches += 1;
                                }
                            }
                        }

                        // Handle next task being scheduled on
                        if let Some(next_pid) = switch.next_pid {
                            if next_pid > 0 {
                                let tracker = task_trackers.entry(next_pid).or_insert_with(|| {
                                    TaskStateTracker::new(
                                        next_pid,
                                        switch.next_comm.clone().unwrap_or_default(),
                                    )
                                });

                                // Calculate scheduler latency if we have a wakeup timestamp
                                if let Some(wakeup_ts) = tracker.last_wakeup_ts {
                                    let latency = ts.saturating_sub(wakeup_ts);
                                    tracker.scheduler_latencies.push(latency);
                                }

                                // Enter running state
                                tracker.enter_state(TaskState::Running, ts);
                                tracker.last_wakeup_ts = None;
                            }
                        }
                    }
                    Some(ftrace_event::Event::SchedWakeup(wakeup)) => {
                        if let Some(pid) = wakeup.pid {
                            if pid > 0 {
                                let tracker = task_trackers.entry(pid).or_insert_with(|| {
                                    TaskStateTracker::new(
                                        pid,
                                        wakeup.comm.clone().unwrap_or_default(),
                                    )
                                });

                                // Enter runnable state
                                tracker.enter_state(TaskState::Runnable, ts);
                                tracker.last_wakeup_ts = Some(ts);
                            }
                        }
                    }
                    Some(ftrace_event::Event::SchedWaking(waking)) => {
                        if let Some(pid) = waking.pid {
                            if pid > 0 {
                                let tracker = task_trackers.entry(pid).or_insert_with(|| {
                                    TaskStateTracker::new(
                                        pid,
                                        waking.comm.clone().unwrap_or_default(),
                                    )
                                });

                                // Enter runnable state
                                tracker.enter_state(TaskState::Runnable, ts);
                                tracker.last_wakeup_ts = Some(ts);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Convert to stats with TGID information
        let thread_stats: Vec<TaskStateStats> = task_trackers
            .into_iter()
            .filter(|(p, _)| pid_filter.is_none_or(|filter| &filter == p))
            .map(|(tid, tracker)| {
                let tgid = self.trace.get_tgid_for_tid(tid);
                tracker.into_stats(end_ts, trace_duration_ns, tgid)
            })
            .collect();

        // If aggregating by process, combine all threads for each TGID
        let stats = match aggregation_mode {
            AggregationMode::PerThread => thread_stats,
            AggregationMode::PerProcess => Self::aggregate_by_tgid(thread_stats, trace_duration_ns),
        };

        let mut sorted_stats = stats;
        sorted_stats.sort_by(|a, b| b.total_time_ns.cmp(&a.total_time_ns));
        sorted_stats
    }

    /// Aggregate thread stats by TGID (process ID)
    fn aggregate_by_tgid(
        thread_stats: Vec<TaskStateStats>,
        trace_duration_ns: u64,
    ) -> Vec<TaskStateStats> {
        let mut process_map: HashMap<i32, Vec<TaskStateStats>> = HashMap::new();

        // Group threads by TGID
        for stat in thread_stats {
            let tgid = stat.tgid.unwrap_or(stat.pid);
            process_map.entry(tgid).or_default().push(stat);
        }

        // Aggregate stats for each process
        process_map
            .into_iter()
            .map(|(tgid, threads)| {
                let thread_count = threads.len();
                let comm = threads[0].comm.clone();

                // Sum up all times across threads
                let mut running_time_ns = 0u64;
                let mut runnable_time_ns = 0u64;
                let mut sleeping_time_ns = 0u64;
                let mut blocked_time_ns = 0u64;
                let mut voluntary_switches = 0usize;
                let mut involuntary_switches = 0usize;
                // Note: We can't reconstruct individual latencies from aggregated stats
                // So we'll use weighted average latencies from the threads instead

                for thread in &threads {
                    running_time_ns += thread.running_time_ns;
                    runnable_time_ns += thread.runnable_time_ns;
                    sleeping_time_ns += thread.sleeping_time_ns;
                    blocked_time_ns += thread.blocked_time_ns;
                    voluntary_switches += thread.voluntary_switches;
                    involuntary_switches += thread.involuntary_switches;
                    // Note: We can't reconstruct individual latencies from aggregated stats
                    // So we'll use average latencies from the threads
                }

                let total_time_ns =
                    running_time_ns + runnable_time_ns + sleeping_time_ns + blocked_time_ns;
                let total_time_clamped = total_time_ns.min(trace_duration_ns * thread_count as u64);

                // Calculate aggregate scheduler latency (weighted average)
                let mut total_latency_weight = 0u64;
                let mut weighted_avg_latency = 0f64;
                let mut weighted_p50_latency = 0f64;
                let mut weighted_p95_latency = 0f64;
                let mut weighted_p99_latency = 0f64;

                for thread in &threads {
                    let weight = thread.total_time_ns;
                    total_latency_weight += weight;
                    weighted_avg_latency += thread.avg_scheduler_latency_ns as f64 * weight as f64;
                    weighted_p50_latency += thread.p50_scheduler_latency_ns as f64 * weight as f64;
                    weighted_p95_latency += thread.p95_scheduler_latency_ns as f64 * weight as f64;
                    weighted_p99_latency += thread.p99_scheduler_latency_ns as f64 * weight as f64;
                }

                let avg_latency = if total_latency_weight > 0 {
                    (weighted_avg_latency / total_latency_weight as f64) as u64
                } else {
                    0
                };
                let p50_latency = if total_latency_weight > 0 {
                    (weighted_p50_latency / total_latency_weight as f64) as u64
                } else {
                    0
                };
                let p95_latency = if total_latency_weight > 0 {
                    (weighted_p95_latency / total_latency_weight as f64) as u64
                } else {
                    0
                };
                let p99_latency = if total_latency_weight > 0 {
                    (weighted_p99_latency / total_latency_weight as f64) as u64
                } else {
                    0
                };

                TaskStateStats {
                    pid: tgid,
                    tgid: Some(tgid),
                    thread_count,
                    comm,
                    running_time_ns,
                    runnable_time_ns,
                    sleeping_time_ns,
                    blocked_time_ns,
                    total_time_ns: total_time_clamped,
                    running_percent: if total_time_clamped > 0 {
                        (running_time_ns as f64 / total_time_clamped as f64) * 100.0
                    } else {
                        0.0
                    },
                    runnable_percent: if total_time_clamped > 0 {
                        (runnable_time_ns as f64 / total_time_clamped as f64) * 100.0
                    } else {
                        0.0
                    },
                    sleeping_percent: if total_time_clamped > 0 {
                        (sleeping_time_ns as f64 / total_time_clamped as f64) * 100.0
                    } else {
                        0.0
                    },
                    blocked_percent: if total_time_clamped > 0 {
                        (blocked_time_ns as f64 / total_time_clamped as f64) * 100.0
                    } else {
                        0.0
                    },
                    voluntary_switches,
                    involuntary_switches,
                    avg_scheduler_latency_ns: avg_latency,
                    p50_scheduler_latency_ns: p50_latency,
                    p95_scheduler_latency_ns: p95_latency,
                    p99_scheduler_latency_ns: p99_latency,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskState {
    Running,
    Runnable,
    Sleeping,
    Blocked,
}

fn classify_task_state(state: i64) -> TaskState {
    if state == 0 {
        TaskState::Runnable
    } else if state & 0x0001 != 0 || state & 0x0080 != 0 {
        TaskState::Sleeping
    } else if state & 0x0002 != 0 {
        TaskState::Blocked
    } else {
        TaskState::Sleeping
    }
}

struct TaskStateTracker {
    pid: i32,
    comm: String,
    // Current state - only one state can be active at a time
    current_state: Option<TaskState>,
    current_state_since: Option<u64>,
    // Accumulated times
    running_time_ns: u64,
    runnable_time_ns: u64,
    sleeping_time_ns: u64,
    blocked_time_ns: u64,
    scheduler_latencies: Vec<u64>,
    voluntary_switches: usize,
    involuntary_switches: usize,
    // Track last wakeup time for latency calculation
    last_wakeup_ts: Option<u64>,
}

impl TaskStateTracker {
    fn new(pid: i32, comm: String) -> Self {
        Self {
            pid,
            comm,
            current_state: None,
            current_state_since: None,
            running_time_ns: 0,
            runnable_time_ns: 0,
            sleeping_time_ns: 0,
            blocked_time_ns: 0,
            scheduler_latencies: Vec::new(),
            voluntary_switches: 0,
            involuntary_switches: 0,
            last_wakeup_ts: None,
        }
    }

    /// Exit current state and accumulate time
    fn exit_current_state(&mut self, ts: u64) {
        if let (Some(state), Some(since)) = (self.current_state, self.current_state_since) {
            let duration = ts.saturating_sub(since);
            match state {
                TaskState::Running => self.running_time_ns += duration,
                TaskState::Runnable => self.runnable_time_ns += duration,
                TaskState::Sleeping => self.sleeping_time_ns += duration,
                TaskState::Blocked => self.blocked_time_ns += duration,
            }
        }
        self.current_state = None;
        self.current_state_since = None;
    }

    /// Enter a new state (exits current state first)
    fn enter_state(&mut self, state: TaskState, ts: u64) {
        // Exit current state before entering new one
        self.exit_current_state(ts);

        self.current_state = Some(state);
        self.current_state_since = Some(ts);
    }

    fn into_stats(
        mut self,
        trace_end_ts: u64,
        trace_duration_ns: u64,
        tgid: Option<i32>,
    ) -> TaskStateStats {
        // If still in a state at end of trace, close it out
        if self.current_state.is_some() {
            self.exit_current_state(trace_end_ts);
        }

        let total_time = self.running_time_ns
            + self.runnable_time_ns
            + self.sleeping_time_ns
            + self.blocked_time_ns;

        // Validation: total time should not exceed trace duration
        // If it does, it indicates a bug in our accounting
        let total_time_clamped = total_time.min(trace_duration_ns);

        let scheduler_latency_percentiles = if !self.scheduler_latencies.is_empty() {
            PerfettoTrace::calculate_percentiles(&self.scheduler_latencies)
        } else {
            Percentiles::default()
        };

        TaskStateStats {
            pid: self.pid,
            tgid,
            thread_count: 1, // Single thread
            comm: self.comm,
            running_time_ns: self.running_time_ns,
            runnable_time_ns: self.runnable_time_ns,
            sleeping_time_ns: self.sleeping_time_ns,
            blocked_time_ns: self.blocked_time_ns,
            total_time_ns: total_time_clamped,
            running_percent: if total_time_clamped > 0 {
                (self.running_time_ns as f64 / total_time_clamped as f64) * 100.0
            } else {
                0.0
            },
            runnable_percent: if total_time_clamped > 0 {
                (self.runnable_time_ns as f64 / total_time_clamped as f64) * 100.0
            } else {
                0.0
            },
            sleeping_percent: if total_time_clamped > 0 {
                (self.sleeping_time_ns as f64 / total_time_clamped as f64) * 100.0
            } else {
                0.0
            },
            blocked_percent: if total_time_clamped > 0 {
                (self.blocked_time_ns as f64 / total_time_clamped as f64) * 100.0
            } else {
                0.0
            },
            voluntary_switches: self.voluntary_switches,
            involuntary_switches: self.involuntary_switches,
            avg_scheduler_latency_ns: scheduler_latency_percentiles.mean as u64,
            p50_scheduler_latency_ns: scheduler_latency_percentiles.median,
            p95_scheduler_latency_ns: scheduler_latency_percentiles.p95,
            p99_scheduler_latency_ns: scheduler_latency_percentiles.p99,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStateStats {
    /// TID (thread ID) for per-thread stats, or TGID for per-process stats
    pub pid: i32,
    /// TGID (thread group ID / process ID) - same as pid for per-thread, different for per-process
    pub tgid: Option<i32>,
    /// Number of threads aggregated (1 for per-thread, >1 for per-process)
    pub thread_count: usize,
    pub comm: String,
    pub running_time_ns: u64,
    pub runnable_time_ns: u64,
    pub sleeping_time_ns: u64,
    pub blocked_time_ns: u64,
    pub total_time_ns: u64,
    pub running_percent: f64,
    pub runnable_percent: f64,
    pub sleeping_percent: f64,
    pub blocked_percent: f64,
    pub voluntary_switches: usize,
    pub involuntary_switches: usize,
    pub avg_scheduler_latency_ns: u64,
    pub p50_scheduler_latency_ns: u64,
    pub p95_scheduler_latency_ns: u64,
    pub p99_scheduler_latency_ns: u64,
}

/// Analyzes preemption patterns
pub struct PreemptionAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl PreemptionAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze preemption patterns for all or specific process
    pub fn analyze_preemptions(&self, pid_filter: Option<i32>) -> Vec<PreemptionStats> {
        let mut preemption_data: HashMap<i32, PreemptionTracker> = HashMap::new();

        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::SchedSwitch(switch)) = &event_with_idx.event.event
                {
                    if let (Some(prev_pid), Some(prev_state), Some(next_pid)) =
                        (switch.prev_pid, switch.prev_state, switch.next_pid)
                    {
                        // Only count involuntary preemptions (state == 0 means still runnable)
                        if prev_state == 0 && prev_pid > 0 && next_pid > 0 {
                            let tracker = preemption_data.entry(prev_pid).or_insert_with(|| {
                                PreemptionTracker::new(
                                    prev_pid,
                                    switch.prev_comm.clone().unwrap_or_default(),
                                )
                            });

                            tracker.preempted_count += 1;
                            tracker
                                .preempted_by
                                .entry(next_pid)
                                .or_insert_with(|| PreemptorInfo {
                                    pid: next_pid,
                                    comm: switch.next_comm.clone().unwrap_or_default(),
                                    count: 0,
                                })
                                .count += 1;
                        }
                    }
                }
            }
        }

        let mut stats: Vec<PreemptionStats> = preemption_data
            .into_iter()
            .filter(|(p, _)| pid_filter.is_none_or(|filter| &filter == p))
            .map(|(_, tracker)| tracker.into_stats())
            .collect();

        stats.sort_by(|a, b| b.preempted_count.cmp(&a.preempted_count));
        stats
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreemptionStats {
    pub pid: i32,
    pub comm: String,
    pub preempted_count: usize,
    pub preempted_by: Vec<PreemptorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreemptorInfo {
    pub pid: i32,
    pub comm: String,
    pub count: usize,
}

/// Analyzes wakeup chains (cascading task dependencies)
pub struct WakeupChainDetector {
    trace: Arc<PerfettoTrace>,
}

impl WakeupChainDetector {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Find critical wakeup chains (A wakes B wakes C...)
    pub fn find_wakeup_chains(&self, limit: usize) -> Vec<WakeupChain> {
        let mut wakeup_map: HashMap<i32, Vec<WakeupChainEvent>> = HashMap::new();
        let mut schedule_times: HashMap<i32, u64> = HashMap::new();

        // Collect all wakeups and schedules
        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ts) = event_with_idx.event.timestamp {
                    match &event_with_idx.event.event {
                        Some(ftrace_event::Event::SchedWakeup(wakeup)) => {
                            if let (Some(wakee_pid), Some(waker_pid)) =
                                (wakeup.pid, event_with_idx.event.pid)
                            {
                                wakeup_map
                                    .entry(wakee_pid)
                                    .or_default()
                                    .push(WakeupChainEvent {
                                        wakee_pid,
                                        waker_pid: waker_pid as i32,
                                        wakee_comm: wakeup.comm.clone().unwrap_or_default(),
                                        waker_comm: String::new(),
                                        wakeup_ts: ts,
                                        schedule_ts: None,
                                    });
                            }
                        }
                        Some(ftrace_event::Event::SchedSwitch(switch)) => {
                            if let Some(next_pid) = switch.next_pid {
                                schedule_times.insert(next_pid, ts);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Match wakeups to schedules
        for wakeup_list in wakeup_map.values_mut() {
            for wakeup_event in wakeup_list {
                if let Some(&schedule_ts) = schedule_times.get(&wakeup_event.wakee_pid) {
                    if schedule_ts >= wakeup_event.wakeup_ts {
                        wakeup_event.schedule_ts = Some(schedule_ts);
                    }
                }
            }
        }

        // Build chains
        let mut chains = Vec::new();
        let mut visited = std::collections::HashSet::new();

        for (wakee_pid, wakeups) in &wakeup_map {
            if visited.contains(wakee_pid) {
                continue;
            }

            for wakeup in wakeups {
                let mut chain = vec![wakeup.clone()];
                let mut current_waker = wakeup.waker_pid;
                visited.insert(*wakee_pid);

                // Follow chain backwards
                for _ in 0..10 {
                    if let Some(waker_wakeups) = wakeup_map.get(&current_waker) {
                        if let Some(waker_wakeup) = waker_wakeups
                            .iter()
                            .filter(|w| w.wakeup_ts <= wakeup.wakeup_ts)
                            .max_by_key(|w| w.wakeup_ts)
                        {
                            chain.push(waker_wakeup.clone());
                            current_waker = waker_wakeup.waker_pid;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if chain.len() > 1 {
                    chain.reverse();

                    let total_latency: u64 = chain
                        .iter()
                        .filter_map(|e| e.schedule_ts.map(|s| s.saturating_sub(e.wakeup_ts)))
                        .sum();

                    let chain_len = chain.len();
                    chains.push(WakeupChain {
                        chain,
                        total_latency_ns: total_latency,
                        chain_length: chain_len,
                        criticality_score: (chain_len as f64)
                            * (total_latency as f64 / 1_000_000.0),
                    });
                }
            }
        }

        chains.sort_by(|a, b| {
            b.criticality_score
                .partial_cmp(&a.criticality_score)
                .unwrap()
        });

        chains.into_iter().take(limit).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeupChain {
    pub chain: Vec<WakeupChainEvent>,
    pub total_latency_ns: u64,
    pub chain_length: usize,
    pub criticality_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeupChainEvent {
    pub wakee_pid: i32,
    pub waker_pid: i32,
    pub wakee_comm: String,
    pub waker_comm: String,
    pub wakeup_ts: u64,
    pub schedule_ts: Option<u64>,
}

/// Analyzes scheduling latency breakdown
pub struct SchedulingLatencyBreakdown {
    trace: Arc<PerfettoTrace>,
}

impl SchedulingLatencyBreakdown {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Break down wakeup latency into stages
    pub fn analyze_latency_stages(&self) -> LatencyBreakdownStats {
        let mut waking_to_wakeup: Vec<u64> = Vec::new();
        let mut wakeup_to_schedule: Vec<u64> = Vec::new();
        let mut waking_times: HashMap<i32, u64> = HashMap::new();
        let mut wakeup_times: HashMap<i32, u64> = HashMap::new();

        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ts) = event_with_idx.event.timestamp {
                    match &event_with_idx.event.event {
                        Some(ftrace_event::Event::SchedWaking(waking)) => {
                            if let Some(pid) = waking.pid {
                                waking_times.insert(pid, ts);
                            }
                        }
                        Some(ftrace_event::Event::SchedWakeup(wakeup)) => {
                            if let Some(pid) = wakeup.pid {
                                if let Some(waking_ts) = waking_times.get(&pid) {
                                    if ts >= *waking_ts {
                                        waking_to_wakeup.push(ts - waking_ts);
                                    }
                                }
                                wakeup_times.insert(pid, ts);
                            }
                        }
                        Some(ftrace_event::Event::SchedSwitch(switch)) => {
                            if let Some(next_pid) = switch.next_pid {
                                if let Some(wakeup_ts) = wakeup_times.remove(&next_pid) {
                                    if ts >= wakeup_ts {
                                        wakeup_to_schedule.push(ts - wakeup_ts);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let waking_percentiles = if !waking_to_wakeup.is_empty() {
            PerfettoTrace::calculate_percentiles(&waking_to_wakeup)
        } else {
            Percentiles::default()
        };

        let wakeup_percentiles = if !wakeup_to_schedule.is_empty() {
            PerfettoTrace::calculate_percentiles(&wakeup_to_schedule)
        } else {
            Percentiles::default()
        };

        let total_avg = waking_percentiles.mean + wakeup_percentiles.mean;
        let waking_percent = if total_avg > 0.0 {
            (waking_percentiles.mean / total_avg) * 100.0
        } else {
            0.0
        };

        LatencyBreakdownStats {
            waking_to_wakeup: LatencyStageStats {
                count: waking_percentiles.count,
                avg_ns: waking_percentiles.mean as u64,
                p50_ns: waking_percentiles.median,
                p95_ns: waking_percentiles.p95,
                p99_ns: waking_percentiles.p99,
                percent_of_total: waking_percent,
            },
            wakeup_to_schedule: LatencyStageStats {
                count: wakeup_percentiles.count,
                avg_ns: wakeup_percentiles.mean as u64,
                p50_ns: wakeup_percentiles.median,
                p95_ns: wakeup_percentiles.p95,
                p99_ns: wakeup_percentiles.p99,
                percent_of_total: 100.0 - waking_percent,
            },
            total_avg_latency_ns: total_avg as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBreakdownStats {
    pub waking_to_wakeup: LatencyStageStats,
    pub wakeup_to_schedule: LatencyStageStats,
    pub total_avg_latency_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStageStats {
    pub count: usize,
    pub avg_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub percent_of_total: f64,
}

struct PreemptionTracker {
    pid: i32,
    comm: String,
    preempted_count: usize,
    preempted_by: HashMap<i32, PreemptorInfo>,
}

impl PreemptionTracker {
    fn new(pid: i32, comm: String) -> Self {
        Self {
            pid,
            comm,
            preempted_count: 0,
            preempted_by: HashMap::new(),
        }
    }

    fn into_stats(self) -> PreemptionStats {
        let mut preempted_by: Vec<PreemptorInfo> = self.preempted_by.into_values().collect();
        preempted_by.sort_by(|a, b| b.count.cmp(&a.count));

        PreemptionStats {
            pid: self.pid,
            comm: self.comm,
            preempted_count: self.preempted_count,
            preempted_by: preempted_by.into_iter().take(10).collect(),
        }
    }
}
