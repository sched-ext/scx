// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::extract::ExtractSchedUtilOpts;
use crate::process::PerfSchedScriptRecord;
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

const DEFAULT_SYSTEM_CATEGORY_NAMES: [&str; 5] = [
    "hardirq",
    "softirq-rx",
    "softirq-tx",
    "softirq-other",
    "nmi",
];
const HARDIRQ_CATEGORY: &str = "hardirq";
const SOFTIRQ_RX_CATEGORY: &str = "softirq-rx";
const SOFTIRQ_TX_CATEGORY: &str = "softirq-tx";
const SOFTIRQ_OTHER_CATEGORY: &str = "softirq-other";
const NMI_CATEGORY: &str = "nmi";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BusyUtilRecord {
    time_ms: u64,
    window_ms: u64,
    cpu_count: usize,
    total: f64,
    uncategorized: f64,
    categories: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct BusyInterval {
    start_ns: u64,
    end_ns: u64,
    comm: String,
    hint: u64,
}

#[derive(Debug, Clone)]
enum CategoryCommMatcher {
    Exact(String),
    Glob(String),
}

#[derive(Debug, Clone)]
struct CategorySpec {
    name: String,
    comm_matcher: CategoryCommMatcher,
    hint: Option<u64>,
}

#[derive(Debug, Default)]
struct CompiledCategoryMatcher {
    exact_any_hint: HashMap<String, Vec<usize>>,
    exact_by_hint: HashMap<String, HashMap<u64, Vec<usize>>>,
    glob_specs: Vec<GlobCategory>,
}

#[derive(Debug)]
struct GlobCategory {
    index: usize,
    pattern: String,
    hint: Option<u64>,
}

#[derive(Debug, Clone)]
struct RunningTask {
    tid: i32,
    comm: String,
    hint: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveSystem {
    HardIrq,
    SoftIrqRx,
    SoftIrqTx,
    SoftIrqOther,
}

impl ActiveSystem {
    fn category_name(self) -> &'static str {
        match self {
            Self::HardIrq => HARDIRQ_CATEGORY,
            Self::SoftIrqRx => SOFTIRQ_RX_CATEGORY,
            Self::SoftIrqTx => SOFTIRQ_TX_CATEGORY,
            Self::SoftIrqOther => SOFTIRQ_OTHER_CATEGORY,
        }
    }

    fn is_softirq(self) -> bool {
        matches!(self, Self::SoftIrqRx | Self::SoftIrqTx | Self::SoftIrqOther)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActiveExecution {
    Task { comm: String, hint: u64 },
    System(ActiveSystem),
}

impl ActiveExecution {
    fn to_interval(&self, start_ns: u64, end_ns: u64) -> Option<BusyInterval> {
        if end_ns <= start_ns {
            return None;
        }

        let (comm, hint) = match self {
            Self::Task { comm, hint } => (comm.clone(), *hint),
            Self::System(system) => (system.category_name().to_string(), 0),
        };

        Some(BusyInterval {
            start_ns,
            end_ns,
            comm,
            hint,
        })
    }
}

#[derive(Debug, Default)]
struct CpuState {
    segment_start_ns: u64,
    last_seen_ns: u64,
    running_task: Option<RunningTask>,
    system_stack: Vec<ActiveSystem>,
    active_execution: Option<ActiveExecution>,
}

#[derive(Debug)]
enum ClassifiedEvent {
    SchedSwitch {
        next_comm: String,
        next_hint: u64,
        next_tid: i32,
        next_is_idle: bool,
    },
    HardIrqEntry,
    HardIrqExit,
    SoftIrqEntry(ActiveSystem),
    SoftIrqExit,
    Nmi {
        delta_ns: u64,
    },
    Other,
}

trait BusyIntervalSink {
    fn on_interval(&mut self, interval: &BusyInterval);
}

#[derive(Debug)]
struct BucketAggregator {
    trace_start_ns: u64,
    window_ns: u64,
    total_busy_ns: Vec<u64>,
    uncategorized_busy_ns: Vec<u64>,
    category_busy_ns: Vec<Vec<u64>>,
    categories: Vec<CategorySpec>,
    matcher: CompiledCategoryMatcher,
    interval_count: usize,
}

impl BucketAggregator {
    fn new(trace_start_ns: u64, window_ns: u64, categories: Vec<CategorySpec>) -> Self {
        let category_busy_ns = vec![Vec::new(); categories.len()];
        let matcher = compile_category_matcher(&categories);
        Self {
            trace_start_ns,
            window_ns,
            total_busy_ns: Vec::new(),
            uncategorized_busy_ns: Vec::new(),
            category_busy_ns,
            categories,
            matcher,
            interval_count: 0,
        }
    }

    fn ensure_bucket(&mut self, idx: usize) {
        let required_len = idx + 1;
        if self.total_busy_ns.len() >= required_len {
            return;
        }

        self.total_busy_ns.resize(required_len, 0);
        self.uncategorized_busy_ns.resize(required_len, 0);
        for values in &mut self.category_busy_ns {
            values.resize(required_len, 0);
        }
    }

    fn finalize(
        self,
        trace_end_ns: u64,
        cpu_count: usize,
        window_ms: u64,
    ) -> Result<(Vec<BusyUtilRecord>, usize)> {
        if trace_end_ns <= self.trace_start_ns {
            anyhow::bail!("non-positive sched trace duration");
        }
        if cpu_count == 0 {
            anyhow::bail!("no CPUs observed in sched trace");
        }

        let total_duration_ns = trace_end_ns - self.trace_start_ns;
        let bucket_count = total_duration_ns.div_ceil(self.window_ns) as usize;

        let mut output = Vec::with_capacity(bucket_count);
        for idx in 0..bucket_count {
            let bucket_start_ns = self.trace_start_ns + idx as u64 * self.window_ns;
            let bucket_end_ns = (bucket_start_ns + self.window_ns).min(trace_end_ns);
            let bucket_width_ns = bucket_end_ns - bucket_start_ns;
            let capacity_ns = bucket_width_ns * cpu_count as u64;
            let scale = if capacity_ns == 0 {
                0.0
            } else {
                100.0 / capacity_ns as f64
            };

            let total_busy_ns = self.total_busy_ns.get(idx).copied().unwrap_or(0);
            let uncategorized_busy_ns = self.uncategorized_busy_ns.get(idx).copied().unwrap_or(0);
            let categorized_busy_ns: u64 = self
                .category_busy_ns
                .iter()
                .map(|values| values.get(idx).copied().unwrap_or(0))
                .sum();

            if categorized_busy_ns + uncategorized_busy_ns != total_busy_ns {
                let category_totals: Vec<_> = self
                    .categories
                    .iter()
                    .enumerate()
                    .filter_map(|(idx_cat, category)| {
                        let value = self
                            .category_busy_ns
                            .get(idx_cat)
                            .and_then(|values| values.get(idx))
                            .copied()
                            .unwrap_or(0);
                        (value > 0).then_some(format!("{}={}ns", category.name, value))
                    })
                    .collect();

                anyhow::bail!(
                    "sched util categories are not mutually exclusive in bucket starting at {}ms: total={}ns uncategorized={}ns categorized_sum={}ns [{}]. Fix --categories so each busy interval matches at most one category",
                    (bucket_start_ns - self.trace_start_ns) / 1_000_000,
                    total_busy_ns,
                    uncategorized_busy_ns,
                    categorized_busy_ns,
                    category_totals.join(", "),
                );
            }

            let categories_json = self
                .categories
                .iter()
                .enumerate()
                .map(|(idx_cat, category)| {
                    let value = self
                        .category_busy_ns
                        .get(idx_cat)
                        .and_then(|values| values.get(idx))
                        .copied()
                        .unwrap_or(0);
                    (category.name.clone(), value as f64 * scale)
                })
                .collect();

            output.push(BusyUtilRecord {
                time_ms: (bucket_start_ns - self.trace_start_ns) / 1_000_000,
                window_ms,
                cpu_count,
                total: total_busy_ns as f64 * scale,
                uncategorized: uncategorized_busy_ns as f64 * scale,
                categories: categories_json,
            });
        }

        Ok((output, self.interval_count))
    }
}

impl BusyIntervalSink for BucketAggregator {
    fn on_interval(&mut self, interval: &BusyInterval) {
        let interval_start = interval.start_ns.max(self.trace_start_ns);
        let interval_end = interval.end_ns;
        if interval_end <= interval_start {
            return;
        }

        let start_idx = ((interval_start - self.trace_start_ns) / self.window_ns) as usize;
        let end_idx = ((interval_end - self.trace_start_ns - 1) / self.window_ns) as usize;
        self.ensure_bucket(end_idx);

        let matched_categories = self.matcher.match_indices(interval);
        for idx in start_idx..=end_idx {
            let bucket_start = self.trace_start_ns + idx as u64 * self.window_ns;
            let bucket_end = bucket_start + self.window_ns;
            let overlap_ns = interval_end.min(bucket_end) - interval_start.max(bucket_start);
            if overlap_ns == 0 {
                continue;
            }

            self.total_busy_ns[idx] += overlap_ns;
            if matched_categories.is_empty() {
                self.uncategorized_busy_ns[idx] += overlap_ns;
            } else {
                for cat_idx in &matched_categories {
                    self.category_busy_ns[*cat_idx][idx] += overlap_ns;
                }
            }
        }

        self.interval_count += 1;
    }
}

#[derive(Debug, Default)]
struct TraceStats {
    trace_start_ns: Option<u64>,
    trace_end_ns: Option<u64>,
    observed_cpus: BTreeSet<u32>,
    saw_switch: bool,
}

impl TraceStats {
    fn observe(&mut self, record: &PerfSchedScriptRecord, time_ns: u64) {
        self.observed_cpus.insert(record.cpu);
        self.trace_start_ns.get_or_insert(time_ns);
        self.trace_end_ns = Some(time_ns);
        if record.event == "sched:sched_switch" {
            self.saw_switch = true;
        }
    }

    fn trace_start_ns(&self) -> u64 {
        self.trace_start_ns.unwrap_or(0)
    }

    fn finish(&self) -> Result<(u64, usize)> {
        if !self.saw_switch {
            anyhow::bail!("no sched:sched_switch events found in perf.sched.jsonl");
        }
        let end_ns = self.trace_end_ns.unwrap_or(0);
        let start_ns = self.trace_start_ns();
        if end_ns <= start_ns {
            anyhow::bail!("non-positive sched trace duration");
        }
        if self.observed_cpus.is_empty() {
            anyhow::bail!("no CPUs observed in sched trace");
        }
        Ok((end_ns, self.observed_cpus.len()))
    }
}

#[derive(Debug)]
struct SchedBusyTracker<S> {
    cpu_states: HashMap<u32, CpuState>,
    sink: S,
}

impl<S: BusyIntervalSink> SchedBusyTracker<S> {
    fn new(sink: S) -> Self {
        Self {
            cpu_states: HashMap::new(),
            sink,
        }
    }

    fn process_record(&mut self, record: PerfSchedScriptRecord) {
        let Some(time_ns) = record
            .sample_time_ns()
            .or_else(|| sched_time_to_ns(record.time))
        else {
            return;
        };

        let mut emitted = Vec::new();
        {
            let state = self
                .cpu_states
                .entry(record.cpu)
                .or_insert_with(|| CpuState {
                    segment_start_ns: time_ns,
                    last_seen_ns: time_ns,
                    ..CpuState::default()
                });
            state.last_seen_ns = time_ns;

            if let Some(task) = state.running_task.as_mut() {
                if record.tid == task.tid && record.hint != task.hint {
                    task.hint = record.hint;
                    if let Some(interval) = sync_cpu_state(state, time_ns) {
                        emitted.push(interval);
                    }
                }
            }

            match classify_event(&record) {
                ClassifiedEvent::SchedSwitch {
                    next_comm,
                    next_hint,
                    next_tid,
                    next_is_idle,
                } => {
                    if next_is_idle {
                        state.running_task = None;
                    } else {
                        state.running_task = Some(RunningTask {
                            tid: next_tid,
                            comm: next_comm,
                            hint: next_hint,
                        });
                    }
                    if let Some(interval) = sync_cpu_state(state, time_ns) {
                        emitted.push(interval);
                    }
                }
                ClassifiedEvent::HardIrqEntry => {
                    state.system_stack.push(ActiveSystem::HardIrq);
                    if let Some(interval) = sync_cpu_state(state, time_ns) {
                        emitted.push(interval);
                    }
                }
                ClassifiedEvent::HardIrqExit => {
                    pop_system_override(state, ActiveSystem::HardIrq);
                    if let Some(interval) = sync_cpu_state(state, time_ns) {
                        emitted.push(interval);
                    }
                }
                ClassifiedEvent::SoftIrqEntry(system) => {
                    state.system_stack.push(system);
                    if let Some(interval) = sync_cpu_state(state, time_ns) {
                        emitted.push(interval);
                    }
                }
                ClassifiedEvent::SoftIrqExit => {
                    pop_softirq_override(state);
                    if let Some(interval) = sync_cpu_state(state, time_ns) {
                        emitted.push(interval);
                    }
                }
                ClassifiedEvent::Nmi { delta_ns } => {
                    let nmi_start_ns = time_ns.saturating_sub(delta_ns);
                    if let Some(interval) = flush_current_interval(state, nmi_start_ns) {
                        emitted.push(interval);
                    }
                    emitted.push(BusyInterval {
                        start_ns: nmi_start_ns,
                        end_ns: time_ns,
                        comm: NMI_CATEGORY.to_string(),
                        hint: 0,
                    });
                    state.segment_start_ns = time_ns;
                }
                ClassifiedEvent::Other => {}
            }
        }

        for interval in emitted {
            self.sink.on_interval(&interval);
        }
    }

    fn finish(mut self, _trace_end_ns: u64) -> S {
        for state in self.cpu_states.values_mut() {
            let cpu_end_ns = state.last_seen_ns.max(state.segment_start_ns);
            if let Some(interval) = flush_current_interval(state, cpu_end_ns) {
                self.sink.on_interval(&interval);
            }
        }
        self.sink
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct VecIntervalSink {
    intervals: Vec<BusyInterval>,
}

#[cfg(test)]
impl BusyIntervalSink for VecIntervalSink {
    fn on_interval(&mut self, interval: &BusyInterval) {
        self.intervals.push(interval.clone());
    }
}

fn current_active_execution(state: &CpuState) -> Option<ActiveExecution> {
    if let Some(system) = state.system_stack.last().copied() {
        return Some(ActiveExecution::System(system));
    }

    state.running_task.as_ref().map(|task| {
        if is_ksoftirqd_comm(&task.comm) {
            ActiveExecution::System(ActiveSystem::SoftIrqOther)
        } else {
            ActiveExecution::Task {
                comm: task.comm.clone(),
                hint: task.hint,
            }
        }
    })
}

fn is_ksoftirqd_comm(comm: &str) -> bool {
    comm.starts_with("ksoftirqd/")
}

fn flush_current_interval(state: &mut CpuState, end_ns: u64) -> Option<BusyInterval> {
    let interval = state
        .active_execution
        .as_ref()
        .and_then(|active| active.to_interval(state.segment_start_ns, end_ns));
    state.segment_start_ns = end_ns;
    interval
}

fn sync_cpu_state(state: &mut CpuState, time_ns: u64) -> Option<BusyInterval> {
    let next_active = current_active_execution(state);
    if state.active_execution == next_active {
        return None;
    }

    let interval = flush_current_interval(state, time_ns);
    state.active_execution = next_active;
    interval
}

fn pop_system_override(state: &mut CpuState, system: ActiveSystem) {
    if let Some(pos) = state
        .system_stack
        .iter()
        .rposition(|value| *value == system)
    {
        state.system_stack.remove(pos);
    }
}

fn pop_softirq_override(state: &mut CpuState) {
    if let Some(pos) = state
        .system_stack
        .iter()
        .rposition(|value| value.is_softirq())
    {
        state.system_stack.remove(pos);
    }
}

fn parse_sched_categories(spec: &str) -> Result<Vec<CategorySpec>> {
    let mut categories = Vec::new();
    let mut seen_names = HashSet::new();
    let mut hinted_comm_parts = BTreeSet::new();
    let mut exact_zero_hint_comms = HashSet::new();
    let mut glob_zero_hint_comms = HashSet::new();

    for raw_item in spec.split(',') {
        let item = raw_item.trim();
        if item.is_empty() {
            continue;
        }

        let (comm_part, hint) = match item.split_once("@hint=") {
            Some((comm, hint_str)) => (
                comm.trim(),
                Some(
                    hint_str
                        .trim()
                        .parse::<u64>()
                        .with_context(|| format!("invalid hint selector in category '{item}'"))?,
                ),
            ),
            None => (item, None),
        };

        let comm_matcher = if comm_part.contains('*') || comm_part.contains('?') {
            CategoryCommMatcher::Glob(comm_part.to_string())
        } else {
            CategoryCommMatcher::Exact(comm_part.to_string())
        };

        if hint.is_some() {
            hinted_comm_parts.insert(comm_part.to_string());
        }
        if hint == Some(0) {
            match &comm_matcher {
                CategoryCommMatcher::Exact(comm) => {
                    exact_zero_hint_comms.insert(comm.clone());
                }
                CategoryCommMatcher::Glob(pattern) => {
                    glob_zero_hint_comms.insert(pattern.clone());
                }
            }
        }

        if !seen_names.insert(item.to_string()) {
            continue;
        }

        categories.push(CategorySpec {
            name: item.to_string(),
            comm_matcher,
            hint,
        });
    }

    for comm_part in hinted_comm_parts {
        let needs_zero_hint = if comm_part.contains('*') || comm_part.contains('?') {
            !glob_zero_hint_comms.contains(&comm_part)
        } else {
            !exact_zero_hint_comms.contains(&comm_part)
        };

        if !needs_zero_hint {
            continue;
        }

        let zero_hint_name = format!("{comm_part}@hint=0");
        if !seen_names.insert(zero_hint_name.clone()) {
            continue;
        }

        let comm_matcher = if comm_part.contains('*') || comm_part.contains('?') {
            CategoryCommMatcher::Glob(comm_part.clone())
        } else {
            CategoryCommMatcher::Exact(comm_part.clone())
        };

        categories.push(CategorySpec {
            name: zero_hint_name,
            comm_matcher,
            hint: Some(0),
        });
    }

    for name in DEFAULT_SYSTEM_CATEGORY_NAMES {
        if seen_names.insert(name.to_string()) {
            categories.push(CategorySpec {
                name: name.to_string(),
                comm_matcher: CategoryCommMatcher::Exact(name.to_string()),
                hint: None,
            });
        }
    }

    Ok(categories)
}

fn compile_category_matcher(categories: &[CategorySpec]) -> CompiledCategoryMatcher {
    let mut matcher = CompiledCategoryMatcher::default();

    for (index, category) in categories.iter().enumerate() {
        match &category.comm_matcher {
            CategoryCommMatcher::Exact(comm) => {
                if let Some(hint) = category.hint {
                    matcher
                        .exact_by_hint
                        .entry(comm.clone())
                        .or_default()
                        .entry(hint)
                        .or_default()
                        .push(index);
                } else {
                    matcher
                        .exact_any_hint
                        .entry(comm.clone())
                        .or_default()
                        .push(index);
                }
            }
            CategoryCommMatcher::Glob(pattern) => matcher.glob_specs.push(GlobCategory {
                index,
                pattern: pattern.clone(),
                hint: category.hint,
            }),
        }
    }

    matcher
}

impl CompiledCategoryMatcher {
    fn match_indices(&self, interval: &BusyInterval) -> Vec<usize> {
        let mut matched = Vec::new();

        if let Some(indices) = self.exact_any_hint.get(&interval.comm) {
            matched.extend(indices.iter().copied());
        }
        if let Some(by_hint) = self.exact_by_hint.get(&interval.comm) {
            if let Some(indices) = by_hint.get(&interval.hint) {
                matched.extend(indices.iter().copied());
            }
        }

        for glob in &self.glob_specs {
            if glob.hint.map(|hint| hint == interval.hint).unwrap_or(true)
                && glob_match(&glob.pattern, &interval.comm)
            {
                matched.push(glob.index);
            }
        }

        matched.sort_unstable();
        matched.dedup();
        matched
    }
}

fn classify_event(record: &PerfSchedScriptRecord) -> ClassifiedEvent {
    match record.event.as_str() {
        "sched:sched_switch" => {
            let Some(fields) = record.fields.as_ref() else {
                return ClassifiedEvent::Other;
            };

            let next_comm = fields
                .get("next_comm")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let next_hint = fields.get("next_hint").and_then(Value::as_u64).unwrap_or(0);
            let next_tid = fields
                .get("next_pid")
                .and_then(Value::as_i64)
                .and_then(|tid| i32::try_from(tid).ok())
                .unwrap_or(0);
            ClassifiedEvent::SchedSwitch {
                next_is_idle: sched_switch_next_is_idle(fields),
                next_comm,
                next_hint,
                next_tid,
            }
        }
        "irq:irq_handler_entry" => ClassifiedEvent::HardIrqEntry,
        "irq:irq_handler_exit" => ClassifiedEvent::HardIrqExit,
        "irq:softirq_entry" => ClassifiedEvent::SoftIrqEntry(classify_softirq_system(record)),
        "irq:softirq_exit" => ClassifiedEvent::SoftIrqExit,
        _ => parse_nmi_duration_ns(record)
            .map(|delta_ns| ClassifiedEvent::Nmi { delta_ns })
            .unwrap_or(ClassifiedEvent::Other),
    }
}

fn classify_softirq_system(record: &PerfSchedScriptRecord) -> ActiveSystem {
    let action = record
        .fields
        .as_ref()
        .and_then(|fields| fields.get("action"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    match action {
        "NET_RX" => ActiveSystem::SoftIrqRx,
        "NET_TX" => ActiveSystem::SoftIrqTx,
        _ => ActiveSystem::SoftIrqOther,
    }
}

fn sched_switch_next_is_idle(fields: &serde_json::Map<String, Value>) -> bool {
    let next_pid = fields.get("next_pid").and_then(Value::as_i64).unwrap_or(-1);
    let next_comm = fields
        .get("next_comm")
        .and_then(Value::as_str)
        .unwrap_or_default();

    next_pid == 0 || next_comm.starts_with("swapper")
}

fn parse_nmi_duration_ns(record: &PerfSchedScriptRecord) -> Option<u64> {
    if !record.event.starts_with("nmi:") {
        return None;
    }

    let needle = "delta_ns:";
    let start = record.trace.find(needle)? + needle.len();
    record.trace[start..]
        .split_whitespace()
        .next()?
        .trim_end_matches(',')
        .parse::<u64>()
        .ok()
}

fn sched_time_to_ns(time: f64) -> Option<u64> {
    if !time.is_finite() || time < 0.0 {
        return None;
    }
    let ns = time * 1_000_000_000.0;
    if ns < 0.0 || ns > u64::MAX as f64 {
        return None;
    }
    Some(ns as u64)
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let (mut pi, mut vi) = (0usize, 0usize);
    let mut star_pi = None;
    let mut star_vi = 0usize;

    while vi < v.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_vi = vi;
        } else if let Some(saved_pi) = star_pi {
            pi = saved_pi + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

pub fn cmd_extract_sched_util(opts: ExtractSchedUtilOpts) -> Result<()> {
    if opts.window_ms == 0 {
        anyhow::bail!("--window-ms must be greater than zero");
    }

    let categories = parse_sched_categories(&opts.categories)?;
    let file = File::open(&opts.file).context("failed to open perf.sched.jsonl")?;
    let reader = BufReader::new(file);

    let mut stats = TraceStats::default();
    let window_ns = opts.window_ms * 1_000_000;
    let mut aggregator = BucketAggregator::new(0, window_ns, categories);
    let mut tracker = SchedBusyTracker::new(aggregator);

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        if line.trim().is_empty() {
            continue;
        }

        let record: PerfSchedScriptRecord =
            serde_json::from_str(&line).context("failed to parse perf.sched.jsonl record")?;
        let Some(time_ns) = record
            .sample_time_ns()
            .or_else(|| sched_time_to_ns(record.time))
        else {
            continue;
        };

        if stats.trace_start_ns.is_none() {
            tracker.sink.trace_start_ns = time_ns;
        }
        stats.observe(&record, time_ns);
        tracker.process_record(record);
    }

    let (trace_end_ns, cpu_count) = stats.finish()?;
    aggregator = tracker.finish(trace_end_ns);
    let category_count = aggregator.categories.len();
    let (output, interval_count) = aggregator.finalize(trace_end_ns, cpu_count, opts.window_ms)?;

    if opts.verbose {
        eprintln!(
            "sched util: {} intervals, {} buckets, {} cpus, {} categories",
            interval_count,
            output.len(),
            cpu_count,
            category_count
        );
    }

    for record in output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "time_ms": record.time_ms,
                "window_ms": record.window_ms,
                "cpu_count": record.cpu_count,
                "total": record.total,
                "uncategorized": record.uncategorized,
                "categories": record.categories,
            }))?
        );
    }

    Ok(())
}

#[cfg(test)]
fn build_busy_intervals(
    records: impl IntoIterator<Item = PerfSchedScriptRecord>,
) -> Result<(Vec<BusyInterval>, u64, u64, usize)> {
    let mut stats = TraceStats::default();
    let mut tracker = SchedBusyTracker::new(VecIntervalSink::default());

    for record in records {
        let Some(time_ns) = record
            .sample_time_ns()
            .or_else(|| sched_time_to_ns(record.time))
        else {
            continue;
        };
        stats.observe(&record, time_ns);
        tracker.process_record(record);
    }

    let (trace_end_ns, cpu_count) = stats.finish()?;
    let sink = tracker.finish(trace_end_ns);
    Ok((
        sink.intervals,
        stats.trace_start_ns(),
        trace_end_ns,
        cpu_count,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write_sched_jsonl(tempdir: &TempDir, lines: &[&str]) -> PathBuf {
        let path = tempdir.path().join("perf.sched.jsonl");
        fs::write(&path, lines.join("\n") + "\n").expect("failed to write perf.sched.jsonl");
        path
    }

    #[test]
    fn sched_util_includes_total_uncategorized_and_hint_categories() -> Result<()> {
        let tempdir = TempDir::new()?;
        let path = write_sched_jsonl(
            &tempdir,
            &[
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.0,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> worker-a:10 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"worker-a","next_pid":10,"next_prio":120},"hint":0}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0005,"event":"sched:sched_stat_runtime","trace":"comm=worker-a runtime=500000 [ns] vruntime=0 [ns]","fields":{"comm":"worker-a","runtime":500000,"vruntime":0},"hint":640}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.001,"event":"sched:sched_switch","trace":"worker-a:10 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"worker-a","prev_pid":10,"prev_prio":120,"prev_state":"R","next_comm":"swapper/0","next_pid":0,"next_prio":120},"hint":640}"#,
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.001,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> svc-4:20 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"svc-4","next_pid":20,"next_prio":120},"hint":0}"#,
                r#"{"comm":"svc-4","pid":20,"tid":20,"cpu":0,"time":0.002,"event":"sched:sched_switch","trace":"svc-4:20 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"svc-4","prev_pid":20,"prev_prio":120,"prev_state":"R","next_comm":"swapper/0","next_pid":0,"next_prio":120},"hint":0}"#,
            ],
        );

        let categories = parse_sched_categories("worker-a@hint=640,svc-*")?;
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let records: Vec<PerfSchedScriptRecord> = reader
            .lines()
            .map(|line| -> Result<_> {
                let line = line?;
                Ok(serde_json::from_str(&line)?)
            })
            .collect::<Result<_>>()?;

        let (intervals, start_ns, end_ns, cpu_count) = build_busy_intervals(records)?;
        assert_eq!(cpu_count, 1);
        assert_eq!(start_ns, 0);
        assert_eq!(end_ns, 2_000_000);
        assert_eq!(intervals.len(), 3);
        assert_eq!(intervals[0].comm, "worker-a");
        assert_eq!(intervals[0].hint, 0);
        assert_eq!(intervals[1].comm, "worker-a");
        assert_eq!(intervals[1].hint, 640);
        assert_eq!(intervals[2].comm, "svc-4");
        assert_eq!(intervals[2].hint, 0);

        let matcher = compile_category_matcher(&categories);
        let category_names: Vec<_> = categories.iter().map(|cat| cat.name.as_str()).collect();
        assert_eq!(
            category_names[matcher.match_indices(&intervals[0])[0]],
            "worker-a@hint=0"
        );
        assert_eq!(
            category_names[matcher.match_indices(&intervals[1])[0]],
            "worker-a@hint=640"
        );
        assert_eq!(
            category_names[matcher.match_indices(&intervals[2])[0]],
            "svc-*"
        );

        Ok(())
    }

    #[test]
    fn sched_util_auto_adds_zero_hint_category_for_hinted_specs() -> Result<()> {
        let categories =
            parse_sched_categories("hhvmworker@hint=256,hhvmworker@hint=640,mcrpxy-*")?;
        let names: BTreeSet<_> = categories.iter().map(|cat| cat.name.as_str()).collect();

        assert!(names.contains("hhvmworker@hint=0"));
        assert!(names.contains("hhvmworker@hint=256"));
        assert!(names.contains("hhvmworker@hint=640"));
        assert!(!names.contains("mcrpxy-*@hint=0"));

        Ok(())
    }

    #[test]
    fn sched_util_does_not_duplicate_explicit_zero_hint_category() -> Result<()> {
        let categories = parse_sched_categories("hhvmworker@hint=0,hhvmworker@hint=384")?;
        let names: Vec<_> = categories
            .iter()
            .filter(|cat| cat.name.starts_with("hhvmworker@hint="))
            .map(|cat| cat.name.as_str())
            .collect();

        assert_eq!(names, vec!["hhvmworker@hint=0", "hhvmworker@hint=384"]);

        Ok(())
    }

    #[test]
    fn sched_util_outputs_total_and_uncategorized_records() -> Result<()> {
        let tempdir = TempDir::new()?;
        let path = write_sched_jsonl(
            &tempdir,
            &[
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.0,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> worker-a:10 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"worker-a","next_pid":10,"next_prio":120},"hint":0}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0005,"event":"sched:sched_stat_runtime","trace":"comm=worker-a runtime=500000 [ns] vruntime=0 [ns]","fields":{"comm":"worker-a","runtime":500000,"vruntime":0},"hint":640}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.001,"event":"sched:sched_switch","trace":"worker-a:10 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"worker-a","prev_pid":10,"prev_prio":120,"prev_state":"R","next_comm":"swapper/0","next_pid":0,"next_prio":120},"hint":640}"#,
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.001,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> uncat:20 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"uncat","next_pid":20,"next_prio":120},"hint":0}"#,
                r#"{"comm":"uncat","pid":20,"tid":20,"cpu":0,"time":0.002,"event":"sched:sched_switch","trace":"uncat:20 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"uncat","prev_pid":20,"prev_prio":120,"prev_state":"R","next_comm":"swapper/0","next_pid":0,"next_prio":120},"hint":0}"#,
            ],
        );

        let opts = ExtractSchedUtilOpts {
            file: path,
            window_ms: 1,
            categories: "worker-a@hint=640".to_string(),
            verbose: false,
        };

        let categories = parse_sched_categories(&opts.categories)?;
        let window_ns = opts.window_ms * 1_000_000;
        let mut agg = BucketAggregator::new(0, window_ns, categories);
        let file = File::open(&opts.file)?;
        let reader = BufReader::new(file);
        let mut stats = TraceStats::default();
        let mut tracker = SchedBusyTracker::new(agg);

        for line in reader.lines() {
            let line = line?;
            let record: PerfSchedScriptRecord = serde_json::from_str(&line)?;
            let Some(time_ns) = record
                .sample_time_ns()
                .or_else(|| sched_time_to_ns(record.time))
            else {
                continue;
            };
            if stats.trace_start_ns.is_none() {
                tracker.sink.trace_start_ns = time_ns;
            }
            stats.observe(&record, time_ns);
            tracker.process_record(record);
        }
        let (trace_end_ns, cpu_count) = stats.finish()?;
        agg = tracker.finish(trace_end_ns);

        assert_eq!(cpu_count, 1);
        let (output, _interval_count) = agg.finalize(trace_end_ns, cpu_count, opts.window_ms)?;
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].total, 100.0);
        assert_eq!(output[0].uncategorized, 0.0);
        assert_eq!(output[0].categories["worker-a@hint=0"], 50.0);
        assert_eq!(output[0].categories["worker-a@hint=640"], 50.0);
        assert_eq!(output[1].uncategorized, 100.0);

        Ok(())
    }

    #[test]
    fn sched_util_rejects_overlapping_categories() -> Result<()> {
        let tempdir = TempDir::new()?;
        let path = write_sched_jsonl(
            &tempdir,
            &[
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.0,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> worker-a:10 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"worker-a","next_pid":10,"next_prio":120,"next_hint":640},"hint":0}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.001,"event":"sched:sched_switch","trace":"worker-a:10 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"worker-a","prev_pid":10,"prev_prio":120,"prev_state":"R","next_comm":"swapper/0","next_pid":0,"next_prio":120,"next_hint":0},"hint":640}"#,
            ],
        );

        let opts = ExtractSchedUtilOpts {
            file: path,
            window_ms: 1,
            categories: "worker-a,worker-a@hint=640".to_string(),
            verbose: false,
        };

        let categories = parse_sched_categories(&opts.categories)?;
        let window_ns = opts.window_ms * 1_000_000;
        let mut agg = BucketAggregator::new(0, window_ns, categories);
        let file = File::open(&opts.file)?;
        let reader = BufReader::new(file);
        let mut stats = TraceStats::default();
        let mut tracker = SchedBusyTracker::new(agg);

        for line in reader.lines() {
            let line = line?;
            let record: PerfSchedScriptRecord = serde_json::from_str(&line)?;
            let Some(time_ns) = record
                .sample_time_ns()
                .or_else(|| sched_time_to_ns(record.time))
            else {
                continue;
            };
            if stats.trace_start_ns.is_none() {
                tracker.sink.trace_start_ns = time_ns;
            }
            stats.observe(&record, time_ns);
            tracker.process_record(record);
        }
        let (trace_end_ns, cpu_count) = stats.finish()?;
        agg = tracker.finish(trace_end_ns);

        let err = agg
            .finalize(trace_end_ns, cpu_count, opts.window_ms)
            .expect_err("expected overlapping categories to be rejected");
        assert!(err
            .to_string()
            .contains("sched util categories are not mutually exclusive"));

        Ok(())
    }

    #[test]
    fn sched_util_splits_busy_time_on_on_cpu_hint_changes_and_tracks_irqs() -> Result<()> {
        let tempdir = TempDir::new()?;
        let path = write_sched_jsonl(
            &tempdir,
            &[
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.0,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> worker-a:10 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"worker-a","next_pid":10,"next_prio":120},"hint":0}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0002,"event":"sched:sched_stat_runtime","trace":"comm=worker-a runtime=200000 [ns] vruntime=0 [ns]","fields":{"comm":"worker-a","runtime":200000,"vruntime":0},"hint":384}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0006,"event":"irq:softirq_entry","trace":"vec=3 [action=NET_RX]","fields":{"action":"NET_RX","vec":3},"hint":384}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0007,"event":"irq:softirq_exit","trace":"vec=3 [action=NET_RX]","fields":{"action":"NET_RX","vec":3},"hint":384}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0008,"event":"sched:sched_stat_runtime","trace":"comm=worker-a runtime=800000 [ns] vruntime=0 [ns]","fields":{"comm":"worker-a","runtime":800000,"vruntime":0},"hint":640}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.0010,"event":"sched:sched_switch","trace":"worker-a:10 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"worker-a","prev_pid":10,"prev_prio":120,"prev_state":"R","next_comm":"swapper/0","next_pid":0,"next_prio":120},"hint":640}"#,
            ],
        );

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let records: Vec<PerfSchedScriptRecord> = reader
            .lines()
            .map(|line| -> Result<_> {
                let line = line?;
                Ok(serde_json::from_str(&line)?)
            })
            .collect::<Result<_>>()?;

        let (intervals, _start_ns, _end_ns, cpu_count) = build_busy_intervals(records)?;
        assert_eq!(cpu_count, 1);
        assert_eq!(intervals.len(), 5);

        assert_eq!(intervals[0].comm, "worker-a");
        assert_eq!(intervals[0].hint, 0);
        assert_eq!((intervals[0].start_ns, intervals[0].end_ns), (0, 200_000));

        assert_eq!(intervals[1].comm, "worker-a");
        assert_eq!(intervals[1].hint, 384);
        assert_eq!(
            (intervals[1].start_ns, intervals[1].end_ns),
            (200_000, 600_000)
        );

        assert_eq!(intervals[2].comm, "softirq-rx");
        assert_eq!(intervals[2].hint, 0);
        assert_eq!(
            (intervals[2].start_ns, intervals[2].end_ns),
            (600_000, 700_000)
        );

        assert_eq!(intervals[3].comm, "worker-a");
        assert_eq!(intervals[3].hint, 384);
        assert_eq!(
            (intervals[3].start_ns, intervals[3].end_ns),
            (700_000, 800_000)
        );

        assert_eq!(intervals[4].comm, "worker-a");
        assert_eq!(intervals[4].hint, 640);
        assert_eq!(
            (intervals[4].start_ns, intervals[4].end_ns),
            (800_000, 1_000_000)
        );

        Ok(())
    }

    #[test]
    fn sched_util_uses_next_hint_from_switch_for_immediate_on_cpu_time() -> Result<()> {
        let tempdir = TempDir::new()?;
        let path = write_sched_jsonl(
            &tempdir,
            &[
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.0,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> worker-a:10 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","prev_hint":0,"next_comm":"worker-a","next_pid":10,"next_prio":120,"next_hint":640},"hint":0}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":0,"time":0.001,"event":"sched:sched_switch","trace":"worker-a:10 [120] R ==> swapper/0:0 [120]","fields":{"prev_comm":"worker-a","prev_pid":10,"prev_prio":120,"prev_state":"R","prev_hint":640,"next_comm":"swapper/0","next_pid":0,"next_prio":120,"next_hint":0},"hint":640}"#,
            ],
        );

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let records: Vec<PerfSchedScriptRecord> = reader
            .lines()
            .map(|line| -> Result<_> {
                let line = line?;
                Ok(serde_json::from_str(&line)?)
            })
            .collect::<Result<_>>()?;

        let (intervals, _start_ns, _end_ns, cpu_count) = build_busy_intervals(records)?;
        assert_eq!(cpu_count, 1);
        assert_eq!(intervals.len(), 1);
        assert_eq!(intervals[0].comm, "worker-a");
        assert_eq!(intervals[0].hint, 640);
        assert_eq!((intervals[0].start_ns, intervals[0].end_ns), (0, 1_000_000));

        Ok(())
    }

    #[test]
    fn sched_util_does_not_extrapolate_last_running_task_to_global_trace_end() -> Result<()> {
        let tempdir = TempDir::new()?;
        let path = write_sched_jsonl(
            &tempdir,
            &[
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":0,"time":0.0,"event":"sched:sched_switch","trace":"swapper/0:0 [120] R ==> perf:900 [120]","fields":{"prev_comm":"swapper/0","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"perf","next_pid":900,"next_prio":120},"hint":0}"#,
                r#"{"comm":"perf","pid":900,"tid":900,"cpu":0,"time":0.001,"event":"sched:sched_stat_runtime","trace":"comm=perf runtime=1000000 [ns] vruntime=0 [ns]","fields":{"comm":"perf","runtime":1000000,"vruntime":0},"hint":0}"#,
                r#"{"comm":"idle","pid":0,"tid":0,"cpu":1,"time":0.0,"event":"sched:sched_switch","trace":"swapper/1:0 [120] R ==> worker-a:10 [120]","fields":{"prev_comm":"swapper/1","prev_pid":0,"prev_prio":120,"prev_state":"R","next_comm":"worker-a","next_pid":10,"next_prio":120},"hint":0}"#,
                r#"{"comm":"worker-a","pid":10,"tid":10,"cpu":1,"time":0.002,"event":"sched:sched_switch","trace":"worker-a:10 [120] R ==> swapper/1:0 [120]","fields":{"prev_comm":"worker-a","prev_pid":10,"prev_prio":120,"prev_state":"R","next_comm":"swapper/1","next_pid":0,"next_prio":120},"hint":0}"#,
            ],
        );

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let records: Vec<PerfSchedScriptRecord> = reader
            .lines()
            .map(|line| -> Result<_> {
                let line = line?;
                Ok(serde_json::from_str(&line)?)
            })
            .collect::<Result<_>>()?;

        let (intervals, _start_ns, end_ns, cpu_count) = build_busy_intervals(records)?;
        assert_eq!(cpu_count, 2);
        assert_eq!(end_ns, 2_000_000);

        let perf_interval = intervals
            .iter()
            .find(|interval| interval.comm == "perf")
            .expect("expected perf interval");
        assert_eq!(
            (perf_interval.start_ns, perf_interval.end_ns),
            (0, 1_000_000)
        );

        let worker_interval = intervals
            .iter()
            .find(|interval| interval.comm == "worker-a")
            .expect("expected worker interval");
        assert_eq!(
            (worker_interval.start_ns, worker_interval.end_ns),
            (0, 2_000_000)
        );

        Ok(())
    }
}
