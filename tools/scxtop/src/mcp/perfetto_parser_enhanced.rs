// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Enhanced perfetto trace parser with cross-tool compatibility and generic event indexing

use super::perfetto_event_types::{event_category, EventCategory};
use super::perfetto_parser::{FtraceEventWithIndex, PerfettoTrace};
use perfetto_protos::{ftrace_event::ftrace_event, trace::Trace};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Trace capability detection - what data is available in the trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCapabilities {
    /// All ftrace event types found in trace
    pub available_events: HashSet<String>,
    /// Event type -> count
    pub event_counts: HashMap<String, usize>,
    /// TrackEvent categories found in trace (from wprof or other TrackEvent sources)
    pub track_event_categories: HashSet<String>,
    /// TrackEvent category -> count
    pub track_event_counts: HashMap<String, usize>,
    /// Clock sources present in trace
    pub clock_sources: HashSet<ClockType>,
    /// Has ProcessTree packets
    pub has_process_tree: bool,
    /// Has SystemInfo packet
    pub has_system_info: bool,
    /// Has ProcessStats packets
    pub has_process_stats: bool,
    /// Has PerfSample packets (perf counters)
    pub has_perf_samples: bool,
    /// Has sched_ext specific data (DSQ tracks)
    pub has_sched_ext: bool,
    /// Trace time range (nanoseconds)
    pub time_range: (u64, u64),
    /// Number of CPUs detected
    pub num_cpus: usize,
    /// Number of processes detected
    pub num_processes: usize,
    /// Total ftrace events
    pub total_events: usize,
    /// Detected trace source
    pub trace_source: TraceSource,
}

/// Maps wprof TrackEvent categories to equivalent ftrace event types
/// This allows analyzers to work with both ftrace and TrackEvent data
pub fn map_wprof_category_to_ftrace(category: &str) -> Option<&'static str> {
    match category {
        "ONCPU" => Some("sched_switch"),
        "WAKEE" | "WAKEE_NEW" => Some("sched_wakeup"),
        "WAKER" | "WAKER_NEW" => Some("sched_waking"),
        "PREEMPTEE" | "PREEMPTOR" => Some("sched_switch"), // preemption is part of sched_switch
        "HARDIRQ" => Some("irq_handler_entry"),
        "SOFTIRQ" => Some("softirq_entry"),
        "FORKING" | "FORKED" => Some("sched_process_fork"),
        "EXIT" => Some("sched_process_exit"),
        "EXEC" => Some("sched_process_exec"),
        "START" => Some("sched_process_exec"),
        "RENAME" => None, // No direct ftrace equivalent
        "FREE" => None,   // No direct ftrace equivalent
        "WQ" => None,     // Workqueue events
        _ => None,
    }
}

impl TraceCapabilities {
    /// Build capabilities from a parsed trace
    pub fn from_trace(trace: &PerfettoTrace) -> Self {
        let mut available_events = HashSet::new();
        let mut event_counts: HashMap<String, usize> = HashMap::new();
        let clock_sources = HashSet::new();
        let has_system_info = false;
        let has_process_stats = false;
        let has_perf_samples = false;

        // Scan all events and track types
        let total_events = trace.total_events();
        let time_range = trace.time_range();
        let num_cpus = trace.num_cpus();
        let num_processes = trace.get_processes().len();
        let has_sched_ext = trace.is_scx_trace();

        // Get event types from trace
        // Note: This requires access to the internal events, which we'll add
        // For now, we'll infer from existing query methods
        for event_type in &[
            "sched_switch",
            "sched_wakeup",
            "sched_waking",
            "sched_migrate",
            "softirq",
            "irq_handler_entry",
            "irq_handler_exit",
            "block_rq_insert",
            "block_rq_issue",
            "block_rq_complete",
            "net_dev_xmit",
            "netif_receive_skb",
            "mm_page_alloc",
            "mm_page_free",
            "cpu_frequency",
            "cpu_idle",
        ] {
            let events = trace.get_events_by_type(event_type);
            if !events.is_empty() {
                available_events.insert(event_type.to_string());
                event_counts.insert(event_type.to_string(), events.len());
            }
        }

        // Get TrackEvent categories (used by wprof and other TrackEvent-based traces)
        let track_event_counts = trace.get_track_event_counts_by_category();
        let track_event_categories: HashSet<String> = track_event_counts.keys().cloned().collect();

        // Map TrackEvent categories to equivalent ftrace events for analyzer compatibility
        // This allows analyzers designed for ftrace to also work with TrackEvent data
        for category in &track_event_categories {
            if let Some(ftrace_equiv) = map_wprof_category_to_ftrace(category) {
                available_events.insert(ftrace_equiv.to_string());
                // Add the TrackEvent count to the ftrace equivalent
                if let Some(count) = track_event_counts.get(category) {
                    *event_counts.entry(ftrace_equiv.to_string()).or_insert(0) += count;
                }
            }
        }

        // Check for process tree
        let has_process_tree = !trace.get_processes().is_empty();

        // Detect trace source based on available data
        // wprof traces have characteristic categories like ONCPU, WAKEE, WAKER
        let is_wprof = track_event_categories.contains("ONCPU")
            && (track_event_categories.contains("WAKEE")
                || track_event_categories.contains("WAKER"));

        let trace_source = if has_sched_ext {
            TraceSource::Scxtop
        } else if is_wprof {
            TraceSource::Wprof
        } else if available_events.contains("sched_switch") && track_event_categories.is_empty() {
            TraceSource::GenericFtrace
        } else {
            TraceSource::Unknown
        };

        Self {
            available_events,
            event_counts,
            track_event_categories,
            track_event_counts,
            clock_sources,
            has_process_tree,
            has_system_info,
            has_process_stats,
            has_perf_samples,
            has_sched_ext,
            time_range,
            num_cpus,
            num_processes,
            total_events,
            trace_source,
        }
    }

    /// Check if trace supports an analyzer's requirements
    pub fn supports_analyzer(&self, required_events: &[&str]) -> bool {
        required_events
            .iter()
            .all(|event| self.available_events.contains(*event))
    }

    /// Get count for a specific event type
    pub fn get_event_count(&self, event_type: &str) -> usize {
        self.event_counts.get(event_type).copied().unwrap_or(0)
    }

    /// Get all event types as a sorted list
    pub fn list_event_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.available_events.iter().cloned().collect();
        types.sort();
        types
    }

    /// Get event types by category
    pub fn events_by_category(&self) -> HashMap<EventCategory, Vec<String>> {
        let mut by_category: HashMap<EventCategory, Vec<String>> = HashMap::new();

        for event_type in &self.available_events {
            let category = event_category(event_type);
            by_category
                .entry(category)
                .or_default()
                .push(event_type.clone());
        }

        by_category
    }

    /// Check if trace has minimum data for meaningful analysis
    pub fn is_analyzable(&self) -> bool {
        // Need at least sched_switch for basic scheduler analysis
        self.available_events.contains("sched_switch") && self.total_events > 0
    }
}

/// Generic event type indexing for fast queries
#[derive(Clone)]
pub struct EventTypeIndex {
    /// Event type -> CPU -> Vec<Event>
    by_cpu: HashMap<String, BTreeMap<u32, Vec<FtraceEventWithIndex>>>,
    /// Event type -> PID -> Vec<Event> (for events that have PIDs)
    by_pid: HashMap<String, HashMap<i32, Vec<FtraceEventWithIndex>>>,
    /// Event type -> count
    event_counts: HashMap<String, usize>,
}

impl EventTypeIndex {
    /// Build generic event index from trace
    pub fn build_from_trace(trace: &PerfettoTrace) -> Self {
        let mut by_cpu: HashMap<String, BTreeMap<u32, Vec<FtraceEventWithIndex>>> = HashMap::new();
        let mut by_pid: HashMap<String, HashMap<i32, Vec<FtraceEventWithIndex>>> = HashMap::new();
        let mut event_counts: HashMap<String, usize> = HashMap::new();

        // Iterate through all CPUs and categorize events
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                // Determine event type
                let event_type = match &event_with_idx.event.event {
                    Some(ftrace_event::Event::SchedSwitch(_)) => Some("sched_switch"),
                    Some(ftrace_event::Event::SchedWakeup(_)) => Some("sched_wakeup"),
                    Some(ftrace_event::Event::SchedWaking(_)) => Some("sched_waking"),
                    Some(ftrace_event::Event::SchedMigrateTask(_)) => Some("sched_migrate_task"),
                    Some(ftrace_event::Event::SchedProcessFork(_)) => Some("sched_process_fork"),
                    Some(ftrace_event::Event::SchedProcessExit(_)) => Some("sched_process_exit"),
                    Some(ftrace_event::Event::SoftirqEntry(_)) => Some("softirq_entry"),
                    Some(ftrace_event::Event::SoftirqExit(_)) => Some("softirq_exit"),
                    Some(ftrace_event::Event::SoftirqRaise(_)) => Some("softirq_raise"),
                    Some(ftrace_event::Event::IrqHandlerEntry(_)) => Some("irq_handler_entry"),
                    Some(ftrace_event::Event::IrqHandlerExit(_)) => Some("irq_handler_exit"),
                    Some(ftrace_event::Event::BlockRqInsert(_)) => Some("block_rq_insert"),
                    Some(ftrace_event::Event::BlockRqIssue(_)) => Some("block_rq_issue"),
                    Some(ftrace_event::Event::BlockRqComplete(_)) => Some("block_rq_complete"),
                    _ => None,
                };

                if let Some(event_type_str) = event_type {
                    // Add to by_cpu index
                    by_cpu
                        .entry(event_type_str.to_string())
                        .or_default()
                        .entry(cpu as u32)
                        .or_default()
                        .push(event_with_idx.clone());

                    // Add to by_pid index if event has a PID
                    if let Some(pid) = event_with_idx.event.pid {
                        by_pid
                            .entry(event_type_str.to_string())
                            .or_default()
                            .entry(pid as i32)
                            .or_default()
                            .push(event_with_idx.clone());
                    }

                    // Update count
                    *event_counts.entry(event_type_str.to_string()).or_insert(0) += 1;
                }
            }
        }

        Self {
            by_cpu,
            by_pid,
            event_counts,
        }
    }

    /// Get events of a specific type for a specific CPU
    pub fn get_events_by_type_and_cpu(
        &self,
        event_type: &str,
        cpu: u32,
    ) -> &[FtraceEventWithIndex] {
        self.by_cpu
            .get(event_type)
            .and_then(|cpu_map| cpu_map.get(&cpu))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get events of a specific type for a specific PID
    pub fn get_events_by_type_and_pid(
        &self,
        event_type: &str,
        pid: i32,
    ) -> &[FtraceEventWithIndex] {
        self.by_pid
            .get(event_type)
            .and_then(|pid_map| pid_map.get(&pid))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all events of a specific type across all CPUs
    pub fn get_events_by_type(&self, event_type: &str) -> Vec<&FtraceEventWithIndex> {
        self.by_cpu
            .get(event_type)
            .map(|cpu_map| cpu_map.values().flat_map(|events| events.iter()).collect())
            .unwrap_or_default()
    }

    /// Get events of a specific type within a time range
    pub fn get_events_by_type_in_range(
        &self,
        event_type: &str,
        start_ns: u64,
        end_ns: u64,
    ) -> Vec<&FtraceEventWithIndex> {
        self.get_events_by_type(event_type)
            .into_iter()
            .filter(|event| {
                if let Some(ts) = event.event.timestamp {
                    ts >= start_ns && ts <= end_ns
                } else {
                    false
                }
            })
            .collect()
    }

    /// Get count for an event type
    pub fn get_event_count(&self, event_type: &str) -> usize {
        self.event_counts.get(event_type).copied().unwrap_or(0)
    }

    /// List all indexed event types
    pub fn list_event_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.event_counts.keys().cloned().collect();
        types.sort();
        types
    }
}

/// Clock type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClockType {
    Realtime,
    Monotonic,
    MonotonicRaw,
    Boottime,
    Tai,
    Unknown,
}

impl ClockType {
    pub fn from_clock_id(id: i32) -> Self {
        match id {
            0 => ClockType::Realtime,     // CLOCK_REALTIME
            1 => ClockType::Monotonic,    // CLOCK_MONOTONIC
            4 => ClockType::MonotonicRaw, // CLOCK_MONOTONIC_RAW
            7 => ClockType::Boottime,     // CLOCK_BOOTTIME
            11 => ClockType::Tai,         // CLOCK_TAI
            _ => ClockType::Unknown,
        }
    }
}

/// Trace source detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceSource {
    /// Generated by scxtop
    Scxtop,
    /// Generated by wprof
    Wprof,
    /// Android systrace
    AndroidSystemTrace,
    /// Chrome tracing
    ChromeTracing,
    /// Generic Linux ftrace
    GenericFtrace,
    /// Unknown source
    Unknown,
}

impl TraceSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceSource::Scxtop => "scxtop",
            TraceSource::Wprof => "wprof",
            TraceSource::AndroidSystemTrace => "Android Systrace",
            TraceSource::ChromeTracing => "Chrome Tracing",
            TraceSource::GenericFtrace => "Generic Ftrace",
            TraceSource::Unknown => "Unknown",
        }
    }
}

/// Cross-tool compatibility detector and helpers
pub struct CompatibilityDetector;

impl CompatibilityDetector {
    /// Detect the source of a perfetto trace
    pub fn detect_trace_source(trace: &Trace) -> TraceSource {
        // Check for scxtop-specific markers (DSQ tracks)
        let mut has_dsq_tracks = false;
        let has_android_markers = false;
        let mut has_chrome_markers = false;

        for packet in &trace.packet {
            if let Some(data) = &packet.data {
                use perfetto_protos::trace_packet::trace_packet::Data;

                match data {
                    Data::TrackDescriptor(desc) => {
                        // Check for DSQ tracks (scxtop-specific)
                        if let Some(counter) = desc.counter.as_ref() {
                            if let Some(unit) = &counter.unit_name {
                                if unit.contains("DSQ") {
                                    has_dsq_tracks = true;
                                }
                            }
                        }
                    }
                    Data::ChromeMetadata(_) => {
                        has_chrome_markers = true;
                    }
                    // Android log events are in ftrace, not separate packets
                    Data::FtraceEvents(_) => {
                        // Could check for Android-specific ftrace events if needed
                    }
                    _ => {}
                }
            }
        }

        if has_dsq_tracks {
            TraceSource::Scxtop
        } else if has_android_markers {
            TraceSource::AndroidSystemTrace
        } else if has_chrome_markers {
            TraceSource::ChromeTracing
        } else {
            // Has ftrace events but no specific markers
            TraceSource::GenericFtrace
        }
    }

    /// Check if trace has required events for analysis
    pub fn has_required_events(caps: &TraceCapabilities, events: &[&str]) -> bool {
        caps.supports_analyzer(events)
    }

    /// Get missing events from required list
    pub fn get_missing_events(caps: &TraceCapabilities, required: &[&str]) -> Vec<String> {
        required
            .iter()
            .filter(|event| !caps.available_events.contains(**event))
            .map(|s| s.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_type_conversion() {
        assert_eq!(ClockType::from_clock_id(0), ClockType::Realtime);
        assert_eq!(ClockType::from_clock_id(1), ClockType::Monotonic);
        assert_eq!(ClockType::from_clock_id(7), ClockType::Boottime);
        assert_eq!(ClockType::from_clock_id(999), ClockType::Unknown);
    }

    #[test]
    fn test_trace_source_as_str() {
        assert_eq!(TraceSource::Scxtop.as_str(), "scxtop");
        assert_eq!(TraceSource::AndroidSystemTrace.as_str(), "Android Systrace");
        assert_eq!(TraceSource::GenericFtrace.as_str(), "Generic Ftrace");
    }

    #[test]
    fn test_trace_capabilities_supports_analyzer() {
        let mut caps = TraceCapabilities {
            available_events: HashSet::new(),
            event_counts: HashMap::new(),
            track_event_categories: HashSet::new(),
            track_event_counts: HashMap::new(),
            clock_sources: HashSet::new(),
            has_process_tree: true,
            has_system_info: false,
            has_process_stats: false,
            has_perf_samples: false,
            has_sched_ext: false,
            time_range: (0, 1000000),
            num_cpus: 4,
            num_processes: 10,
            total_events: 1000,
            trace_source: TraceSource::GenericFtrace,
        };

        caps.available_events.insert("sched_switch".to_string());
        caps.available_events.insert("sched_wakeup".to_string());

        assert!(caps.supports_analyzer(&["sched_switch"]));
        assert!(caps.supports_analyzer(&["sched_switch", "sched_wakeup"]));
        assert!(!caps.supports_analyzer(&["sched_switch", "irq_handler_entry"]));
        assert!(!caps.supports_analyzer(&["nonexistent_event"]));
    }

    #[test]
    fn test_compatibility_detector_missing_events() {
        let mut caps = TraceCapabilities {
            available_events: HashSet::new(),
            event_counts: HashMap::new(),
            track_event_categories: HashSet::new(),
            track_event_counts: HashMap::new(),
            clock_sources: HashSet::new(),
            has_process_tree: true,
            has_system_info: false,
            has_process_stats: false,
            has_perf_samples: false,
            has_sched_ext: false,
            time_range: (0, 1000000),
            num_cpus: 4,
            num_processes: 10,
            total_events: 1000,
            trace_source: TraceSource::GenericFtrace,
        };

        caps.available_events.insert("sched_switch".to_string());

        let missing = CompatibilityDetector::get_missing_events(
            &caps,
            &["sched_switch", "irq_handler_entry", "block_rq_issue"],
        );

        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"irq_handler_entry".to_string()));
        assert!(missing.contains(&"block_rq_issue".to_string()));
    }
}
