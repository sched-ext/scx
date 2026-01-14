// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use perfetto_protos::{
    ftrace_event::{ftrace_event, FtraceEvent},
    ftrace_event_bundle::ftrace_event_bundle::CompactSched,
    sys_stats::SysStats,
    trace::Trace,
    trace_packet::{trace_packet, TracePacket},
    track_event::TrackEvent,
};
use protobuf::Message;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Intern tables for resolving IIDs to strings (used by wprof traces)
#[derive(Debug, Clone, Default)]
pub struct InternTables {
    /// Event categories (field 1 in InternedData): iid -> category name
    pub event_categories: HashMap<u64, String>,
    /// Event names (field 2 in InternedData): iid -> event name
    pub event_names: HashMap<u64, String>,
    /// Debug annotation names (field 3 in InternedData): iid -> annotation name
    pub debug_annotation_names: HashMap<u64, String>,
    /// Debug annotation string values (field 29 in InternedData): iid -> string value
    pub debug_annotation_string_values: HashMap<u64, String>,
}

/// Core structure for a parsed perfetto trace file
#[derive(Clone)]
pub struct PerfettoTrace {
    /// All trace packets (stored for reference)
    #[allow(dead_code)] // Reserved for future DSQ event correlation
    packets: Vec<TracePacket>,
    /// Process information indexed by PID
    processes: HashMap<i32, ProcessInfo>,
    /// Thread information indexed by (pid << 32) | tid
    #[allow(dead_code)] // Reserved for future thread-level analysis
    threads: HashMap<u64, ThreadInfo>,
    /// Ftrace events indexed by CPU for efficient per-CPU queries
    ftrace_events_by_cpu: BTreeMap<u32, Vec<FtraceEventWithIndex>>,
    /// DSQ (dispatch queue) events indexed by DSQ ID
    #[allow(dead_code)] // Reserved for future DSQ latency analysis
    dsq_events: HashMap<u64, Vec<DsqEvent>>,
    /// System statistics indexed by timestamp
    #[allow(dead_code)] // Reserved for future system stats analysis
    system_stats: BTreeMap<u64, SysStats>,
    /// Overall trace time range (start_ns, end_ns)
    time_range: (u64, u64),
    /// sched_ext scheduler metadata (if trace contains sched_ext events)
    scx_metadata: Option<SchedExtMetadata>,

    /// NEW: Track events parsed from wprof traces (ONCPU, WAKER, etc.)
    track_events: Vec<super::perfetto_track_event_types::ParsedTrackEvent>,
    /// Track events indexed by PID for efficient per-process queries
    track_events_by_pid: HashMap<i32, Vec<usize>>, // Maps PID -> indices into track_events
    /// Track events indexed by category for efficient type queries
    track_events_by_category: HashMap<String, Vec<usize>>, // Maps category -> indices into track_events
    /// Track UUID to thread info mapping (from TrackDescriptors)
    #[allow(dead_code)]
    track_uuid_to_thread: HashMap<u64, (i32, i32)>, // Maps track_uuid -> (pid, tid)

    /// NEW: Trace capabilities (what data is available)
    #[allow(dead_code)]
    capabilities: Option<super::perfetto_parser_enhanced::TraceCapabilities>,
    /// NEW: Generic event index (lazy-loaded on demand)
    #[allow(dead_code)]
    event_index: Option<Arc<super::perfetto_parser_enhanced::EventTypeIndex>>,
}

/// Information about a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub cmdline: Vec<String>,
    pub name: Option<String>,
}

/// Information about a thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: i32,
    pub pid: i32,
    pub name: Option<String>,
}

/// Ftrace event with index for efficient lookups
#[derive(Clone)]
pub struct FtraceEventWithIndex {
    pub event: FtraceEvent,
    pub packet_index: usize,
}

/// DSQ (dispatch queue) event from sched_ext scheduler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsqEvent {
    pub dsq_id: u64,
    pub timestamp: u64,
    pub latency_us: Option<i64>,
    pub nr_queued: Option<i64>,
}

/// sched_ext specific metadata extracted from traces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedExtMetadata {
    /// Scheduler name (if available)
    pub scheduler_name: Option<String>,
    /// All dispatch queue IDs seen in trace
    pub dsq_ids: Vec<u64>,
    /// Descriptors for each DSQ
    pub dsq_descriptors: HashMap<u64, DsqDescriptor>,
    /// True if trace contains sched_ext-specific events
    pub has_scx_events: bool,
}

/// Descriptor for a dispatch queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsqDescriptor {
    pub dsq_id: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub event_count: usize,
}

/// sched_ext event data extracted from sched_switch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedExtEventData {
    pub dsq_id: u64,
    pub dsq_latency_us: i64,
    pub dsq_nr_queued: i64,
    pub timestamp: u64,
    pub pid: i32,
    pub cpu: u32,
}

/// Common percentile structure used across all analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Percentiles {
    pub count: usize,
    pub min: u64,
    pub max: u64,
    pub mean: f64,
    pub median: u64, // p50
    pub p95: u64,
    pub p99: u64,
    pub p999: u64,
}

/// Helper function to expand CompactSched format into individual FtraceEvents
fn expand_compact_sched(
    compact: &CompactSched,
    _cpu: u32,
    packet_idx: usize,
) -> Vec<FtraceEventWithIndex> {
    use perfetto_protos::sched::{SchedSwitchFtraceEvent, SchedWakingFtraceEvent};

    let mut events = Vec::new();

    // Expand sched_waking events
    let mut waking_ts = 0u64;
    let waking_count = compact.waking_timestamp.len();
    for i in 0..waking_count {
        // Reconstruct absolute timestamp from delta-encoded values
        waking_ts += compact.waking_timestamp[i];

        // Get command name from intern table
        let comm = if let Some(&comm_idx) = compact.waking_comm_index.get(i) {
            compact
                .intern_table
                .get(comm_idx as usize)
                .cloned()
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Create SchedWakingFtraceEvent
        let waking = SchedWakingFtraceEvent {
            pid: compact.waking_pid.get(i).copied(),
            target_cpu: compact.waking_target_cpu.get(i).copied(),
            prio: compact.waking_prio.get(i).copied(),
            comm: Some(comm),
            ..Default::default()
        };

        // Create FtraceEvent wrapper
        let ftrace_event = FtraceEvent {
            timestamp: Some(waking_ts),
            event: Some(ftrace_event::Event::SchedWaking(waking)),
            ..Default::default()
        };

        events.push(FtraceEventWithIndex {
            event: ftrace_event,
            packet_index: packet_idx,
        });
    }

    // Expand sched_switch events
    let mut switch_ts = 0u64;
    let switch_count = compact.switch_timestamp.len();
    for i in 0..switch_count {
        // Reconstruct absolute timestamp from delta-encoded values
        switch_ts += compact.switch_timestamp[i];

        // Get command name from intern table
        let next_comm = if let Some(&comm_idx) = compact.switch_next_comm_index.get(i) {
            compact
                .intern_table
                .get(comm_idx as usize)
                .cloned()
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Create SchedSwitchFtraceEvent
        // Note: CompactSched doesn't include prev_pid/prev_comm in systing's format
        // These would need to be inferred from previous next_pid/next_comm
        let switch = SchedSwitchFtraceEvent {
            prev_state: compact.switch_prev_state.get(i).copied(),
            next_pid: compact.switch_next_pid.get(i).copied(),
            next_prio: compact.switch_next_prio.get(i).copied(),
            next_comm: Some(next_comm),
            ..Default::default()
        };

        // Create FtraceEvent wrapper
        let ftrace_event = FtraceEvent {
            timestamp: Some(switch_ts),
            event: Some(ftrace_event::Event::SchedSwitch(switch)),
            ..Default::default()
        };

        events.push(FtraceEventWithIndex {
            event: ftrace_event,
            packet_index: packet_idx,
        });
    }

    // Sort all events by timestamp
    events.sort_by_key(|e| e.event.timestamp.unwrap_or(0));

    events
}

impl PerfettoTrace {
    /// Parse a perfetto trace file from disk
    pub fn from_file(path: &Path) -> Result<Self> {
        // Read entire file into memory
        let bytes = fs::read(path)?;

        // Parse protobuf
        let trace = Trace::parse_from_bytes(&bytes)
            .map_err(|e| anyhow!("Failed to parse perfetto trace: {}", e))?;

        // Build trace structure with indexes
        Self::from_trace(trace)
    }

    /// Build indexed trace structure from parsed Trace protobuf
    fn from_trace(trace: Trace) -> Result<Self> {
        let mut processes = HashMap::new();
        let mut threads = HashMap::new();
        let mut ftrace_events_by_cpu: BTreeMap<u32, Vec<FtraceEventWithIndex>> = BTreeMap::new();
        let mut dsq_events: HashMap<u64, Vec<DsqEvent>> = HashMap::new();
        let mut system_stats: BTreeMap<u64, SysStats> = BTreeMap::new();
        let mut min_ts = u64::MAX;
        let mut max_ts = 0u64;

        // Track DSQ descriptors as we parse
        let mut dsq_descriptors: HashMap<u64, DsqDescriptor> = HashMap::new();
        let mut has_scx_events = false;

        // Track events storage
        let mut track_events: Vec<super::perfetto_track_event_types::ParsedTrackEvent> = Vec::new();
        let mut track_events_by_pid: HashMap<i32, Vec<usize>> = HashMap::new();
        let mut track_events_by_category: HashMap<String, Vec<usize>> = HashMap::new();
        let mut track_uuid_to_thread: HashMap<u64, (i32, i32)> = HashMap::new();

        // Intern tables for IID resolution (used by tools like wprof that use interned strings)
        // This is a fallback mechanism - if strings are directly present, they're used first
        let mut intern_tables = InternTables::default();

        // First pass: Extract processes, threads, track descriptors, and build intern tables
        for (packet_idx, packet) in trace.packet.iter().enumerate() {
            // Extract InternedData to build IID lookup tables
            // This is optional - only needed for tools that use interned strings (e.g., wprof)
            // interned_data is a MessageField, use .as_ref() to get Option<&InternedData>
            if let Some(interned_data) = packet.interned_data.as_ref() {
                // Event categories (field 1)
                for cat in &interned_data.event_categories {
                    if let (Some(iid), Some(name)) = (cat.iid, cat.name.as_ref()) {
                        intern_tables.event_categories.insert(iid, name.clone());
                    }
                }

                // Event names (field 2)
                for name_entry in &interned_data.event_names {
                    if let (Some(iid), Some(name)) = (name_entry.iid, name_entry.name.as_ref()) {
                        intern_tables.event_names.insert(iid, name.clone());
                    }
                }

                // Debug annotation names (field 3)
                for ann_name in &interned_data.debug_annotation_names {
                    if let (Some(iid), Some(name)) = (ann_name.iid, ann_name.name.as_ref()) {
                        intern_tables
                            .debug_annotation_names
                            .insert(iid, name.clone());
                    }
                }

                // Debug annotation string values (field 29)
                for ann_str in &interned_data.debug_annotation_string_values {
                    if let (Some(iid), Some(str_val)) = (ann_str.iid, ann_str.str.as_ref()) {
                        if let Ok(str_val_string) = String::from_utf8(str_val.clone()) {
                            intern_tables
                                .debug_annotation_string_values
                                .insert(iid, str_val_string);
                        }
                    }
                }
            }

            if let Some(data) = &packet.data {
                match data {
                    trace_packet::Data::ProcessTree(process_tree) => {
                        // Extract process information
                        for process in &process_tree.processes {
                            if let Some(pid) = process.pid {
                                processes.insert(
                                    pid,
                                    ProcessInfo {
                                        pid,
                                        cmdline: process.cmdline.clone(),
                                        name: None, // Will be filled from descriptors if available
                                    },
                                );
                            }
                        }
                    }
                    trace_packet::Data::TrackDescriptor(track_desc) => {
                        // Extract process information from TrackDescriptor
                        // (fallback for tools like wprof that don't emit ProcessTree)
                        if let Some(process) = track_desc.process.as_ref() {
                            if let Some(pid) = process.pid {
                                // Only insert if not already present from ProcessTree
                                processes.entry(pid).or_insert_with(|| ProcessInfo {
                                    pid,
                                    cmdline: process.cmdline.clone(),
                                    name: process.process_name.clone(),
                                });
                            }
                        }

                        // Extract thread information from TrackDescriptor
                        if let Some(thread) = track_desc.thread.as_ref() {
                            if let (Some(tid), Some(pid)) = (thread.tid, thread.pid) {
                                let key = ((pid as u64) << 32) | (tid as u64);
                                threads.insert(
                                    key,
                                    ThreadInfo {
                                        tid,
                                        pid,
                                        name: thread.thread_name.clone(),
                                    },
                                );
                                // Also add process entry if not present
                                processes.entry(pid).or_insert_with(|| ProcessInfo {
                                    pid,
                                    cmdline: vec![],
                                    name: thread.thread_name.clone(), // Use thread name as process name fallback
                                });
                                // Map track_uuid to (pid, tid) for TrackEvent resolution
                                if let Some(uuid) = track_desc.uuid {
                                    track_uuid_to_thread.insert(uuid, (pid, tid));
                                }
                            }
                        }

                        // Check for DSQ track descriptors (sched_ext specific)
                        if let Some(counter) = track_desc.counter.as_ref() {
                            if let Some(unit_name) = &counter.unit_name {
                                // DSQ tracks have unit names like "DSQ 0 latency ns" or "DSQ 0 nr_queued"
                                if unit_name.contains("DSQ ") && unit_name.contains("latency") {
                                    // Extract DSQ ID from track UUID
                                    if let Some(_uuid) = track_desc.uuid {
                                        // DSQ ID is encoded in the track name
                                        if let Some(name_str) = &track_desc.static_or_dynamic_name {
                                            use perfetto_protos::track_descriptor::track_descriptor::Static_or_dynamic_name;
                                            if let Static_or_dynamic_name::StaticName(name) =
                                                name_str
                                            {
                                                if let Some(dsq_id) = extract_dsq_id_from_name(name)
                                                {
                                                    has_scx_events = true;
                                                    dsq_descriptors.entry(dsq_id).or_insert(
                                                        DsqDescriptor {
                                                            dsq_id,
                                                            first_seen: u64::MAX,
                                                            last_seen: 0,
                                                            event_count: 0,
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Second pass: Extract events and build indexes
            if let Some(data) = &packet.data {
                match data {
                    trace_packet::Data::FtraceEvents(ftrace_bundle) => {
                        let cpu = ftrace_bundle.cpu.unwrap_or(0);

                        // Process individual FtraceEvents
                        for event in &ftrace_bundle.event {
                            // Track timestamp range
                            if let Some(ts) = event.timestamp {
                                min_ts = min_ts.min(ts);
                                max_ts = max_ts.max(ts);
                            }

                            // Add to per-CPU index
                            ftrace_events_by_cpu.entry(cpu).or_default().push(
                                FtraceEventWithIndex {
                                    event: event.clone(),
                                    packet_index: packet_idx,
                                },
                            );
                        }

                        // Process CompactSched format (used by systing and other tools)
                        if let Some(compact_sched) = ftrace_bundle.compact_sched.as_ref() {
                            let expanded_events =
                                expand_compact_sched(compact_sched, cpu, packet_idx);

                            // Track timestamp range from expanded events
                            for event_with_idx in &expanded_events {
                                if let Some(ts) = event_with_idx.event.timestamp {
                                    min_ts = min_ts.min(ts);
                                    max_ts = max_ts.max(ts);
                                }
                            }

                            // Add expanded events to per-CPU index
                            ftrace_events_by_cpu
                                .entry(cpu)
                                .or_default()
                                .extend(expanded_events);
                        }
                    }
                    trace_packet::Data::TrackEvent(track_event) => {
                        // Get timestamp from packet or track event
                        let timestamp_ns = if let Some(ts) = packet.timestamp {
                            ts
                        } else if let Some(ts_us) = extract_track_event_timestamp(track_event) {
                            ts_us * 1000 // Convert microseconds to nanoseconds
                        } else {
                            0 // No timestamp available
                        };

                        // Parse track event using helper function with intern tables for IID resolution
                        if let Some(mut parsed_event) =
                            super::perfetto_track_event_types::parse_track_event_with_interns(
                                track_event,
                                timestamp_ns,
                                &intern_tables,
                            )
                        {
                            // Resolve PID/TID from track_uuid if not in annotations
                            // This is needed for wprof traces where PID is in TrackDescriptor, not event
                            if parsed_event.metadata.pid.is_none() {
                                if let Some(uuid) = parsed_event.track_uuid {
                                    if let Some(&(pid, tid)) = track_uuid_to_thread.get(&uuid) {
                                        parsed_event.metadata.pid = Some(pid);
                                        parsed_event.metadata.tid = Some(tid);
                                    }
                                }
                            }

                            let event_idx = track_events.len();

                            // Index by PID if available
                            if let Some(pid) = parsed_event.metadata.pid {
                                track_events_by_pid.entry(pid).or_default().push(event_idx);
                            }

                            // Index by category
                            if let Some(ref category) = parsed_event.category {
                                track_events_by_category
                                    .entry(category.clone())
                                    .or_default()
                                    .push(event_idx);
                            }

                            // Update time range
                            min_ts = min_ts.min(timestamp_ns);
                            max_ts = max_ts.max(timestamp_ns);

                            // Store the parsed event
                            track_events.push(parsed_event);
                        }

                        // Also extract DSQ events from track events (legacy behavior)
                        if let Some(_uuid) = track_event.track_uuid {
                            // Check if this is a DSQ track by looking for it in descriptors
                            for (&dsq_id, desc) in dsq_descriptors.iter_mut() {
                                // This is a simplified check - in reality we'd match UUIDs properly
                                if let Some(ts) = extract_track_event_timestamp(track_event) {
                                    let ts_ns = ts * 1000; // Convert us to ns

                                    // Extract counter value
                                    let value = extract_counter_value(track_event);

                                    // Update descriptor
                                    desc.first_seen = desc.first_seen.min(ts_ns);
                                    desc.last_seen = desc.last_seen.max(ts_ns);
                                    desc.event_count += 1;

                                    // Create DSQ event (simplified - would need proper UUID matching)
                                    dsq_events.entry(dsq_id).or_default().push(DsqEvent {
                                        dsq_id,
                                        timestamp: ts_ns,
                                        latency_us: value,
                                        nr_queued: None, // Would be filled from separate track
                                    });
                                }
                            }
                        }
                    }
                    trace_packet::Data::SysStats(sys_stat) => {
                        if let Some(ts) = packet.timestamp {
                            system_stats.insert(ts, sys_stat.clone());
                            min_ts = min_ts.min(ts);
                            max_ts = max_ts.max(ts);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Build sched_ext metadata
        let scx_metadata = if has_scx_events {
            let mut dsq_ids: Vec<u64> = dsq_descriptors.keys().copied().collect();
            dsq_ids.sort_unstable();

            Some(SchedExtMetadata {
                scheduler_name: None, // Would be extracted from trace if available
                dsq_ids,
                dsq_descriptors,
                has_scx_events: true,
            })
        } else {
            None
        };

        Ok(PerfettoTrace {
            packets: trace.packet,
            processes,
            threads,
            ftrace_events_by_cpu,
            dsq_events,
            system_stats,
            time_range: (min_ts, max_ts),
            scx_metadata,
            track_events,
            track_events_by_pid,
            track_events_by_category,
            track_uuid_to_thread,
            capabilities: None, // Lazy-loaded on demand
            event_index: None,  // Lazy-loaded on demand
        })
    }

    /// Get all events within a time range
    pub fn get_events_by_time_range(&self, start_ns: u64, end_ns: u64) -> Vec<&FtraceEvent> {
        let mut events = Vec::new();

        for cpu_events in self.ftrace_events_by_cpu.values() {
            for event_with_idx in cpu_events {
                if let Some(ts) = event_with_idx.event.timestamp {
                    if ts >= start_ns && ts <= end_ns {
                        events.push(&event_with_idx.event);
                    }
                }
            }
        }

        events
    }

    /// Get all events for a specific CPU
    pub fn get_events_by_cpu(&self, cpu: u32) -> &[FtraceEventWithIndex] {
        self.ftrace_events_by_cpu
            .get(&cpu)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all events of a specific type
    pub fn get_events_by_type(&self, event_type: &str) -> Vec<&FtraceEvent> {
        let mut events = Vec::new();

        for cpu_events in self.ftrace_events_by_cpu.values() {
            for event_with_idx in cpu_events {
                let matches = match event_type {
                    "sched_switch" => matches!(
                        &event_with_idx.event.event,
                        Some(perfetto_protos::ftrace_event::ftrace_event::Event::SchedSwitch(_))
                    ),
                    "sched_wakeup" => matches!(
                        &event_with_idx.event.event,
                        Some(perfetto_protos::ftrace_event::ftrace_event::Event::SchedWakeup(_))
                    ),
                    "sched_waking" => matches!(
                        &event_with_idx.event.event,
                        Some(perfetto_protos::ftrace_event::ftrace_event::Event::SchedWaking(_))
                    ),
                    "sched_migrate" => matches!(
                        &event_with_idx.event.event,
                        Some(
                            perfetto_protos::ftrace_event::ftrace_event::Event::SchedMigrateTask(_)
                        )
                    ),
                    "softirq" => matches!(
                        &event_with_idx.event.event,
                        Some(perfetto_protos::ftrace_event::ftrace_event::Event::SoftirqEntry(_))
                            | Some(
                                perfetto_protos::ftrace_event::ftrace_event::Event::SoftirqExit(_)
                            )
                    ),
                    _ => false,
                };

                if matches {
                    events.push(&event_with_idx.event);
                }
            }
        }

        events
    }

    /// Check if trace has events of a given type (including TrackEvent equivalents)
    /// This method checks both ftrace events and mapped TrackEvent categories
    /// to support traces from different sources (e.g., wprof uses TrackEvents)
    pub fn has_event_type(&self, event_type: &str) -> bool {
        // First check ftrace events
        if !self.get_events_by_type(event_type).is_empty() {
            return true;
        }

        // Check if any TrackEvent category maps to this event type
        // This uses the reverse mapping from map_wprof_category_to_ftrace
        let matching_categories: &[&str] = match event_type {
            "sched_switch" => &["ONCPU", "PREEMPTEE", "PREEMPTOR"],
            "sched_wakeup" => &["WAKEE", "WAKEE_NEW"],
            "sched_waking" => &["WAKER", "WAKER_NEW"],
            "irq_handler_entry" => &["HARDIRQ"],
            "softirq_entry" => &["SOFTIRQ"],
            "sched_process_fork" => &["FORKING", "FORKED"],
            "sched_process_exit" => &["EXIT"],
            "sched_process_exec" => &["EXEC", "START"],
            _ => &[],
        };

        for category in matching_categories {
            if self.track_events_by_category.contains_key(*category) {
                return true;
            }
        }

        false
    }

    /// Get all processes in the trace
    pub fn get_processes(&self) -> &HashMap<i32, ProcessInfo> {
        &self.processes
    }

    /// Get sched_ext metadata
    pub fn get_scx_metadata(&self) -> Option<&SchedExtMetadata> {
        self.scx_metadata.as_ref()
    }

    /// Check if this is a sched_ext trace
    pub fn is_scx_trace(&self) -> bool {
        self.scx_metadata
            .as_ref()
            .map(|m| m.has_scx_events)
            .unwrap_or(false)
    }

    /// Get sched_ext events for a specific DSQ
    ///
    /// Returns SchedExtEventData for the specified DSQ extracted from the trace.
    /// Note: Currently returns simplified data; full DSQ event correlation
    /// requires UUID matching between TrackDescriptors and TrackEvents.
    pub fn get_scx_events_by_dsq(&self, _dsq_id: u64) -> Vec<SchedExtEventData> {
        // Full implementation would correlate:
        // 1. TrackDescriptor UUIDs for DSQ tracks
        // 2. TrackEvent counter values matching those UUIDs
        // 3. sched_switch events occurring at same timestamp
        // This requires more complex UUID tracking during parse phase.
        // For now, DSQ metadata is available via get_scx_metadata()
        Vec::new()
    }

    /// Get all track events
    pub fn get_track_events(&self) -> &[super::perfetto_track_event_types::ParsedTrackEvent] {
        &self.track_events
    }

    /// Get track events by category (e.g., "ONCPU", "WAKER", "WAKEE")
    pub fn get_track_events_by_category(
        &self,
        category: &str,
    ) -> Vec<&super::perfetto_track_event_types::ParsedTrackEvent> {
        self.track_events_by_category
            .get(category)
            .map(|indices| indices.iter().map(|&idx| &self.track_events[idx]).collect())
            .unwrap_or_default()
    }

    /// Get track events for a specific PID
    pub fn get_track_events_by_pid(
        &self,
        pid: i32,
    ) -> Vec<&super::perfetto_track_event_types::ParsedTrackEvent> {
        self.track_events_by_pid
            .get(&pid)
            .map(|indices| indices.iter().map(|&idx| &self.track_events[idx]).collect())
            .unwrap_or_default()
    }

    /// Get track events within a time range
    pub fn get_track_events_by_time_range(
        &self,
        start_ns: u64,
        end_ns: u64,
    ) -> Vec<&super::perfetto_track_event_types::ParsedTrackEvent> {
        self.track_events
            .iter()
            .filter(|e| e.timestamp_ns >= start_ns && e.timestamp_ns <= end_ns)
            .collect()
    }

    /// Get count of track events by category
    pub fn get_track_event_counts_by_category(&self) -> HashMap<String, usize> {
        self.track_events_by_category
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }

    /// Get total number of track events
    pub fn total_track_events(&self) -> usize {
        self.track_events.len()
    }

    /// Get list of available track event categories
    pub fn get_track_event_categories(&self) -> Vec<String> {
        self.track_events_by_category.keys().cloned().collect()
    }

    /// Calculate percentiles from a set of values
    pub fn calculate_percentiles(values: &[u64]) -> Percentiles {
        if values.is_empty() {
            return Percentiles {
                count: 0,
                min: 0,
                max: 0,
                mean: 0.0,
                median: 0,
                p95: 0,
                p99: 0,
                p999: 0,
            };
        }

        let mut sorted = values.to_vec();
        sorted.sort_unstable();

        let count = sorted.len();
        let min = sorted[0];
        let max = sorted[count - 1];
        let sum: u64 = sorted.iter().sum();
        let mean = sum as f64 / count as f64;

        // Calculate percentiles using nearest-rank method
        let percentile = |p: f64| -> u64 {
            let rank = (p * count as f64).ceil() as usize;
            sorted[rank.min(count) - 1]
        };

        Percentiles {
            count,
            min,
            max,
            mean,
            median: percentile(0.50),
            p95: percentile(0.95),
            p99: percentile(0.99),
            p999: percentile(0.999),
        }
    }

    /// Get the trace time range in nanoseconds
    pub fn time_range(&self) -> (u64, u64) {
        self.time_range
    }

    /// Get the total number of CPUs in the trace
    pub fn num_cpus(&self) -> usize {
        self.ftrace_events_by_cpu.len()
    }

    /// Get total number of ftrace events
    pub fn total_ftrace_events(&self) -> usize {
        self.ftrace_events_by_cpu.values().map(|v| v.len()).sum()
    }

    /// Get total number of events (ftrace + track events)
    pub fn total_events(&self) -> usize {
        self.total_ftrace_events() + self.track_events.len()
    }

    /// Get timeline of events for a specific process
    pub fn get_timeline_for_process(
        &self,
        pid: i32,
        start_ns: u64,
        end_ns: u64,
    ) -> ProcessTimeline {
        let mut events = Vec::new();
        let comm = self
            .processes
            .get(&pid)
            .and_then(|p| p.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Scan all CPUs for events related to this PID
        for (&cpu, cpu_events) in &self.ftrace_events_by_cpu {
            for event_with_idx in cpu_events {
                if let Some(ts) = event_with_idx.event.timestamp {
                    if ts < start_ns || ts > end_ns {
                        continue;
                    }

                    match &event_with_idx.event.event {
                        Some(ftrace_event::Event::SchedSwitch(switch)) => {
                            // Check if this process was scheduled on
                            if switch.next_pid == Some(pid) {
                                events.push(ProcessTimelineEvent::Scheduled { cpu, timestamp: ts });
                            }
                            // Check if this process was scheduled off
                            if switch.prev_pid == Some(pid) {
                                events.push(ProcessTimelineEvent::Preempted {
                                    cpu,
                                    timestamp: ts,
                                    state: switch.prev_state.unwrap_or(0),
                                });
                            }
                        }
                        Some(ftrace_event::Event::SchedWakeup(wakeup)) => {
                            if wakeup.pid == Some(pid) {
                                events.push(ProcessTimelineEvent::Woken {
                                    by_pid: event_with_idx.event.pid.unwrap_or(0),
                                    timestamp: ts,
                                });
                            }
                        }
                        Some(ftrace_event::Event::SchedMigrateTask(migrate)) => {
                            if migrate.pid == Some(pid) {
                                events.push(ProcessTimelineEvent::Migrated {
                                    from_cpu: 0, // Would need to track current CPU
                                    to_cpu: migrate.dest_cpu.unwrap_or(0) as u32,
                                    timestamp: ts,
                                });
                            }
                        }
                        Some(ftrace_event::Event::SchedProcessFork(fork)) => {
                            if fork.parent_pid == Some(pid) {
                                events.push(ProcessTimelineEvent::Forked {
                                    child_pid: fork.child_pid.unwrap_or(0),
                                    timestamp: ts,
                                });
                            }
                        }
                        Some(ftrace_event::Event::SchedProcessExit(exit)) => {
                            if exit.pid == Some(pid) {
                                events.push(ProcessTimelineEvent::Exited { timestamp: ts });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Sort events by timestamp
        events.sort_by_key(|e| e.timestamp());

        ProcessTimeline { pid, comm, events }
    }

    /// Get timeline of events for a specific CPU
    pub fn get_cpu_timeline(&self, cpu: u32, start_ns: u64, end_ns: u64) -> CpuTimeline {
        let mut events = Vec::new();

        if let Some(cpu_events) = self.ftrace_events_by_cpu.get(&cpu) {
            for event_with_idx in cpu_events {
                if let Some(ts) = event_with_idx.event.timestamp {
                    if ts < start_ns || ts > end_ns {
                        continue;
                    }

                    match &event_with_idx.event.event {
                        Some(ftrace_event::Event::SchedSwitch(switch)) => {
                            events.push(CpuTimelineEvent {
                                timestamp: ts,
                                event_type: CpuEventType::ContextSwitch {
                                    prev_pid: switch.prev_pid.unwrap_or(0) as u32,
                                    next_pid: switch.next_pid.unwrap_or(0) as u32,
                                    prev_comm: switch.prev_comm.clone().unwrap_or_default(),
                                    next_comm: switch.next_comm.clone().unwrap_or_default(),
                                },
                            });
                        }
                        Some(ftrace_event::Event::SoftirqEntry(entry)) => {
                            events.push(CpuTimelineEvent {
                                timestamp: ts,
                                event_type: CpuEventType::Softirq {
                                    vec: entry.vec.unwrap_or(0),
                                    entry: true,
                                },
                            });
                        }
                        Some(ftrace_event::Event::SoftirqExit(exit)) => {
                            events.push(CpuTimelineEvent {
                                timestamp: ts,
                                event_type: CpuEventType::Softirq {
                                    vec: exit.vec.unwrap_or(0),
                                    entry: false,
                                },
                            });
                        }
                        _ => {}
                    }
                }
            }
        }

        CpuTimeline { cpu, events }
    }

    /// Build capabilities from trace data
    pub fn build_capabilities(&self) -> super::perfetto_parser_enhanced::TraceCapabilities {
        super::perfetto_parser_enhanced::TraceCapabilities::from_trace(self)
    }

    /// Check if analyzer requirements are met
    pub fn supports_analysis(&self, required_events: &[&str]) -> bool {
        let caps = self.build_capabilities();
        caps.supports_analyzer(required_events)
    }

    /// Get available event types as list
    pub fn list_event_types(&self) -> Vec<String> {
        let caps = self.build_capabilities();
        caps.list_event_types()
    }

    /// Build generic event index
    pub fn build_event_index(&self) -> Arc<super::perfetto_parser_enhanced::EventTypeIndex> {
        Arc::new(super::perfetto_parser_enhanced::EventTypeIndex::build_from_trace(self))
    }

    /// Get thread information by TID
    pub fn get_thread_info(&self, tid: i32) -> Option<&ThreadInfo> {
        // Try to find the thread in the threads map
        // We don't know the PID, so we need to search
        self.threads
            .values()
            .find(|&thread_info| thread_info.tid == tid)
    }

    /// Get TGID (process ID) for a given TID (thread ID)
    /// Returns None if thread info not found, or tid if it's likely the main thread
    pub fn get_tgid_for_tid(&self, tid: i32) -> Option<i32> {
        self.get_thread_info(tid).map(|info| info.pid)
    }

    /// Get all threads for a given TGID (process ID)
    pub fn get_threads_for_tgid(&self, tgid: i32) -> Vec<&ThreadInfo> {
        self.threads
            .values()
            .filter(|info| info.pid == tgid)
            .collect()
    }

    /// Get all unique TGIDs (process IDs) in the trace
    pub fn get_all_tgids(&self) -> Vec<i32> {
        let mut tgids: Vec<i32> = self
            .threads
            .values()
            .map(|info| info.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        tgids.sort_unstable();
        tgids
    }
}

/// Timeline of events for a specific process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTimeline {
    pub pid: i32,
    pub comm: String,
    pub events: Vec<ProcessTimelineEvent>,
}

/// Events in a process timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessTimelineEvent {
    Scheduled {
        cpu: u32,
        timestamp: u64,
    },
    Preempted {
        cpu: u32,
        timestamp: u64,
        state: i64,
    },
    Woken {
        by_pid: u32,
        timestamp: u64,
    },
    Migrated {
        from_cpu: u32,
        to_cpu: u32,
        timestamp: u64,
    },
    Forked {
        child_pid: i32,
        timestamp: u64,
    },
    Exited {
        timestamp: u64,
    },
}

impl ProcessTimelineEvent {
    pub fn timestamp(&self) -> u64 {
        match self {
            ProcessTimelineEvent::Scheduled { timestamp, .. } => *timestamp,
            ProcessTimelineEvent::Preempted { timestamp, .. } => *timestamp,
            ProcessTimelineEvent::Woken { timestamp, .. } => *timestamp,
            ProcessTimelineEvent::Migrated { timestamp, .. } => *timestamp,
            ProcessTimelineEvent::Forked { timestamp, .. } => *timestamp,
            ProcessTimelineEvent::Exited { timestamp } => *timestamp,
        }
    }
}

/// Timeline of events for a specific CPU
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTimeline {
    pub cpu: u32,
    pub events: Vec<CpuTimelineEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTimelineEvent {
    pub timestamp: u64,
    pub event_type: CpuEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpuEventType {
    ContextSwitch {
        prev_pid: u32,
        next_pid: u32,
        prev_comm: String,
        next_comm: String,
    },
    Softirq {
        vec: u32,
        entry: bool,
    },
}

/// Extract DSQ ID from track descriptor name
fn extract_dsq_id_from_name(name: &str) -> Option<u64> {
    // Track names are like "DSQ 0 latency ns" or "DSQ 123 nr_queued"
    if !name.starts_with("DSQ ") {
        return None;
    }

    let parts: Vec<&str> = name.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    parts[1].parse::<u64>().ok()
}

/// Extract timestamp from track event
fn extract_track_event_timestamp(event: &TrackEvent) -> Option<u64> {
    use perfetto_protos::track_event::track_event::Timestamp;
    match &event.timestamp {
        Some(Timestamp::TimestampAbsoluteUs(ts)) => Some(*ts as u64),
        Some(Timestamp::TimestampDeltaUs(_delta)) => {
            // Delta timestamps would need base timestamp from previous event
            None
        }
        None => None,
        _ => None,
    }
}

/// Extract counter value from track event
fn extract_counter_value(event: &TrackEvent) -> Option<i64> {
    use perfetto_protos::track_event::track_event::Counter_value_field;
    match &event.counter_value_field {
        Some(Counter_value_field::CounterValue(val)) => Some(*val),
        Some(Counter_value_field::DoubleCounterValue(val)) => Some(*val as i64),
        None => None,
        _ => None,
    }
}
