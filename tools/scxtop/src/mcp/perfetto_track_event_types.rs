// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! TrackEvent types and parsing for wprof-generated perfetto traces
//!
//! This module handles parsing of TrackEvent messages which are used by wprof
//! to encode rich scheduling information including:
//! - ONCPU slices (task on-CPU periods)
//! - WAKER/WAKEE instant events (wakeup relationships)
//! - PREEMPTOR/PREEMPTEE events (preemption tracking)
//! - Perf counter deltas
//! - Sched-ext metadata (layer_id, dsq_id)
//! - Compound delay tracking

use perfetto_protos::debug_annotation::debug_annotation;
use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::track_event::{track_event, TrackEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TrackEvent type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackEventType {
    /// Slice begin event (e.g., ONCPU start)
    SliceBegin,
    /// Slice end event (e.g., ONCPU end)
    SliceEnd,
    /// Instant event (e.g., WAKER, WAKEE)
    Instant,
    /// Counter event
    Counter,
    /// Unknown/unspecified
    Unspecified,
}

impl From<track_event::Type> for TrackEventType {
    fn from(t: track_event::Type) -> Self {
        match t {
            track_event::Type::TYPE_SLICE_BEGIN => TrackEventType::SliceBegin,
            track_event::Type::TYPE_SLICE_END => TrackEventType::SliceEnd,
            track_event::Type::TYPE_INSTANT => TrackEventType::Instant,
            track_event::Type::TYPE_COUNTER => TrackEventType::Counter,
            track_event::Type::TYPE_UNSPECIFIED => TrackEventType::Unspecified,
        }
    }
}

/// Parsed debug annotation with name and value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub name: String,
    pub value: AnnotationValue,
}

/// Annotation value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnnotationValue {
    Bool(bool),
    Uint(u64),
    Int(i64),
    Double(f64),
    String(String),
    Pointer(u64),
}

/// Parsed TrackEvent with all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTrackEvent {
    /// Event timestamp (nanoseconds)
    pub timestamp_ns: u64,
    /// Event type
    pub event_type: TrackEventType,
    /// Category name (e.g., "ONCPU", "WAKER")
    pub category: Option<String>,
    /// Event name
    pub name: Option<String>,
    /// Track UUID
    pub track_uuid: Option<u64>,
    /// Debug annotations
    pub annotations: Vec<Annotation>,
    /// Parsed metadata for quick access
    pub metadata: TrackEventMetadata,
}

/// Common metadata extracted from annotations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrackEventMetadata {
    /// CPU ID
    pub cpu: Option<u32>,
    /// NUMA node
    pub numa_node: Option<u32>,
    /// Sched-ext layer ID
    pub scx_layer_id: Option<u64>,
    /// Sched-ext dispatch queue ID
    pub scx_dsq_id: Option<u64>,
    /// Waking delay in microseconds
    pub waking_delay_us: Option<u64>,
    /// Compound delay in microseconds
    pub compound_delay_us: Option<u64>,
    /// Compound chain length
    pub compound_chain_len: Option<u64>,
    /// Perf counter deltas
    pub perf_counters: HashMap<String, i64>,
    /// Task PID (from annotations)
    pub pid: Option<i32>,
    /// Task TID (from annotations)
    pub tid: Option<i32>,
    /// Task comm (from annotations)
    pub comm: Option<String>,
}

/// ONCPU slice event (task on-CPU period)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OncpuSliceEvent {
    pub timestamp_ns: u64,
    pub is_begin: bool,
    pub track_uuid: u64,
    pub cpu: u32,
    pub pid: i32,
    pub tid: i32,
    pub comm: String,
    pub metadata: TrackEventMetadata,
}

/// Wakeup instant event (WAKER or WAKEE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeupInstantEvent {
    pub timestamp_ns: u64,
    pub is_waker: bool, // true for WAKER, false for WAKEE
    pub waker_pid: i32,
    pub wakee_pid: i32,
    pub wakee_tid: i32,
    pub target_cpu: Option<u32>,
    pub waking_delay_us: Option<u64>,
    pub metadata: TrackEventMetadata,
}

/// Preemption instant event (PREEMPTOR or PREEMPTEE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreemptionInstantEvent {
    pub timestamp_ns: u64,
    pub is_preemptor: bool, // true for PREEMPTOR, false for PREEMPTEE
    pub preemptor_pid: i32,
    pub preemptee_pid: i32,
    pub cpu: u32,
    pub metadata: TrackEventMetadata,
}

/// Perf counter event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfCounterEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub counter_deltas: HashMap<String, i64>,
}

/// Process lifecycle event (FORK, EXEC, EXIT, FREE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLifecycleEvent {
    pub timestamp_ns: u64,
    pub event_type: ProcessLifecycleType,
    pub pid: i32,
    pub parent_pid: Option<i32>,
    pub comm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessLifecycleType {
    Fork,
    Exec,
    Exit,
    Free,
}

/// IRQ/Softirq/Workqueue TrackEvent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptTrackEvent {
    pub timestamp_ns: u64,
    pub event_type: InterruptEventType,
    pub is_begin: bool,
    pub cpu: u32,
    pub irq_nr: Option<u32>,
    pub handler_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterruptEventType {
    HardIrq,
    SoftIrq,
    Workqueue,
}

/// Helper function to extract annotation value as u64
pub fn get_annotation_uint(annotations: &[Annotation], name: &str) -> Option<u64> {
    annotations.iter().find_map(|ann| {
        if ann.name == name {
            match &ann.value {
                AnnotationValue::Uint(v) => Some(*v),
                AnnotationValue::Int(v) if *v >= 0 => Some(*v as u64),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Helper function to extract annotation value as i64
pub fn get_annotation_int(annotations: &[Annotation], name: &str) -> Option<i64> {
    annotations.iter().find_map(|ann| {
        if ann.name == name {
            match &ann.value {
                AnnotationValue::Int(v) => Some(*v),
                AnnotationValue::Uint(v) if *v <= i64::MAX as u64 => Some(*v as i64),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Helper function to extract annotation value as string
pub fn get_annotation_string(annotations: &[Annotation], name: &str) -> Option<String> {
    annotations.iter().find_map(|ann| {
        if ann.name == name {
            match &ann.value {
                AnnotationValue::String(v) => Some(v.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Parse TrackEvent into our internal representation
pub fn parse_track_event(event: &TrackEvent, timestamp_ns: u64) -> Option<ParsedTrackEvent> {
    // Call the new function with empty intern tables for backward compatibility
    parse_track_event_with_interns(
        event,
        timestamp_ns,
        &super::perfetto_parser::InternTables::default(),
    )
}

/// Parse TrackEvent with IID resolution using intern tables
///
/// This function supports both standard Perfetto traces (with inline strings) and
/// traces from tools like wprof that use interned strings (IIDs) for efficiency.
/// String values are checked first; IID resolution is only used as a fallback.
pub fn parse_track_event_with_interns(
    event: &TrackEvent,
    timestamp_ns: u64,
    intern_tables: &super::perfetto_parser::InternTables,
) -> Option<ParsedTrackEvent> {
    // Extract event type
    let event_type = event
        .type_
        .as_ref()
        .map(|t| TrackEventType::from(t.enum_value_or_default()))
        .unwrap_or(TrackEventType::Unspecified);

    // Extract category - check string categories first, then IIDs
    let category = if !event.categories.is_empty() {
        Some(event.categories[0].clone())
    } else if !event.category_iids.is_empty() {
        // Resolve category IID using intern table
        let iid = event.category_iids[0];
        intern_tables.event_categories.get(&iid).cloned()
    } else {
        // Fallback: check event name (older format)
        match &event.name_field {
            Some(track_event::Name_field::Name(n)) => Some(n.clone()),
            Some(track_event::Name_field::NameIid(iid)) => {
                intern_tables.event_names.get(iid).cloned()
            }
            _ => None,
        }
    };

    // Extract name - check string name first, then IID
    let name = match &event.name_field {
        Some(track_event::Name_field::Name(n)) => Some(n.clone()),
        Some(track_event::Name_field::NameIid(iid)) => intern_tables.event_names.get(iid).cloned(),
        _ => None,
    };

    // Parse debug annotations with IID resolution
    let annotations = parse_annotations_with_interns(&event.debug_annotations, intern_tables);

    // Extract common metadata
    let metadata = extract_metadata(&annotations);

    Some(ParsedTrackEvent {
        timestamp_ns,
        event_type,
        category,
        name,
        track_uuid: event.track_uuid,
        annotations,
        metadata,
    })
}

/// Parse debug annotations with IID resolution using intern tables
///
/// Supports both inline strings and interned strings (IIDs).
/// String values are checked first; IID resolution is only used as a fallback.
#[allow(dead_code)]
fn parse_annotations(debug_annotations: &[DebugAnnotation]) -> Vec<Annotation> {
    parse_annotations_with_interns(
        debug_annotations,
        &super::perfetto_parser::InternTables::default(),
    )
}

/// Parse debug annotations with IID resolution using intern tables
fn parse_annotations_with_interns(
    debug_annotations: &[DebugAnnotation],
    intern_tables: &super::perfetto_parser::InternTables,
) -> Vec<Annotation> {
    debug_annotations
        .iter()
        .filter_map(|ann| {
            // Get annotation name - check string name first, then IID
            let name = match &ann.name_field {
                Some(debug_annotation::Name_field::Name(n)) => n.clone(),
                Some(debug_annotation::Name_field::NameIid(iid)) => {
                    intern_tables.debug_annotation_names.get(iid).cloned()?
                }
                _ => return None,
            };

            // Get annotation value - check all value types including string_value_iid
            let value = match &ann.value {
                Some(debug_annotation::Value::BoolValue(v)) => AnnotationValue::Bool(*v),
                Some(debug_annotation::Value::UintValue(v)) => AnnotationValue::Uint(*v),
                Some(debug_annotation::Value::IntValue(v)) => AnnotationValue::Int(*v),
                Some(debug_annotation::Value::DoubleValue(v)) => AnnotationValue::Double(*v),
                Some(debug_annotation::Value::StringValue(v)) => AnnotationValue::String(v.clone()),
                Some(debug_annotation::Value::PointerValue(v)) => AnnotationValue::Pointer(*v),
                Some(debug_annotation::Value::StringValueIid(iid)) => {
                    // Resolve string value IID using intern table
                    let resolved = intern_tables
                        .debug_annotation_string_values
                        .get(iid)
                        .cloned()
                        .unwrap_or_else(|| format!("<iid:{}>", iid));
                    AnnotationValue::String(resolved)
                }
                _ => return None,
            };

            Some(Annotation { name, value })
        })
        .collect()
}

/// Extract common metadata from annotations
fn extract_metadata(annotations: &[Annotation]) -> TrackEventMetadata {
    let mut metadata = TrackEventMetadata::default();

    for ann in annotations {
        match ann.name.as_str() {
            "cpu" => metadata.cpu = get_annotation_uint(annotations, "cpu").map(|v| v as u32),
            "numa_node" => {
                metadata.numa_node = get_annotation_uint(annotations, "numa_node").map(|v| v as u32)
            }
            "scx_layer_id" => {
                metadata.scx_layer_id = get_annotation_uint(annotations, "scx_layer_id")
            }
            "scx_dsq_id" => metadata.scx_dsq_id = get_annotation_uint(annotations, "scx_dsq_id"),
            "waking_delay_us" => {
                metadata.waking_delay_us = get_annotation_uint(annotations, "waking_delay_us")
            }
            "compound_delay_us" => {
                metadata.compound_delay_us = get_annotation_uint(annotations, "compound_delay_us")
            }
            "compound_chain_len" => {
                metadata.compound_chain_len = get_annotation_uint(annotations, "compound_chain_len")
            }
            "pid" => metadata.pid = get_annotation_int(annotations, "pid").map(|v| v as i32),
            "tid" => metadata.tid = get_annotation_int(annotations, "tid").map(|v| v as i32),
            "comm" => metadata.comm = get_annotation_string(annotations, "comm"),
            // Perf counters typically have names like "instructions", "cycles", etc.
            _ if is_perf_counter_name(&ann.name) => {
                if let Some(val) = get_annotation_int(annotations, &ann.name) {
                    metadata.perf_counters.insert(ann.name.clone(), val);
                }
            }
            _ => {}
        }
    }

    metadata
}

/// Check if annotation name looks like a perf counter
fn is_perf_counter_name(name: &str) -> bool {
    matches!(
        name,
        "instructions"
            | "cycles"
            | "cache_references"
            | "cache_misses"
            | "branch_instructions"
            | "branch_misses"
            | "stalled_cycles_frontend"
            | "stalled_cycles_backend"
    )
}

/// Parse ONCPU slice event from TrackEvent
pub fn parse_oncpu_slice(event: &ParsedTrackEvent) -> Option<OncpuSliceEvent> {
    if event.category.as_deref() != Some("ONCPU") {
        return None;
    }

    let is_begin = matches!(event.event_type, TrackEventType::SliceBegin);
    let track_uuid = event.track_uuid?;
    let cpu = event.metadata.cpu?;
    let pid = event.metadata.pid?;
    let tid = event.metadata.tid?;
    let comm = event.metadata.comm.clone()?;

    Some(OncpuSliceEvent {
        timestamp_ns: event.timestamp_ns,
        is_begin,
        track_uuid,
        cpu,
        pid,
        tid,
        comm,
        metadata: event.metadata.clone(),
    })
}

/// Parse wakeup instant event from TrackEvent
pub fn parse_wakeup_instant(event: &ParsedTrackEvent) -> Option<WakeupInstantEvent> {
    let category = event.category.as_deref()?;
    let is_waker = match category {
        "WAKER" => true,
        "WAKEE" => false,
        _ => return None,
    };

    if event.event_type != TrackEventType::Instant {
        return None;
    }

    // Extract PIDs from annotations
    let waker_pid = get_annotation_int(&event.annotations, "waker_pid")? as i32;
    let wakee_pid = get_annotation_int(&event.annotations, "wakee_pid")? as i32;
    let wakee_tid = get_annotation_int(&event.annotations, "wakee_tid")? as i32;
    let target_cpu = get_annotation_uint(&event.annotations, "target_cpu").map(|v| v as u32);

    Some(WakeupInstantEvent {
        timestamp_ns: event.timestamp_ns,
        is_waker,
        waker_pid,
        wakee_pid,
        wakee_tid,
        target_cpu,
        waking_delay_us: event.metadata.waking_delay_us,
        metadata: event.metadata.clone(),
    })
}

/// Parse preemption instant event from TrackEvent
pub fn parse_preemption_instant(event: &ParsedTrackEvent) -> Option<PreemptionInstantEvent> {
    let category = event.category.as_deref()?;
    let is_preemptor = match category {
        "PREEMPTOR" => true,
        "PREEMPTEE" => false,
        _ => return None,
    };

    if event.event_type != TrackEventType::Instant {
        return None;
    }

    let preemptor_pid = get_annotation_int(&event.annotations, "preemptor_pid")? as i32;
    let preemptee_pid = get_annotation_int(&event.annotations, "preemptee_pid")? as i32;
    let cpu = event.metadata.cpu?;

    Some(PreemptionInstantEvent {
        timestamp_ns: event.timestamp_ns,
        is_preemptor,
        preemptor_pid,
        preemptee_pid,
        cpu,
        metadata: event.metadata.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_annotation_helpers() {
        let annotations = vec![
            Annotation {
                name: "cpu".to_string(),
                value: AnnotationValue::Uint(5),
            },
            Annotation {
                name: "pid".to_string(),
                value: AnnotationValue::Int(1234),
            },
            Annotation {
                name: "comm".to_string(),
                value: AnnotationValue::String("test".to_string()),
            },
        ];

        assert_eq!(get_annotation_uint(&annotations, "cpu"), Some(5));
        assert_eq!(get_annotation_int(&annotations, "pid"), Some(1234));
        assert_eq!(
            get_annotation_string(&annotations, "comm"),
            Some("test".to_string())
        );
        assert_eq!(get_annotation_uint(&annotations, "missing"), None);
    }

    #[test]
    fn test_perf_counter_detection() {
        assert!(is_perf_counter_name("instructions"));
        assert!(is_perf_counter_name("cycles"));
        assert!(!is_perf_counter_name("cpu"));
        assert!(!is_perf_counter_name("scx_layer_id"));
    }
}
