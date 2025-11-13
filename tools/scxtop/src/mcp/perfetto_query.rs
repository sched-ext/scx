// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Phase 5: Generic Query Framework
//!
//! Provides SQL-like query capabilities for perfetto traces with flexible
//! filtering, aggregation, and cross-event correlation.

use super::perfetto_parser::PerfettoTrace;
use perfetto_protos::ftrace_event::ftrace_event;
use perfetto_protos::ftrace_event::FtraceEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generic query builder for perfetto traces
pub struct QueryBuilder {
    event_type_filter: Option<String>,
    cpu_filter: Option<u32>,
    pid_filter: Option<i32>,
    time_range: Option<(u64, u64)>,
    field_filters: Vec<FieldFilter>,
    limit: Option<usize>,
    offset: usize,
}

impl QueryBuilder {
    pub fn new() -> Self {
        Self {
            event_type_filter: None,
            cpu_filter: None,
            pid_filter: None,
            time_range: None,
            field_filters: Vec::new(),
            limit: None,
            offset: 0,
        }
    }

    /// Filter by event type (e.g., "sched_switch", "sched_wakeup")
    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type_filter = Some(event_type.into());
        self
    }

    /// Filter by CPU
    pub fn cpu(mut self, cpu: u32) -> Self {
        self.cpu_filter = Some(cpu);
        self
    }

    /// Filter by PID
    pub fn pid(mut self, pid: i32) -> Self {
        self.pid_filter = Some(pid);
        self
    }

    /// Filter by time range (start_ns, end_ns)
    pub fn time_range(mut self, start_ns: u64, end_ns: u64) -> Self {
        self.time_range = Some((start_ns, end_ns));
        self
    }

    /// Add a field filter (e.g., "prev_state == 1")
    pub fn where_field(mut self, filter: FieldFilter) -> Self {
        self.field_filters.push(filter);
        self
    }

    /// Limit number of results
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Skip first N results
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Execute query and return matching events
    pub fn execute(self, trace: &PerfettoTrace) -> QueryResult {
        let start_time = std::time::Instant::now();

        // Get candidate events based on filters
        let events = if let Some(cpu) = self.cpu_filter {
            trace
                .get_events_by_cpu(cpu)
                .iter()
                .map(|e| &e.event)
                .collect::<Vec<_>>()
        } else if let Some((start, end)) = self.time_range {
            trace.get_events_by_time_range(start, end)
        } else if let Some(ref event_type) = self.event_type_filter {
            trace.get_events_by_type(event_type)
        } else {
            trace.get_events_by_time_range(0, u64::MAX)
        };

        // Apply additional filters
        let filtered_events: Vec<QueryEvent> = events
            .iter()
            .filter_map(|event| {
                // Check event type filter
                if let Some(ref event_type) = self.event_type_filter {
                    let matches = match event_type.as_str() {
                        "sched_switch" => {
                            matches!(event.event, Some(ftrace_event::Event::SchedSwitch(_)))
                        }
                        "sched_wakeup" => {
                            matches!(event.event, Some(ftrace_event::Event::SchedWakeup(_)))
                        }
                        "sched_waking" => {
                            matches!(event.event, Some(ftrace_event::Event::SchedWaking(_)))
                        }
                        "sched_migrate" => {
                            matches!(event.event, Some(ftrace_event::Event::SchedMigrateTask(_)))
                        }
                        "softirq_entry" => {
                            matches!(event.event, Some(ftrace_event::Event::SoftirqEntry(_)))
                        }
                        "softirq_exit" => {
                            matches!(event.event, Some(ftrace_event::Event::SoftirqExit(_)))
                        }
                        "irq_handler_entry" => {
                            matches!(event.event, Some(ftrace_event::Event::IrqHandlerEntry(_)))
                        }
                        "irq_handler_exit" => {
                            matches!(event.event, Some(ftrace_event::Event::IrqHandlerExit(_)))
                        }
                        "cpu_frequency" => {
                            matches!(event.event, Some(ftrace_event::Event::CpuFrequency(_)))
                        }
                        "cpu_idle" => matches!(event.event, Some(ftrace_event::Event::CpuIdle(_))),
                        _ => true,
                    };
                    if !matches {
                        return None;
                    }
                }

                // Check PID filter
                if let Some(pid_filter) = self.pid_filter {
                    if event.pid != Some(pid_filter as u32) {
                        return None;
                    }
                }

                // Check field filters
                for field_filter in &self.field_filters {
                    if !field_filter.matches(event) {
                        return None;
                    }
                }

                Some(QueryEvent::from_ftrace_event(event))
            })
            .skip(self.offset)
            .take(self.limit.unwrap_or(usize::MAX))
            .collect();

        let query_time = start_time.elapsed();

        QueryResult {
            events: filtered_events,
            total_matched: events.len(),
            query_time_ms: query_time.as_millis() as u64,
        }
    }
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Field filter for event attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldFilter {
    pub field: String,
    pub operator: FilterOperator,
    pub value: FilterValue,
}

impl FieldFilter {
    pub fn new(field: impl Into<String>, operator: FilterOperator, value: FilterValue) -> Self {
        Self {
            field: field.into(),
            operator,
            value,
        }
    }

    /// Check if event matches this filter
    pub fn matches(&self, event: &FtraceEvent) -> bool {
        // Extract field value from event
        let event_value = self.extract_field_value(event);

        match event_value {
            Some(val) => self.operator.compare(&val, &self.value),
            None => false,
        }
    }

    fn extract_field_value(&self, event: &FtraceEvent) -> Option<FilterValue> {
        match &event.event {
            Some(ftrace_event::Event::SchedSwitch(ss)) => match self.field.as_str() {
                "prev_pid" => ss.prev_pid.map(|p| FilterValue::Int(p as i64)),
                "next_pid" => ss.next_pid.map(|p| FilterValue::Int(p as i64)),
                "prev_state" => ss.prev_state.map(FilterValue::Int),
                "prev_prio" => ss.prev_prio.map(|p| FilterValue::Int(p as i64)),
                "next_prio" => ss.next_prio.map(|p| FilterValue::Int(p as i64)),
                "prev_comm" => ss.prev_comm.clone().map(FilterValue::String),
                "next_comm" => ss.next_comm.clone().map(FilterValue::String),
                _ => None,
            },
            Some(ftrace_event::Event::SchedWakeup(sw)) => match self.field.as_str() {
                "pid" => sw.pid.map(|p| FilterValue::Int(p as i64)),
                "prio" => sw.prio.map(|p| FilterValue::Int(p as i64)),
                "target_cpu" => sw.target_cpu.map(|c| FilterValue::Int(c as i64)),
                "comm" => sw.comm.clone().map(FilterValue::String),
                _ => None,
            },
            Some(ftrace_event::Event::SoftirqEntry(se)) => match self.field.as_str() {
                "vec" => se.vec.map(|v| FilterValue::Int(v as i64)),
                _ => None,
            },
            Some(ftrace_event::Event::IrqHandlerEntry(ie)) => match self.field.as_str() {
                "irq" => ie.irq.map(|i| FilterValue::Int(i as i64)),
                "name" => ie.name.clone().map(FilterValue::String),
                _ => None,
            },
            Some(ftrace_event::Event::CpuFrequency(cf)) => match self.field.as_str() {
                "state" => cf.state.map(|s| FilterValue::Int(s as i64)),
                "cpu_id" => cf.cpu_id.map(|c| FilterValue::Int(c as i64)),
                _ => None,
            },
            Some(ftrace_event::Event::CpuIdle(ci)) => match self.field.as_str() {
                "state" => ci.state.map(|s| FilterValue::Int(s as i64)),
                "cpu_id" => ci.cpu_id.map(|c| FilterValue::Int(c as i64)),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Filter operators
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FilterOperator {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    Contains,
}

impl FilterOperator {
    pub fn compare(&self, left: &FilterValue, right: &FilterValue) -> bool {
        match (left, right) {
            (FilterValue::Int(l), FilterValue::Int(r)) => match self {
                Self::Equal => l == r,
                Self::NotEqual => l != r,
                Self::GreaterThan => l > r,
                Self::LessThan => l < r,
                Self::GreaterOrEqual => l >= r,
                Self::LessOrEqual => l <= r,
                _ => false,
            },
            (FilterValue::String(l), FilterValue::String(r)) => match self {
                Self::Equal => l == r,
                Self::NotEqual => l != r,
                Self::Contains => l.contains(r),
                _ => false,
            },
            _ => false,
        }
    }
}

/// Filter value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterValue {
    Int(i64),
    String(String),
}

/// Query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub events: Vec<QueryEvent>,
    pub total_matched: usize,
    pub query_time_ms: u64,
}

/// Simplified event representation for query results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryEvent {
    pub timestamp: Option<u64>,
    pub pid: Option<i32>,
    pub event_type: String,
    pub fields: HashMap<String, String>,
}

impl QueryEvent {
    fn from_ftrace_event(event: &FtraceEvent) -> Self {
        let mut fields = HashMap::new();
        let event_type;

        match &event.event {
            Some(ftrace_event::Event::SchedSwitch(ss)) => {
                event_type = "sched_switch".to_string();
                if let Some(prev_pid) = ss.prev_pid {
                    fields.insert("prev_pid".to_string(), prev_pid.to_string());
                }
                if let Some(next_pid) = ss.next_pid {
                    fields.insert("next_pid".to_string(), next_pid.to_string());
                }
                if let Some(prev_state) = ss.prev_state {
                    fields.insert("prev_state".to_string(), prev_state.to_string());
                }
                if let Some(ref prev_comm) = ss.prev_comm {
                    fields.insert("prev_comm".to_string(), prev_comm.clone());
                }
                if let Some(ref next_comm) = ss.next_comm {
                    fields.insert("next_comm".to_string(), next_comm.clone());
                }
            }
            Some(ftrace_event::Event::SchedWakeup(sw)) => {
                event_type = "sched_wakeup".to_string();
                if let Some(pid) = sw.pid {
                    fields.insert("pid".to_string(), pid.to_string());
                }
                if let Some(prio) = sw.prio {
                    fields.insert("prio".to_string(), prio.to_string());
                }
                if let Some(target_cpu) = sw.target_cpu {
                    fields.insert("target_cpu".to_string(), target_cpu.to_string());
                }
                if let Some(ref comm) = sw.comm {
                    fields.insert("comm".to_string(), comm.clone());
                }
            }
            Some(ftrace_event::Event::SchedWaking(sw)) => {
                event_type = "sched_waking".to_string();
                if let Some(pid) = sw.pid {
                    fields.insert("pid".to_string(), pid.to_string());
                }
                if let Some(target_cpu) = sw.target_cpu {
                    fields.insert("target_cpu".to_string(), target_cpu.to_string());
                }
            }
            Some(ftrace_event::Event::SchedMigrateTask(sm)) => {
                event_type = "sched_migrate".to_string();
                if let Some(pid) = sm.pid {
                    fields.insert("pid".to_string(), pid.to_string());
                }
                if let Some(orig_cpu) = sm.orig_cpu {
                    fields.insert("orig_cpu".to_string(), orig_cpu.to_string());
                }
                if let Some(dest_cpu) = sm.dest_cpu {
                    fields.insert("dest_cpu".to_string(), dest_cpu.to_string());
                }
            }
            Some(ftrace_event::Event::SoftirqEntry(se)) => {
                event_type = "softirq_entry".to_string();
                if let Some(vec) = se.vec {
                    fields.insert("vec".to_string(), vec.to_string());
                }
            }
            Some(ftrace_event::Event::SoftirqExit(se)) => {
                event_type = "softirq_exit".to_string();
                if let Some(vec) = se.vec {
                    fields.insert("vec".to_string(), vec.to_string());
                }
            }
            Some(ftrace_event::Event::IrqHandlerEntry(ie)) => {
                event_type = "irq_handler_entry".to_string();
                if let Some(irq) = ie.irq {
                    fields.insert("irq".to_string(), irq.to_string());
                }
                if let Some(ref name) = ie.name {
                    fields.insert("name".to_string(), name.clone());
                }
            }
            Some(ftrace_event::Event::IrqHandlerExit(ie)) => {
                event_type = "irq_handler_exit".to_string();
                if let Some(irq) = ie.irq {
                    fields.insert("irq".to_string(), irq.to_string());
                }
                if let Some(ret) = ie.ret {
                    fields.insert("ret".to_string(), ret.to_string());
                }
            }
            Some(ftrace_event::Event::CpuFrequency(cf)) => {
                event_type = "cpu_frequency".to_string();
                if let Some(state) = cf.state {
                    fields.insert("frequency_khz".to_string(), state.to_string());
                }
                if let Some(cpu_id) = cf.cpu_id {
                    fields.insert("cpu_id".to_string(), cpu_id.to_string());
                }
            }
            Some(ftrace_event::Event::CpuIdle(ci)) => {
                event_type = "cpu_idle".to_string();
                if let Some(state) = ci.state {
                    fields.insert("state".to_string(), state.to_string());
                }
                if let Some(cpu_id) = ci.cpu_id {
                    fields.insert("cpu_id".to_string(), cpu_id.to_string());
                }
            }
            _ => {
                event_type = "unknown".to_string();
            }
        }

        Self {
            timestamp: event.timestamp,
            pid: event.pid.map(|p| p as i32),
            event_type,
            fields,
        }
    }
}

/// Aggregation functions for query results
pub struct Aggregator;

impl Aggregator {
    /// Count events
    pub fn count(result: &QueryResult) -> usize {
        result.events.len()
    }

    /// Group events by field value
    pub fn group_by(result: &QueryResult, field: &str) -> HashMap<String, Vec<QueryEvent>> {
        let mut groups: HashMap<String, Vec<QueryEvent>> = HashMap::new();

        for event in &result.events {
            if let Some(value) = event.fields.get(field) {
                groups.entry(value.clone()).or_default().push(event.clone());
            }
        }

        groups
    }

    /// Count events by field value
    pub fn count_by(result: &QueryResult, field: &str) -> HashMap<String, usize> {
        let groups = Self::group_by(result, field);
        groups.into_iter().map(|(k, v)| (k, v.len())).collect()
    }

    /// Calculate average of numeric field
    pub fn avg(result: &QueryResult, field: &str) -> Option<f64> {
        let values: Vec<i64> = result
            .events
            .iter()
            .filter_map(|e| e.fields.get(field))
            .filter_map(|v| v.parse::<i64>().ok())
            .collect();

        if values.is_empty() {
            None
        } else {
            Some(values.iter().sum::<i64>() as f64 / values.len() as f64)
        }
    }

    /// Find min value of numeric field
    pub fn min(result: &QueryResult, field: &str) -> Option<i64> {
        result
            .events
            .iter()
            .filter_map(|e| e.fields.get(field))
            .filter_map(|v| v.parse::<i64>().ok())
            .min()
    }

    /// Find max value of numeric field
    pub fn max(result: &QueryResult, field: &str) -> Option<i64> {
        result
            .events
            .iter()
            .filter_map(|e| e.fields.get(field))
            .filter_map(|v| v.parse::<i64>().ok())
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_operator_compare() {
        let int_left = FilterValue::Int(10);
        let int_right = FilterValue::Int(5);

        assert!(FilterOperator::GreaterThan.compare(&int_left, &int_right));
        assert!(!FilterOperator::LessThan.compare(&int_left, &int_right));
        assert!(FilterOperator::Equal.compare(&int_left, &FilterValue::Int(10)));
    }

    #[test]
    fn test_aggregator_count() {
        let result = QueryResult {
            events: vec![],
            total_matched: 0,
            query_time_ms: 0,
        };
        assert_eq!(Aggregator::count(&result), 0);
    }
}
