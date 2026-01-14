// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Phase 6: Analyzer Registry and Auto-Discovery
//!
//! Provides a registry system for dynamically discovering and running
//! perfetto analyzers based on trace capabilities.

use super::perfetto_parser::PerfettoTrace;
use super::perfetto_parser_enhanced::TraceCapabilities;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Analyzer metadata describing capabilities and requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerMetadata {
    /// Unique identifier for the analyzer
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this analyzer does
    pub description: String,
    /// Category of analysis
    pub category: AnalyzerCategory,
    /// Required event types for this analyzer to work
    pub required_events: Vec<String>,
    /// Optional event types that enhance analysis
    pub optional_events: Vec<String>,
    /// Whether this analyzer requires sched_ext data
    pub requires_scx: bool,
    /// Estimated performance cost (1-5, 5 being most expensive)
    pub performance_cost: u8,
}

/// Categories of analyzers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalyzerCategory {
    /// Scheduling analysis
    Scheduling,
    /// Interrupt and IPI analysis
    Interrupt,
    /// I/O and block device analysis
    IO,
    /// Power and frequency analysis
    Power,
    /// Extended scheduling metrics
    Extended,
    /// Generic query capability
    Query,
}

impl AnalyzerCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scheduling => "scheduling",
            Self::Interrupt => "interrupt",
            Self::IO => "io",
            Self::Power => "power",
            Self::Extended => "extended",
            Self::Query => "query",
        }
    }
}

/// Result of running an analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerResult {
    pub analyzer_id: String,
    pub success: bool,
    pub data: serde_json::Value,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Trait for analyzers that can be registered
pub trait TraceAnalyzer: Send + Sync {
    /// Get analyzer metadata
    fn metadata(&self) -> &AnalyzerMetadata;

    /// Check if this analyzer can run on the given trace
    fn can_analyze(&self, trace: &PerfettoTrace) -> bool;

    /// Run the analysis and return results
    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult;
}

/// Registry for perfetto analyzers
pub struct AnalyzerRegistry {
    analyzers: HashMap<String, Box<dyn TraceAnalyzer>>,
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerRegistry {
    /// Create a new analyzer registry
    pub fn new() -> Self {
        Self {
            analyzers: HashMap::new(),
        }
    }

    /// Create a registry with all built-in analyzers
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        registry.register_builtins();
        registry
    }

    /// Register a new analyzer
    pub fn register(&mut self, analyzer: Box<dyn TraceAnalyzer>) {
        let id = analyzer.metadata().id.clone();
        self.analyzers.insert(id, analyzer);
    }

    /// Register all built-in analyzers
    pub fn register_builtins(&mut self) {
        // Scheduling analyzers
        self.register(Box::new(ContextSwitchAnalyzerWrapper));
        self.register(Box::new(WakeupLatencyAnalyzerWrapper));
        self.register(Box::new(MigrationAnalyzerWrapper));
        self.register(Box::new(DsqAnalyzerWrapper));

        // Interrupt analyzers
        self.register(Box::new(IrqAnalyzerWrapper));
        self.register(Box::new(IpiAnalyzerWrapper));

        // I/O analyzers
        self.register(Box::new(BlockIoAnalyzerWrapper));
        self.register(Box::new(NetworkIoAnalyzerWrapper));
        self.register(Box::new(MemoryPressureAnalyzerWrapper));
        self.register(Box::new(FileIoAnalyzerWrapper));

        // Power analyzers
        self.register(Box::new(CpuFrequencyAnalyzerWrapper));
        self.register(Box::new(CpuIdleAnalyzerWrapper));
        self.register(Box::new(PowerStateAnalyzerWrapper));

        // Extended analyzers
        self.register(Box::new(TaskStateAnalyzerWrapper));
        self.register(Box::new(PreemptionAnalyzerWrapper));
        self.register(Box::new(WakeupChainAnalyzerWrapper));
        self.register(Box::new(LatencyBreakdownAnalyzerWrapper));
    }

    /// Get all registered analyzers
    pub fn list_analyzers(&self) -> Vec<&AnalyzerMetadata> {
        self.analyzers.values().map(|a| a.metadata()).collect()
    }

    /// Get analyzers by category
    pub fn list_by_category(&self, category: AnalyzerCategory) -> Vec<&AnalyzerMetadata> {
        self.analyzers
            .values()
            .filter(|a| a.metadata().category == category)
            .map(|a| a.metadata())
            .collect()
    }

    /// Discover which analyzers can run on a trace
    pub fn discover_analyzers(&self, trace: &PerfettoTrace) -> Vec<&AnalyzerMetadata> {
        self.analyzers
            .values()
            .filter(|a| a.can_analyze(trace))
            .map(|a| a.metadata())
            .collect()
    }

    /// Run all applicable analyzers on a trace
    pub fn analyze_all(&self, trace: Arc<PerfettoTrace>) -> Vec<AnalyzerResult> {
        let applicable: Vec<_> = self
            .analyzers
            .values()
            .filter(|a| a.can_analyze(&trace))
            .collect();

        applicable
            .into_iter()
            .map(|analyzer| analyzer.analyze(trace.clone()))
            .collect()
    }

    /// Run specific analyzer by ID
    pub fn analyze_by_id(
        &self,
        analyzer_id: &str,
        trace: Arc<PerfettoTrace>,
    ) -> Option<AnalyzerResult> {
        self.analyzers
            .get(analyzer_id)
            .map(|analyzer| analyzer.analyze(trace))
    }

    /// Get trace analysis summary
    pub fn get_trace_summary(&self, trace: &PerfettoTrace) -> TraceSummary {
        let capabilities = TraceCapabilities::from_trace(trace);
        let applicable_analyzers = self.discover_analyzers(trace);

        let mut by_category: HashMap<String, Vec<String>> = HashMap::new();
        for analyzer in &applicable_analyzers {
            by_category
                .entry(analyzer.category.as_str().to_string())
                .or_default()
                .push(analyzer.name.clone());
        }

        TraceSummary {
            trace_duration_ms: (trace.time_range().1 - trace.time_range().0) / 1_000_000,
            num_cpus: trace.num_cpus(),
            num_processes: trace.get_processes().len(),
            total_events: trace.total_events(),
            is_scx_trace: trace.is_scx_trace(),
            capabilities,
            applicable_analyzers: applicable_analyzers.len(),
            analyzers_by_category: by_category,
        }
    }
}

/// Trace analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    pub trace_duration_ms: u64,
    pub num_cpus: usize,
    pub num_processes: usize,
    pub total_events: usize,
    pub is_scx_trace: bool,
    pub capabilities: TraceCapabilities,
    pub applicable_analyzers: usize,
    pub analyzers_by_category: HashMap<String, Vec<String>>,
}

// ============================================================================
// Built-in Analyzer Wrappers
// ============================================================================

/// Wrapper for ContextSwitchAnalyzer
struct ContextSwitchAnalyzerWrapper;

impl TraceAnalyzer for ContextSwitchAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "cpu_utilization".to_string(),
            name: "CPU Utilization".to_string(),
            description: "Analyzes CPU utilization and per-process runtime".to_string(),
            category: AnalyzerCategory::Scheduling,
            required_events: vec!["sched_switch".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 3,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_switch")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers::ContextSwitchAnalyzer;

        let start = std::time::Instant::now();
        let analyzer = ContextSwitchAnalyzer::new(trace);
        let stats = analyzer.analyze_cpu_utilization_parallel();
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&stats).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

/// Wrapper for WakeupChainAnalyzer
struct WakeupLatencyAnalyzerWrapper;

impl TraceAnalyzer for WakeupLatencyAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "wakeup_latency".to_string(),
            name: "Wakeup Latency".to_string(),
            description: "Analyzes wakeup-to-schedule latencies".to_string(),
            category: AnalyzerCategory::Scheduling,
            required_events: vec!["sched_waking".to_string(), "sched_switch".to_string()],
            optional_events: vec!["sched_wakeup".to_string()],
            requires_scx: false,
            performance_cost: 4,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_waking") && trace.has_event_type("sched_switch")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers::WakeupChainAnalyzer;

        let start = std::time::Instant::now();
        let analyzer = WakeupChainAnalyzer::new(trace);
        let stats = analyzer.analyze_wakeup_latency();
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&stats).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

/// Wrapper for PerfettoMigrationAnalyzer
struct MigrationAnalyzerWrapper;

impl TraceAnalyzer for MigrationAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "migration_patterns".to_string(),
            name: "Migration Patterns".to_string(),
            description: "Analyzes CPU migration patterns and hotspots".to_string(),
            category: AnalyzerCategory::Scheduling,
            required_events: vec!["sched_migrate_task".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 2,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_migrate_task")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers::PerfettoMigrationAnalyzer;

        let start = std::time::Instant::now();
        let analyzer = PerfettoMigrationAnalyzer::new(trace);
        let stats = analyzer.analyze_migration_patterns();
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&stats).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

/// Wrapper for DsqAnalyzer
struct DsqAnalyzerWrapper;

impl TraceAnalyzer for DsqAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "dsq_summary".to_string(),
            name: "DSQ Summary".to_string(),
            description: "Analyzes sched_ext dispatch queue behavior".to_string(),
            category: AnalyzerCategory::Scheduling,
            required_events: vec![],
            optional_events: vec![],
            requires_scx: true,
            performance_cost: 3,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.is_scx_trace()
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers::DsqAnalyzer;

        let start = std::time::Instant::now();
        let analyzer = DsqAnalyzer::new(trace);
        let result = if let Some(summary) = analyzer.get_summary() {
            AnalyzerResult {
                analyzer_id: self.metadata().id.clone(),
                success: true,
                data: serde_json::to_value(&summary).unwrap(),
                duration_ms: start.elapsed().as_millis() as u64,
                error: None,
            }
        } else {
            AnalyzerResult {
                analyzer_id: self.metadata().id.clone(),
                success: false,
                data: serde_json::json!({}),
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some("No DSQ data found".to_string()),
            }
        };

        result
    }
}

// Macro to reduce boilerplate for simple analyzers
macro_rules! simple_analyzer_wrapper {
    ($name:ident, $analyzer_type:path, $id:expr, $display_name:expr, $desc:expr, $category:expr, $required:expr, $cost:expr) => {
        struct $name;

        impl TraceAnalyzer for $name {
            fn metadata(&self) -> &AnalyzerMetadata {
                static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
                METADATA.get_or_init(|| AnalyzerMetadata {
                    id: $id.to_string(),
                    name: $display_name.to_string(),
                    description: $desc.to_string(),
                    category: $category,
                    required_events: $required.iter().map(|s| s.to_string()).collect(),
                    optional_events: vec![],
                    requires_scx: false,
                    performance_cost: $cost,
                })
            }

            fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
                let required_events = $required;
                required_events
                    .iter()
                    .all(|event_type| trace.has_event_type(event_type))
            }

            fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
                let start = std::time::Instant::now();
                let result = <$analyzer_type>::analyze(&trace);
                let duration = start.elapsed();

                AnalyzerResult {
                    analyzer_id: self.metadata().id.clone(),
                    success: true,
                    data: serde_json::to_value(&result).unwrap(),
                    duration_ms: duration.as_millis() as u64,
                    error: None,
                }
            }
        }
    };
}

// Interrupt analyzers
simple_analyzer_wrapper!(
    IrqAnalyzerWrapper,
    super::perfetto_analyzers_irq::IrqHandlerAnalyzer,
    "irq_analysis",
    "IRQ Handler Analysis",
    "Analyzes hardware interrupt handler latencies",
    AnalyzerCategory::Interrupt,
    &["irq_handler_entry", "irq_handler_exit"],
    2
);

simple_analyzer_wrapper!(
    IpiAnalyzerWrapper,
    super::perfetto_analyzers_irq::IpiAnalyzer,
    "ipi_analysis",
    "IPI Analysis",
    "Analyzes inter-processor interrupts",
    AnalyzerCategory::Interrupt,
    &["ipi_entry", "ipi_exit"],
    2
);

// I/O analyzers
simple_analyzer_wrapper!(
    BlockIoAnalyzerWrapper,
    super::perfetto_analyzers_io::BlockIoAnalyzer,
    "block_io",
    "Block I/O Analysis",
    "Analyzes block device I/O patterns and latencies",
    AnalyzerCategory::IO,
    &["block_rq_insert", "block_rq_issue"],
    3
);

simple_analyzer_wrapper!(
    NetworkIoAnalyzerWrapper,
    super::perfetto_analyzers_io::NetworkIoAnalyzer,
    "network_io",
    "Network I/O Analysis",
    "Analyzes network transmit/receive and bandwidth",
    AnalyzerCategory::IO,
    &["net_dev_xmit", "netif_receive_skb"],
    2
);

simple_analyzer_wrapper!(
    MemoryPressureAnalyzerWrapper,
    super::perfetto_analyzers_io::MemoryPressureAnalyzer,
    "memory_pressure",
    "Memory Pressure Analysis",
    "Analyzes memory allocation and reclaim",
    AnalyzerCategory::IO,
    &["mm_page_alloc", "mm_page_free"],
    3
);

simple_analyzer_wrapper!(
    FileIoAnalyzerWrapper,
    super::perfetto_analyzers_io::FileIoAnalyzer,
    "file_io",
    "File I/O Analysis",
    "Analyzes file sync operations",
    AnalyzerCategory::IO,
    &["ext4_sync_file_enter", "ext4_sync_file_exit"],
    2
);

// Power analyzers
simple_analyzer_wrapper!(
    CpuFrequencyAnalyzerWrapper,
    super::perfetto_analyzers_power::CpuFrequencyAnalyzer,
    "cpu_frequency",
    "CPU Frequency Analysis",
    "Analyzes CPU frequency scaling behavior",
    AnalyzerCategory::Power,
    &["cpu_frequency"],
    2
);

simple_analyzer_wrapper!(
    CpuIdleAnalyzerWrapper,
    super::perfetto_analyzers_power::CpuIdleStateAnalyzer,
    "cpu_idle",
    "CPU Idle State Analysis",
    "Analyzes CPU idle state transitions",
    AnalyzerCategory::Power,
    &["cpu_idle"],
    2
);

simple_analyzer_wrapper!(
    PowerStateAnalyzerWrapper,
    super::perfetto_analyzers_power::PowerStateAnalyzer,
    "power_state",
    "Power State Analysis",
    "Analyzes system suspend/resume transitions",
    AnalyzerCategory::Power,
    &["suspend_resume"],
    1
);

// Extended analyzers - these have custom interfaces
struct TaskStateAnalyzerWrapper;

impl TraceAnalyzer for TaskStateAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "task_states".to_string(),
            name: "Task State Analysis".to_string(),
            description: "Analyzes task state transitions and distributions".to_string(),
            category: AnalyzerCategory::Extended,
            required_events: vec!["sched_switch".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 3,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_switch")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers_extended::{AggregationMode, TaskStateAnalyzer};

        let start = std::time::Instant::now();
        let analyzer = TaskStateAnalyzer::new(trace);
        let result = analyzer.analyze_task_states(None, AggregationMode::PerThread);
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&result).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

struct PreemptionAnalyzerWrapper;

impl TraceAnalyzer for PreemptionAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "preemptions".to_string(),
            name: "Preemption Analysis".to_string(),
            description: "Analyzes task preemption patterns".to_string(),
            category: AnalyzerCategory::Extended,
            required_events: vec!["sched_switch".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 3,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_switch")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers_extended::PreemptionAnalyzer;

        let start = std::time::Instant::now();
        let analyzer = PreemptionAnalyzer::new(trace);
        let result = analyzer.analyze_preemptions(None);
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&result).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

struct WakeupChainAnalyzerWrapper;

impl TraceAnalyzer for WakeupChainAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "wakeup_chains".to_string(),
            name: "Wakeup Chain Detection".to_string(),
            description: "Detects wakeup chains and cascades".to_string(),
            category: AnalyzerCategory::Extended,
            required_events: vec!["sched_waking".to_string(), "sched_switch".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 4,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_waking") && trace.has_event_type("sched_switch")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers_extended::WakeupChainDetector;

        let start = std::time::Instant::now();
        let analyzer = WakeupChainDetector::new(trace);
        let result = analyzer.find_wakeup_chains(20);
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&result).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

struct LatencyBreakdownAnalyzerWrapper;

impl TraceAnalyzer for LatencyBreakdownAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "latency_breakdown".to_string(),
            name: "Latency Breakdown".to_string(),
            description: "Breaks down scheduling latency into stages".to_string(),
            category: AnalyzerCategory::Extended,
            required_events: vec!["sched_waking".to_string(), "sched_switch".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 4,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        trace.has_event_type("sched_waking") && trace.has_event_type("sched_switch")
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        use super::perfetto_analyzers_extended::SchedulingLatencyBreakdown;

        let start = std::time::Instant::now();
        let analyzer = SchedulingLatencyBreakdown::new(trace);
        let result = analyzer.analyze_latency_stages();
        let duration = start.elapsed();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&result).unwrap(),
            duration_ms: duration.as_millis() as u64,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = AnalyzerRegistry::new();
        assert_eq!(registry.analyzers.len(), 0);
    }

    #[test]
    fn test_registry_with_builtins() {
        let registry = AnalyzerRegistry::with_builtins();
        let analyzers = registry.list_analyzers();
        assert!(analyzers.len() > 10); // Should have many built-in analyzers
    }

    #[test]
    fn test_category_filtering() {
        let registry = AnalyzerRegistry::with_builtins();
        let scheduling = registry.list_by_category(AnalyzerCategory::Scheduling);
        assert!(!scheduling.is_empty());
    }

    #[test]
    fn test_analyzer_metadata() {
        let wrapper = ContextSwitchAnalyzerWrapper;
        let metadata = wrapper.metadata();
        assert_eq!(metadata.id, "cpu_utilization");
        assert_eq!(metadata.category, AnalyzerCategory::Scheduling);
    }
}
