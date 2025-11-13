// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub mod analyzer_control;
pub mod analyzers;
mod bpf_stats;
pub mod event_aggregator;
pub mod event_buffer;
mod event_control;
pub mod event_filter;
pub mod events;
pub mod extended_analyzers;
pub mod memory_aware_limits;
pub mod outlier_detection;
mod perf_profiling;
pub mod perfetto_analyzer_registry;
pub mod perfetto_analyzers;
pub mod perfetto_analyzers_extended;
pub mod perfetto_analyzers_io;
pub mod perfetto_analyzers_irq;
pub mod perfetto_analyzers_power;
pub mod perfetto_event_types;
pub mod perfetto_outlier_analyzer;
pub mod perfetto_parser;
pub mod perfetto_parser_enhanced;
pub mod perfetto_query;
pub mod perfetto_track_event_types;
mod prompts;
mod protocol;
mod resources;
mod server;
mod shared_state;
mod stats_client;
pub mod subscription_manager;
mod tools;
pub mod waker_wakee_analyzer;

pub use analyzer_control::{AnalyzerControl, AnalyzerStatus, SharedAnalyzerControl};
pub use analyzers::{
    CpuHotspot, CpuHotspotAnalyzer, CpuLatencyStats, LatencyStats, LatencyTracker, LatencyType,
    MigrationAnalysis, MigrationAnalyzer, SystemAverages,
};
pub use bpf_stats::BpfStatsCollector;
pub use event_aggregator::{AggregatedStats, AggregationConfig, EventAggregator};
pub use event_buffer::{BufferedEvent, EventBuffer, EventBufferStats, SharedEventBuffer};
pub use event_control::{
    create_event_control, AttachCallback, EventControl, SharedEventControl, StatsControlCommand,
};
pub use event_filter::EventFilter;
pub use extended_analyzers::{
    CpuSoftirqStats, DsqMonitor, DsqMonitorStats, EventRateMonitor, ProcessEventHistory,
    ProcessSoftirqStats, RateAnomaly, SoftirqAnalyzer, SoftirqStats, SoftirqSummary,
    SystemSnapshot, WakeupChainTracker,
};
pub use outlier_detection::{
    CpuOutlier, EventOutlier, Outlier, OutlierDetector, OutlierMethod, OutlierResult,
    OutlierSummary, OutlierThresholds, ProcessOutlier,
};
pub use perf_profiling::{
    BpfPerfEventAttacher, PerfEventAttacher, PerfProfiler, PerfProfilingConfig, ProfilingStatus,
    RawSample, SharedPerfProfiler,
};
pub use perfetto_analyzer_registry::{
    AnalyzerCategory, AnalyzerMetadata, AnalyzerRegistry, AnalyzerResult, TraceAnalyzer,
    TraceSummary,
};
pub use perfetto_analyzers::{
    BottleneckType, ContextSwitchAnalyzer, CorrelationAnalyzer, CpuUtilStats, DsqAnalysisSummary,
    DsqAnalyzer, LatencyStatsPerCpu, PerfettoMigrationAnalyzer, PerfettoMigrationStats,
    ProcessRuntimeStats, SchedulingBottleneck, WakeupChainAnalyzer, WakeupLatencyStats,
    WakeupScheduleCorrelation,
};
pub use perfetto_analyzers_extended::{
    LatencyBreakdownStats, LatencyStageStats, PreemptionAnalyzer, PreemptionStats, PreemptorInfo,
    SchedulingLatencyBreakdown, TaskStateAnalyzer, TaskStateStats, WakeupChain,
    WakeupChainDetector, WakeupChainEvent,
};
pub use perfetto_analyzers_io::{
    BlockIoAnalyzer, BlockIoEvent, BlockIoResult, FileIoAnalyzer, FileIoResult, FileSyncEvent,
    MemoryPressureAnalyzer, MemoryPressureResult, NetworkEvent, NetworkIoAnalyzer, NetworkIoResult,
    ReclaimEvent,
};
pub use perfetto_analyzers_irq::{
    IpiAnalysisResult, IpiAnalyzer, IpiEvent, IpiReasonSummary, IrqAnalysisResult, IrqEvent,
    IrqHandlerAnalyzer, IrqSummary,
};
pub use perfetto_analyzers_power::{
    CpuFrequencyAnalyzer, CpuFrequencyResult, CpuFrequencyStats, CpuIdleResult,
    CpuIdleStateAnalyzer, CpuIdleStats, FrequencyEvent, IdleEvent, PowerStateAnalyzer,
    PowerStateResult, SuspendResumeEvent,
};
pub use perfetto_event_types::{
    event_category, event_type_name, events_in_category, softirq_type_name, EventCategory,
};
pub use perfetto_outlier_analyzer::{
    CpuUtilizationOutliers, LatencyOutliers, PerfettoOutlierAnalyzer, RuntimeOutliers,
    TraceOutlierAnalysis,
};
pub use perfetto_parser::{
    CpuEventType, CpuTimeline, CpuTimelineEvent, DsqDescriptor, DsqEvent, FtraceEventWithIndex,
    Percentiles, PerfettoTrace, ProcessInfo, ProcessTimeline, ProcessTimelineEvent,
    SchedExtEventData, SchedExtMetadata, ThreadInfo,
};
pub use perfetto_parser_enhanced::{
    ClockType, CompatibilityDetector, EventTypeIndex, TraceCapabilities, TraceSource,
};
pub use perfetto_query::{
    Aggregator, FieldFilter, FilterOperator, FilterValue, QueryBuilder, QueryEvent, QueryResult,
};
pub use perfetto_track_event_types::{
    get_annotation_int, get_annotation_string, get_annotation_uint, Annotation, AnnotationValue,
    InterruptEventType, InterruptTrackEvent, OncpuSliceEvent, ParsedTrackEvent,
    PreemptionInstantEvent, ProcessLifecycleEvent, ProcessLifecycleType, TrackEventMetadata,
    TrackEventType, WakeupInstantEvent,
};
pub use prompts::McpPrompts;
pub use protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
pub use resources::McpResources;
pub use server::{McpServer, McpServerConfig};
pub use shared_state::{create_shared_stats, SharedStats, SharedStatsHandle};
pub use stats_client::SharedStatsClient;
pub use subscription_manager::{SharedSubscriptionManager, SubscriptionManager, SubscriptionStats};
pub use tools::McpTools;
pub use waker_wakee_analyzer::{
    extract_wakee_run_info, extract_wakeup_info, BidirectionalRelationship, LatencyPercentiles,
    RelationshipStats, RelationshipsByPid, WakerWakeeAnalyzer, WakerWakeeSummary,
};
