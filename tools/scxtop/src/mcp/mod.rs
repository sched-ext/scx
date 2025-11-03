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
mod perf_profiling;
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
pub use perf_profiling::{
    BpfPerfEventAttacher, PerfEventAttacher, PerfProfiler, PerfProfilingConfig, ProfilingStatus,
    RawSample, SharedPerfProfiler,
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
