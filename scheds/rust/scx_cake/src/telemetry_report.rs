// SPDX-License-Identifier: GPL-2.0

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageQuality {
    Exact,
    Derived,
    Sampled,
    Bounded,
    Dropped,
    Missing,
}

impl CoverageQuality {
    pub fn label(self) -> &'static str {
        match self {
            CoverageQuality::Exact => "exact",
            CoverageQuality::Derived => "derived",
            CoverageQuality::Sampled => "sampled",
            CoverageQuality::Bounded => "bounded",
            CoverageQuality::Dropped => "dropped",
            CoverageQuality::Missing => "missing",
        }
    }

    pub fn is_degraded(self) -> bool {
        matches!(self, CoverageQuality::Dropped | CoverageQuality::Missing)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageItem {
    pub name: String,
    pub source: String,
    pub quality: CoverageQuality,
    pub window: String,
    pub drops: u64,
    pub note: String,
}

impl CoverageItem {
    pub fn new(
        name: impl Into<String>,
        source: impl Into<String>,
        quality: CoverageQuality,
        window: impl Into<String>,
        drops: u64,
        note: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
            quality,
            window: window.into(),
            drops,
            note: note.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HealthSummary {
    pub dsq_depth: u64,
    pub total_dispatches: u64,
    pub total_wakes: u64,
    pub timeline_samples: usize,
    pub timeline_expected: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct GraphSummary {
    pub wake_edges: usize,
    pub wake_events: u64,
    pub wait_samples: u64,
    pub wait_max_us: u64,
    pub event_drops: u64,
    pub observed_events: u64,
    pub sample_weight_sum: u64,
    pub important_events: u64,
    pub wake_events_est: u64,
    pub wait_samples_est: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct LifecycleSummary {
    pub init_enqueue_avg_us: u64,
    pub init_enqueue_count: u64,
    pub init_select_avg_us: u64,
    pub init_select_count: u64,
    pub init_run_avg_us: u64,
    pub init_run_count: u64,
    pub run_stop_avg_us: u64,
    pub run_stop_count: u64,
    pub init_exit_avg_us: u64,
    pub init_exit_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct AcceleratorSummary {
    pub source: String,
    pub trained_cpus: usize,
    pub route_ready_cpus: u64,
    pub floor_ready_cpus: u64,
    pub shock_cpus: u64,
    pub trust_low_cpus: u64,
    pub owner_low_cpus: u64,
    pub gear_counts: [u64; 4],
    pub route_counts: [u64; 7],
    pub select_tunnel: u64,
    pub select_idle: u64,
    pub wake_target_hit: u64,
    pub wake_target_miss: u64,
    pub wake_direct: u64,
    pub wake_busy: u64,
    pub wake_queued: u64,
    pub dispatch_hit: u64,
    pub dispatch_miss: u64,
    pub route_attempt_counts: [u64; 7],
    pub route_hit_counts: [u64; 7],
    pub route_miss_counts: [u64; 7],
    pub fast_attempt_counts: [u64; 7],
    pub fast_hit_counts: [u64; 7],
    pub fast_miss_counts: [u64; 7],
    pub route_block_counts: [u64; 13],
    pub scoreboard_probe_counts: [[u64; 7]; 7],
    pub pull_mode_counts: [u64; 3],
    pub pull_probe_counts: [u64; 2],
    pub native_fallback_counts: [u64; 3],
    pub accounting_relaxed: u64,
    pub accounting_audit: u64,
    pub storm_guard_mode_counts: [u64; 4],
    pub storm_guard_decision_counts: [u64; 9],
    pub trust_prev_enabled_cpus: u64,
    pub trust_prev_active_cpus: u64,
    pub trust_prev_blocked_cpus: u64,
    pub trust_prev_demotions: u64,
    pub trust_prev_attempts: u64,
    pub trust_prev_hits: u64,
    pub trust_prev_misses: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TelemetryReport {
    pub schema_version: u32,
    pub text_version: u32,
    pub coverage: Vec<CoverageItem>,
    pub health: HealthSummary,
    pub graph: GraphSummary,
    pub lifecycle: LifecycleSummary,
    pub accelerator: AcceleratorSummary,
}

impl TelemetryReport {
    pub fn new(coverage: Vec<CoverageItem>, health: HealthSummary, graph: GraphSummary) -> Self {
        Self {
            schema_version: 7,
            text_version: 1,
            coverage,
            health,
            graph,
            lifecycle: LifecycleSummary::default(),
            accelerator: AcceleratorSummary::default(),
        }
    }

    pub fn with_lifecycle(mut self, lifecycle: LifecycleSummary) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    pub fn with_accelerator(mut self, accelerator: AcceleratorSummary) -> Self {
        self.accelerator = accelerator;
        self
    }

    pub fn degraded_count(&self) -> usize {
        self.coverage
            .iter()
            .filter(|item| item.quality.is_degraded() || item.drops > 0)
            .count()
    }

    pub fn status_label(&self) -> &'static str {
        if self.degraded_count() == 0 {
            "ok"
        } else {
            "degraded"
        }
    }

    pub fn coverage_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "coverage: status={} degraded={} sections={}\n",
            self.status_label(),
            self.degraded_count(),
            self.coverage.len()
        ));
        for item in &self.coverage {
            out.push_str(&format!(
                "  name={} source={} quality={} window={} drops={} note={}\n",
                item.name,
                item.source,
                item.quality.label(),
                item.window,
                item.drops,
                item.note
            ));
        }
        out
    }

    #[cfg(test)]
    pub fn to_json(&self) -> String {
        #[derive(Serialize)]
        struct TelemetryReportJson<'a> {
            schema_version: u32,
            text_version: u32,
            status: &'static str,
            degraded_count: usize,
            health: &'a HealthSummary,
            lifecycle: &'a LifecycleSummary,
            accelerator: &'a AcceleratorSummary,
            graph: &'a GraphSummary,
            coverage: &'a [CoverageItem],
        }

        let json = TelemetryReportJson {
            schema_version: self.schema_version,
            text_version: self.text_version,
            status: self.status_label(),
            degraded_count: self.degraded_count(),
            health: &self.health,
            lifecycle: &self.lifecycle,
            accelerator: &self.accelerator,
            graph: &self.graph,
            coverage: &self.coverage,
        };

        match serde_json::to_string_pretty(&json) {
            Ok(mut out) => {
                out.push('\n');
                out
            }
            Err(err) => format!(
                "{{\"schema_version\":{},\"status\":\"degraded\",\"error\":\"{}\"}}\n",
                self.schema_version, err
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_status_fails_loud_for_missing_or_dropped_sections() {
        let report = TelemetryReport::new(
            vec![
                CoverageItem::new(
                    "global",
                    "bpf_stats",
                    CoverageQuality::Exact,
                    "lifetime",
                    0,
                    "ok",
                ),
                CoverageItem::new(
                    "wakegraph.events",
                    "debug_ringbuf",
                    CoverageQuality::Missing,
                    "runtime",
                    0,
                    "expected debug events were not observed",
                ),
                CoverageItem::new(
                    "wakegraph.ringbuf",
                    "debug_ringbuf",
                    CoverageQuality::Dropped,
                    "runtime",
                    3,
                    "ringbuf reserve failed",
                ),
            ],
            HealthSummary::default(),
            GraphSummary::default(),
        );

        assert_eq!(report.status_label(), "degraded");
        assert_eq!(report.degraded_count(), 2);
        assert!(report.coverage_text().contains("coverage: status=degraded"));
        let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["degraded_count"], 2);
    }

    #[test]
    fn json_escapes_string_fields() {
        let report = TelemetryReport::new(
            vec![CoverageItem::new(
                "field\"name",
                "source\\path",
                CoverageQuality::Derived,
                "60s",
                0,
                "line\nbreak",
            )],
            HealthSummary::default(),
            GraphSummary::default(),
        );

        let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["coverage"][0]["name"], "field\"name");
        assert_eq!(json["coverage"][0]["source"], "source\\path");
        assert_eq!(json["coverage"][0]["note"], "line\nbreak");
    }

    #[test]
    fn json_includes_accelerator_summary() {
        let report =
            TelemetryReport::new(vec![], HealthSummary::default(), GraphSummary::default())
                .with_accelerator(AcceleratorSummary {
                    source: "debug-hot-telemetry".to_string(),
                    trained_cpus: 2,
                    route_ready_cpus: 2,
                    floor_ready_cpus: 1,
                    gear_counts: [0, 1, 0, 1],
                    route_counts: [0, 1, 0, 0, 0, 0, 1],
                    dispatch_hit: 7,
                    dispatch_miss: 3,
                    route_attempt_counts: [0, 11, 0, 0, 0, 0, 2],
                    route_hit_counts: [0, 10, 0, 0, 0, 0, 2],
                    route_miss_counts: [0, 1, 0, 0, 0, 0, 0],
                    fast_attempt_counts: [0, 20, 4, 2, 0, 0, 0],
                    fast_hit_counts: [0, 18, 1, 1, 0, 0, 0],
                    fast_miss_counts: [0, 2, 3, 1, 0, 0, 0],
                    route_block_counts: [0, 0, 0, 5, 0, 0, 1, 0, 0, 0, 2, 0, 0],
                    scoreboard_probe_counts: [
                        [0; 7],
                        [18, 2, 0, 0, 1, 3, 0],
                        [1, 2, 1, 0, 0, 1, 0],
                        [1, 0, 0, 1, 0, 0, 0],
                        [0; 7],
                        [0; 7],
                        [0; 7],
                    ],
                    pull_mode_counts: [3, 4, 5],
                    pull_probe_counts: [6, 7],
                    native_fallback_counts: [8, 0, 8],
                    accounting_relaxed: 13,
                    accounting_audit: 2,
                    ..AcceleratorSummary::default()
                });

        let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["schema_version"], 7);
        assert_eq!(json["accelerator"]["source"], "debug-hot-telemetry");
        assert_eq!(json["accelerator"]["trained_cpus"], 2);
        assert_eq!(json["accelerator"]["route_ready_cpus"], 2);
        assert_eq!(
            json["accelerator"]["gear_counts"],
            serde_json::json!([0, 1, 0, 1])
        );
        assert_eq!(
            json["accelerator"]["route_counts"],
            serde_json::json!([0, 1, 0, 0, 0, 0, 1])
        );
        assert_eq!(json["accelerator"]["dispatch_hit"], 7);
        assert_eq!(json["accelerator"]["dispatch_miss"], 3);
        assert_eq!(
            json["accelerator"]["route_attempt_counts"],
            serde_json::json!([0, 11, 0, 0, 0, 0, 2])
        );
        assert_eq!(
            json["accelerator"]["fast_hit_counts"],
            serde_json::json!([0, 18, 1, 1, 0, 0, 0])
        );
        assert_eq!(
            json["accelerator"]["route_block_counts"],
            serde_json::json!([0, 0, 0, 5, 0, 0, 1, 0, 0, 0, 2, 0, 0])
        );
        assert_eq!(
            json["accelerator"]["scoreboard_probe_counts"][1],
            serde_json::json!([18, 2, 0, 0, 1, 3, 0])
        );
        assert_eq!(
            json["accelerator"]["native_fallback_counts"],
            serde_json::json!([8, 0, 8])
        );
        assert_eq!(json["accelerator"]["accounting_relaxed"], 13);
        assert_eq!(json["accelerator"]["accounting_audit"], 2);
    }
}
