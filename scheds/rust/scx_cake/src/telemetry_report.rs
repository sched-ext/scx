// SPDX-License-Identifier: GPL-2.0

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthSummary {
    pub dsq_depth: u64,
    pub total_dispatches: u64,
    pub total_wakes: u64,
    pub timeline_samples: usize,
    pub timeline_expected: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TelemetryReport {
    pub schema_version: u32,
    pub text_version: u32,
    pub coverage: Vec<CoverageItem>,
    pub health: HealthSummary,
    pub graph: GraphSummary,
    pub lifecycle: LifecycleSummary,
}

impl TelemetryReport {
    pub fn new(coverage: Vec<CoverageItem>, health: HealthSummary, graph: GraphSummary) -> Self {
        Self {
            schema_version: 3,
            text_version: 1,
            coverage,
            health,
            graph,
            lifecycle: LifecycleSummary::default(),
        }
    }

    pub fn with_lifecycle(mut self, lifecycle: LifecycleSummary) -> Self {
        self.lifecycle = lifecycle;
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

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"schema_version\": {},\n", self.schema_version));
        out.push_str(&format!("  \"text_version\": {},\n", self.text_version));
        out.push_str(&format!("  \"status\": \"{}\",\n", self.status_label()));
        out.push_str(&format!(
            "  \"degraded_count\": {},\n",
            self.degraded_count()
        ));
        out.push_str("  \"health\": {\n");
        out.push_str(&format!("    \"dsq_depth\": {},\n", self.health.dsq_depth));
        out.push_str(&format!(
            "    \"total_dispatches\": {},\n",
            self.health.total_dispatches
        ));
        out.push_str(&format!(
            "    \"total_wakes\": {},\n",
            self.health.total_wakes
        ));
        out.push_str(&format!(
            "    \"timeline_samples\": {},\n",
            self.health.timeline_samples
        ));
        out.push_str(&format!(
            "    \"timeline_expected\": {}\n",
            self.health.timeline_expected
        ));
        out.push_str("  },\n");
        out.push_str("  \"lifecycle\": {\n");
        out.push_str(&format!(
            "    \"init_enqueue_avg_us\": {},\n",
            self.lifecycle.init_enqueue_avg_us
        ));
        out.push_str(&format!(
            "    \"init_enqueue_count\": {},\n",
            self.lifecycle.init_enqueue_count
        ));
        out.push_str(&format!(
            "    \"init_select_avg_us\": {},\n",
            self.lifecycle.init_select_avg_us
        ));
        out.push_str(&format!(
            "    \"init_select_count\": {},\n",
            self.lifecycle.init_select_count
        ));
        out.push_str(&format!(
            "    \"init_run_avg_us\": {},\n",
            self.lifecycle.init_run_avg_us
        ));
        out.push_str(&format!(
            "    \"init_run_count\": {},\n",
            self.lifecycle.init_run_count
        ));
        out.push_str(&format!(
            "    \"run_stop_avg_us\": {},\n",
            self.lifecycle.run_stop_avg_us
        ));
        out.push_str(&format!(
            "    \"run_stop_count\": {},\n",
            self.lifecycle.run_stop_count
        ));
        out.push_str(&format!(
            "    \"init_exit_avg_us\": {},\n",
            self.lifecycle.init_exit_avg_us
        ));
        out.push_str(&format!(
            "    \"init_exit_count\": {}\n",
            self.lifecycle.init_exit_count
        ));
        out.push_str("  },\n");
        out.push_str("  \"graph\": {\n");
        out.push_str(&format!("    \"wake_edges\": {},\n", self.graph.wake_edges));
        out.push_str(&format!(
            "    \"wake_events\": {},\n",
            self.graph.wake_events
        ));
        out.push_str(&format!(
            "    \"wake_events_est\": {},\n",
            self.graph.wake_events_est
        ));
        out.push_str(&format!(
            "    \"wait_samples\": {},\n",
            self.graph.wait_samples
        ));
        out.push_str(&format!(
            "    \"wait_samples_est\": {},\n",
            self.graph.wait_samples_est
        ));
        out.push_str(&format!(
            "    \"observed_events\": {},\n",
            self.graph.observed_events
        ));
        out.push_str(&format!(
            "    \"sample_weight_sum\": {},\n",
            self.graph.sample_weight_sum
        ));
        out.push_str(&format!(
            "    \"important_events\": {},\n",
            self.graph.important_events
        ));
        out.push_str(&format!(
            "    \"wait_max_us\": {},\n",
            self.graph.wait_max_us
        ));
        out.push_str(&format!(
            "    \"event_drops\": {}\n",
            self.graph.event_drops
        ));
        out.push_str("  },\n");
        out.push_str("  \"coverage\": [\n");
        for (idx, item) in self.coverage.iter().enumerate() {
            out.push_str("    {");
            out.push_str(&format!("\"name\": \"{}\", ", json_escape(&item.name)));
            out.push_str(&format!("\"source\": \"{}\", ", json_escape(&item.source)));
            out.push_str(&format!("\"quality\": \"{}\", ", item.quality.label()));
            out.push_str(&format!("\"window\": \"{}\", ", json_escape(&item.window)));
            out.push_str(&format!("\"drops\": {}, ", item.drops));
            out.push_str(&format!("\"note\": \"{}\"", json_escape(&item.note)));
            out.push('}');
            if idx + 1 != self.coverage.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n");
        out.push_str("}\n");
        out
    }
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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
        assert!(report.to_json().contains("\"status\": \"degraded\""));
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

        let json = report.to_json();
        assert!(json.contains("field\\\"name"));
        assert!(json.contains("source\\\\path"));
        assert!(json.contains("line\\nbreak"));
    }
}
