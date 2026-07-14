// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

pub mod bpf_skel;
mod collector;
pub use collector::Collector;

#[derive(Debug, Default)]
pub struct MetricsSnapshot {
    pub work_conservation: Option<f64>,
    pub busy_cpu_samples_total: u64,
    pub needed_cpu_samples_total: u64,
}

impl MetricsSnapshot {
    pub fn delta_from(&self, previous: &Self) -> Self {
        let busy = self
            .busy_cpu_samples_total
            .saturating_sub(previous.busy_cpu_samples_total);
        let needed = self
            .needed_cpu_samples_total
            .saturating_sub(previous.needed_cpu_samples_total);

        Self {
            work_conservation: (needed > 0).then(|| busy as f64 / needed as f64),
            busy_cpu_samples_total: busy,
            needed_cpu_samples_total: needed,
        }
    }

    pub fn to_text(&self) -> String {
        let ratio = self
            .work_conservation
            .map(|value| format!("{:.2}%", value * 100.0))
            .unwrap_or_else(|| "N/A".to_string());
        format!(
            "work_conservation={ratio}({}/{})",
            self.busy_cpu_samples_total, self.needed_cpu_samples_total
        )
    }

    pub fn to_openmetrics(&self) -> String {
        let mut out = String::new();
        if let Some(value) = self.work_conservation {
            out.push_str(&format!("scx_work_conservation_ratio {value}\n"));
        }
        out.push_str(&format!(
            "scx_work_conservation_busy_cpu_samples_total {}\n\
             scx_work_conservation_needed_cpu_samples_total {}\n\
             # EOF\n",
            self.busy_cpu_samples_total, self.needed_cpu_samples_total
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_delta_calculates_work_conservation() {
        let previous = MetricsSnapshot {
            busy_cpu_samples_total: 3,
            needed_cpu_samples_total: 4,
            ..Default::default()
        };
        let current = MetricsSnapshot {
            busy_cpu_samples_total: 7,
            needed_cpu_samples_total: 9,
            ..Default::default()
        };

        let delta = current.delta_from(&previous);
        assert_eq!(delta.work_conservation, Some(4.0 / 5.0));
        assert_eq!(delta.busy_cpu_samples_total, 4);
        assert_eq!(delta.needed_cpu_samples_total, 5);
    }

    #[test]
    fn snapshot_exports_only_work_conservation() {
        let snapshot = MetricsSnapshot {
            work_conservation: Some(0.75),
            busy_cpu_samples_total: 3,
            needed_cpu_samples_total: 4,
            ..Default::default()
        };

        assert_eq!(snapshot.to_text(), "work_conservation=75.00%(3/4)");
        assert!(snapshot
            .to_openmetrics()
            .contains("scx_work_conservation_ratio 0.75"));
    }
}
