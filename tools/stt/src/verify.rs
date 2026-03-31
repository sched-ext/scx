use crate::workload::WorkerReport;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

static WARN_UNFAIR: AtomicBool = AtomicBool::new(false);

pub fn set_warn_unfair(v: bool) {
    WARN_UNFAIR.store(v, Ordering::Relaxed);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyResult {
    pub passed: bool,
    pub details: Vec<String>,
    /// Aggregated stats from all workers in this scenario.
    #[serde(default)]
    pub stats: ScenarioStats,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CellStats {
    pub num_workers: usize,
    pub num_cpus: usize,
    pub avg_runnable_pct: f64,
    pub min_runnable_pct: f64,
    pub max_runnable_pct: f64,
    pub spread: f64,
    pub max_gap_ms: u64,
    pub max_gap_cpu: usize,
    pub total_migrations: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScenarioStats {
    pub cells: Vec<CellStats>,
    pub total_workers: usize,
    pub total_cpus: usize,
    pub total_migrations: u64,
    /// Worst spread across any cell.
    pub worst_spread: f64,
    /// Worst gap across any cell (ms).
    pub worst_gap_ms: u64,
    pub worst_gap_cpu: usize,
}

impl VerifyResult {
    pub fn pass() -> Self {
        Self {
            passed: true,
            details: vec![],
            stats: Default::default(),
        }
    }
    pub fn merge(&mut self, other: VerifyResult) {
        if !other.passed {
            self.passed = false;
        }
        self.details.extend(other.details);
        self.stats.cells.extend(other.stats.cells);
        self.stats.total_workers += other.stats.total_workers;
        self.stats.total_cpus += other.stats.total_cpus;
        self.stats.total_migrations += other.stats.total_migrations;
        if other.stats.worst_spread > self.stats.worst_spread {
            self.stats.worst_spread = other.stats.worst_spread;
        }
        if other.stats.worst_gap_ms > self.stats.worst_gap_ms {
            self.stats.worst_gap_ms = other.stats.worst_gap_ms;
            self.stats.worst_gap_cpu = other.stats.worst_gap_cpu;
        }
    }
}

pub fn verify_isolation(reports: &[WorkerReport], expected: &BTreeSet<usize>) -> VerifyResult {
    let mut r = VerifyResult::pass();
    for w in reports {
        let bad: BTreeSet<usize> = w.cpus_used.difference(expected).copied().collect();
        if !bad.is_empty() {
            r.passed = false;
            r.details
                .push(format!("tid {} ran on unexpected CPUs {:?}", w.tid, bad));
        }
    }
    r
}

/// Verify one cell's workers. Returns per-cell stats.
pub fn verify_not_starved(reports: &[WorkerReport]) -> VerifyResult {
    let mut r = VerifyResult::pass();
    if reports.is_empty() {
        return r;
    }

    let cpus: BTreeSet<usize> = reports
        .iter()
        .flat_map(|w| w.cpus_used.iter().copied())
        .collect();
    let mut pcts: Vec<f64> = Vec::new();

    for w in reports {
        if w.work_units == 0 {
            r.passed = false;
            r.details
                .push(format!("tid {} starved (0 work units)", w.tid));
        }
        if w.wall_time_ns > 0 {
            pcts.push(w.runnable_ns as f64 / w.wall_time_ns as f64 * 100.0);
        }
    }

    let min = pcts.iter().cloned().reduce(f64::min).unwrap_or(0.0);
    let max = pcts.iter().cloned().reduce(f64::max).unwrap_or(0.0);
    let avg = if pcts.is_empty() {
        0.0
    } else {
        pcts.iter().sum::<f64>() / pcts.len() as f64
    };
    let spread = max - min;

    let worst_gap = reports.iter().max_by_key(|w| w.max_gap_ms);
    let (gap_ms, gap_cpu) = worst_gap
        .map(|w| (w.max_gap_ms, w.max_gap_cpu))
        .unwrap_or((0, 0));

    let cell = CellStats {
        num_workers: reports.len(),
        num_cpus: cpus.len(),
        avg_runnable_pct: avg,
        min_runnable_pct: min,
        max_runnable_pct: max,
        spread,
        max_gap_ms: gap_ms,
        max_gap_cpu: gap_cpu,
        total_migrations: reports.iter().map(|w| w.migration_count).sum(),
    };

    // Per-cell fairness: spread > 15% means unequal scheduling within a cell
    if spread > 15.0 && pcts.len() >= 2 {
        if !WARN_UNFAIR.load(Ordering::Relaxed) {
            r.passed = false;
        }
        r.details.push(format!(
            "unfair cell: spread={:.0}% ({:.0}-{:.0}%) {} workers on {} cpus",
            spread,
            min,
            max,
            reports.len(),
            cpus.len(),
        ));
    }

    // Scheduling gap: >2s = dispatch failure
    for w in reports {
        if w.max_gap_ms > 2000 {
            r.passed = false;
            r.details.push(format!(
                "stuck {}ms on cpu{} at +{}ms",
                w.max_gap_ms, w.max_gap_cpu, w.max_gap_at_ms
            ));
        }
    }

    // Store this cell's stats - merge accumulates cells
    r.stats = ScenarioStats {
        cells: vec![cell],
        total_workers: reports.len(),
        total_cpus: cpus.len(),
        total_migrations: reports.iter().map(|w| w.migration_count).sum(),
        worst_spread: spread,
        worst_gap_ms: gap_ms,
        worst_gap_cpu: gap_cpu,
    };

    r
}

fn verify_runnable(reports: &[WorkerReport], _available_cpus: usize) -> VerifyResult {
    if reports.is_empty() {
        return VerifyResult::pass();
    }

    let mut r = VerifyResult::pass();
    let mut pcts: Vec<(u32, f64)> = Vec::new();
    for w in reports {
        if w.wall_time_ns == 0 {
            continue;
        }
        let pct = w.runnable_ns as f64 / w.wall_time_ns as f64 * 100.0;
        pcts.push((w.tid, pct));
    }

    // Don't check absolute runnable% - it's meaningless in VMs due to
    // host scheduling overhead. CFS baseline can be 60%+ in a VM.
    // Instead, only check fairness: flag workers that are WAY worse
    // than their peers, which indicates a scheduler bug.
    if pcts.len() >= 3 {
        let mut sorted: Vec<f64> = pcts.iter().map(|(_, p)| *p).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let _median = sorted[sorted.len() / 2];

        let spread = sorted.last().unwrap_or(&0.0) - sorted.first().unwrap_or(&0.0);

        // Unfair scheduling: flag if spread > 15% AND workers have significantly
        // different runnable times. All workers doing the same work should get
        // similar CPU time regardless of oversubscription level.
        if spread > 15.0 && pcts.len() >= 2 {
            r.passed = false;
            let min_w = pcts
                .iter()
                .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                .unwrap();
            let max_w = pcts
                .iter()
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                .unwrap();
            r.details.push(format!(
                "unfair: spread={:.0}% (tid {} at {:.0}% vs tid {} at {:.0}%)",
                spread, min_w.0, min_w.1, max_w.0, max_w.1,
            ));
        }
    }

    // Scheduling gap check: any worker stuck >2s = dispatch failure
    for w in reports {
        if w.max_gap_ms > 2000 {
            r.passed = false;
            r.details.push(format!(
                "stuck {}ms on cpu{} at +{}ms",
                w.max_gap_ms, w.max_gap_cpu, w.max_gap_at_ms,
            ));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::WorkerReport;

    fn rpt(
        tid: u32,
        work: u64,
        wall_ns: u64,
        run_ns: u64,
        cpus: &[usize],
        gap_ms: u64,
    ) -> WorkerReport {
        WorkerReport {
            tid,
            work_units: work,
            cpu_time_ns: wall_ns.saturating_sub(run_ns),
            wall_time_ns: wall_ns,
            runnable_ns: run_ns,
            migration_count: 0,
            cpus_used: cpus.iter().copied().collect(),
            migrations: vec![],
            max_gap_ms: gap_ms,
            max_gap_cpu: cpus.first().copied().unwrap_or(0),
            max_gap_at_ms: 1000,
        }
    }

    #[test]
    fn healthy_pass() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5_000_000_000, 500_000_000, &[0, 1], 50),
            rpt(2, 1000, 5_000_000_000, 600_000_000, &[0, 1], 60),
            rpt(3, 1000, 5_000_000_000, 550_000_000, &[0, 1], 45),
        ]);
        assert!(r.passed, "{:?}", r.details);
    }

    #[test]
    fn starved_fail() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50),
            rpt(2, 0, 5e9 as u64, 5e9 as u64, &[0], 50),
        ]);
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("starved")));
    }

    #[test]
    fn unfair_spread_fail() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0, 1], 50), // 10%
            rpt(2, 500, 5e9 as u64, 4e9 as u64, &[0, 1], 50),  // 80%
            rpt(3, 800, 5e9 as u64, 2e9 as u64, &[0, 1], 50),  // 40%
        ]);
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("unfair")));
    }

    #[test]
    fn fair_oversubscribed_pass() {
        let r = verify_not_starved(&[
            rpt(1, 100, 5e9 as u64, (3.75e9) as u64, &[0], 50),
            rpt(2, 100, 5e9 as u64, (3.70e9) as u64, &[0], 50),
            rpt(3, 100, 5e9 as u64, (3.80e9) as u64, &[0], 50),
            rpt(4, 100, 5e9 as u64, (3.75e9) as u64, &[0], 50),
        ]);
        assert!(r.passed, "{:?}", r.details);
    }

    #[test]
    fn stuck_fail() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50),
            rpt(2, 1000, 5e9 as u64, 5e8 as u64, &[0], 2500),
        ]);
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("stuck")));
    }

    #[test]
    fn isolation_pass() {
        let expected: BTreeSet<usize> = [0, 1, 2, 3].into_iter().collect();
        let r = verify_isolation(
            &[
                rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0, 1], 50),
                rpt(2, 1000, 5e9 as u64, 5e8 as u64, &[2, 3], 50),
            ],
            &expected,
        );
        assert!(r.passed);
    }

    #[test]
    fn isolation_fail() {
        let expected: BTreeSet<usize> = [0, 1].into_iter().collect();
        let r = verify_isolation(
            &[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0, 1, 4], 50)],
            &expected,
        );
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("unexpected")));
    }

    #[test]
    fn merge_cells() {
        let r1 = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0, 1], 50),
            rpt(2, 1000, 5e9 as u64, 6e8 as u64, &[0, 1], 60),
        ]);
        let r2 = verify_not_starved(&[
            rpt(3, 1000, 5e9 as u64, 25e8 as u64, &[2, 3], 50),
            rpt(4, 1000, 5e9 as u64, 26e8 as u64, &[2, 3], 50),
        ]);
        let mut m = r1;
        m.merge(r2);
        assert_eq!(m.stats.cells.len(), 2);
        assert_eq!(m.stats.total_workers, 4);
        assert!(m.passed, "diff cells diff runnable should pass");
    }

    #[test]
    fn spread_boundary() {
        // 15% exactly - pass
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 1e9 as u64, &[0], 50),
            rpt(2, 1000, 5e9 as u64, (1.75e9) as u64, &[0], 50),
        ]);
        assert!(r.passed, "15% spread: {:?}", r.details);
        // 20% - fail
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50),
            rpt(2, 1000, 5e9 as u64, (1.5e9) as u64, &[0], 50),
        ]);
        assert!(!r.passed, "20% spread should fail");
    }

    #[test]
    fn empty_pass() {
        assert!(verify_not_starved(&[]).passed);
    }

    #[test]
    fn zero_wall_time() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50),
            rpt(2, 0, 0, 0, &[], 0),
        ]);
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("starved")));
    }

    #[test]
    fn single_worker_always_pass() {
        let r = verify_not_starved(&[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0, 1], 50)]);
        assert!(r.passed);
        assert_eq!(r.stats.total_workers, 1);
        assert_eq!(r.stats.cells.len(), 1);
    }

    #[test]
    fn stats_accuracy() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 1e9 as u64, &[0], 50),  // 20%
            rpt(2, 1000, 5e9 as u64, 15e8 as u64, &[1], 60), // 30%
        ]);
        assert!(r.passed); // spread = 10% < 15%
        let c = &r.stats.cells[0];
        assert_eq!(c.num_workers, 2);
        assert_eq!(c.num_cpus, 2);
        assert!((c.min_runnable_pct - 20.0).abs() < 0.1);
        assert!((c.max_runnable_pct - 30.0).abs() < 0.1);
        assert!((c.spread - 10.0).abs() < 0.1);
        assert!((c.avg_runnable_pct - 25.0).abs() < 0.1);
    }

    #[test]
    fn merge_takes_worst_gap() {
        let r1 = verify_not_starved(&[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 100)]);
        let r2 = verify_not_starved(&[rpt(2, 1000, 5e9 as u64, 5e8 as u64, &[1], 500)]);
        let mut m = r1;
        m.merge(r2);
        assert_eq!(m.stats.worst_gap_ms, 500);
        assert_eq!(m.stats.worst_gap_cpu, 1);
    }

    #[test]
    fn merge_takes_worst_spread() {
        let r1 = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 1e9 as u64, &[0], 50),
            rpt(2, 1000, 5e9 as u64, 12e8 as u64, &[0], 50),
        ]); // spread = 4%
        let r2 = verify_not_starved(&[
            rpt(3, 1000, 5e9 as u64, 1e9 as u64, &[1], 50),
            rpt(4, 1000, 5e9 as u64, 15e8 as u64, &[1], 50),
        ]); // spread = 10%
        let mut m = r1;
        m.merge(r2);
        assert!((m.stats.worst_spread - 10.0).abs() < 0.1);
    }

    #[test]
    fn merge_accumulates_totals() {
        let r1 = verify_not_starved(&[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50)]);
        let r2 = verify_not_starved(&[rpt(2, 1000, 5e9 as u64, 5e8 as u64, &[1], 50)]);
        let mut m = r1;
        m.merge(r2);
        assert_eq!(m.stats.total_workers, 2);
        assert_eq!(m.stats.total_cpus, 2);
    }

    #[test]
    fn isolation_empty_reports() {
        let expected: BTreeSet<usize> = [0, 1].into_iter().collect();
        assert!(verify_isolation(&[], &expected).passed);
    }

    #[test]
    fn gap_boundary_2000ms_pass() {
        let r = verify_not_starved(&[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 2000)]);
        assert!(r.passed, "2000ms gap should pass: {:?}", r.details);
    }

    #[test]
    fn gap_boundary_2001ms_fail() {
        let r = verify_not_starved(&[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 2001)]);
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("stuck")));
    }

    #[test]
    fn scenario_stats_serde_roundtrip() {
        let s = ScenarioStats {
            cells: vec![CellStats {
                num_workers: 4,
                num_cpus: 2,
                avg_runnable_pct: 50.0,
                min_runnable_pct: 40.0,
                max_runnable_pct: 60.0,
                spread: 20.0,
                max_gap_ms: 150,
                max_gap_cpu: 3,
                total_migrations: 10,
            }],
            total_workers: 4,
            total_cpus: 2,
            total_migrations: 10,
            worst_spread: 20.0,
            worst_gap_ms: 150,
            worst_gap_cpu: 3,
        };
        let json = serde_json::to_string(&s).unwrap();
        let s2: ScenarioStats = serde_json::from_str(&json).unwrap();
        assert_eq!(s.total_workers, s2.total_workers);
        assert_eq!(s.worst_gap_ms, s2.worst_gap_ms);
        assert_eq!(s.cells.len(), s2.cells.len());
        assert_eq!(s.cells[0].num_workers, s2.cells[0].num_workers);
    }

    #[test]
    fn verify_result_serde_roundtrip() {
        let r = VerifyResult {
            passed: false,
            details: vec!["test".into()],
            stats: Default::default(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: VerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.passed, r2.passed);
        assert_eq!(r.details, r2.details);
    }

    #[test]
    fn verify_runnable_empty() {
        assert!(verify_runnable(&[], 4).passed);
    }

    #[test]
    fn verify_runnable_fair() {
        let r = verify_runnable(
            &[
                rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50),
                rpt(2, 1000, 5e9 as u64, 6e8 as u64, &[0], 50),
                rpt(3, 1000, 5e9 as u64, 55e7 as u64, &[0], 50),
            ],
            4,
        );
        assert!(r.passed, "{:?}", r.details);
    }

    #[test]
    fn verify_runnable_unfair() {
        let r = verify_runnable(
            &[
                rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 50), // 10%
                rpt(2, 500, 5e9 as u64, 4e9 as u64, &[0], 50),  // 80%
                rpt(3, 800, 5e9 as u64, 2e9 as u64, &[0], 50),  // 40%
            ],
            4,
        );
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("unfair")));
    }

    #[test]
    fn verify_runnable_stuck() {
        let r = verify_runnable(&[rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 2500)], 4);
        assert!(!r.passed);
        assert!(r.details.iter().any(|d| d.contains("stuck")));
    }

    #[test]
    fn multiple_stuck_workers() {
        let r = verify_not_starved(&[
            rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0], 3000),
            rpt(2, 1000, 5e9 as u64, 5e8 as u64, &[1], 4000),
        ]);
        assert!(!r.passed);
        let stuck_count = r.details.iter().filter(|d| d.contains("stuck")).count();
        assert_eq!(stuck_count, 2, "both workers should be flagged stuck");
    }

    #[test]
    fn migration_tracking() {
        let mut report = rpt(1, 1000, 5e9 as u64, 5e8 as u64, &[0, 1, 2], 50);
        report.migration_count = 5;
        let r = verify_not_starved(&[report]);
        assert_eq!(r.stats.total_migrations, 5);
    }
}
