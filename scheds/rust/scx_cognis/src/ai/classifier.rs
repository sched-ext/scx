// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// Heuristic Task Classifier
//
// Classifies each scheduling event into one of five labels using a
// deterministic, O(1) rule evaluated directly on `ops.enqueue`:
//
//   cpu_intensity = burst_ns / prev_assigned_slice_ns  (slice-usage fraction)
//
//   > 0.85  →  Compute     (consumed most of assigned slice; CPU-bound)
//   < 0.10  →  IoWait      (released CPU far before slice expired; I/O-blocked)
//   else    →  Interactive (yields regularly; latency-sensitive)
//
//   weight_norm > 0.95  →  RealTime  (SCHED_FIFO / SCHED_RR, regardless of slice usage)
//
// Stateless, no sliding window, no feedback loop.

/// Labels assigned to tasks after classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskLabel {
    /// Latency-sensitive interactive tasks (games, HID, audio).
    Interactive,
    /// CPU-bound background tasks (compilers, encoders).
    Compute,
    /// Tasks blocked on I/O most of the time.
    IoWait,
    /// Realtime or near-realtime tasks (audio daemons, JACK).
    RealTime,
    /// Not yet classified (unused in current heuristic; reserved).
    Unknown,
}

impl TaskLabel {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            TaskLabel::Interactive => "Interactive",
            TaskLabel::Compute => "Compute",
            TaskLabel::IoWait => "I/O Wait",
            TaskLabel::RealTime => "RealTime",
            TaskLabel::Unknown => "Unknown",
        }
    }
}

/// Compact feature vector for one scheduling event.
#[derive(Debug, Clone, Copy)]
pub struct TaskFeatures {
    /// `burst_ns / base_slice_ns` — most-recent burst as a fraction of the target slice.
    /// Reserved for future heuristic conditions.
    #[allow(dead_code)]
    pub runnable_ratio: f32,
    /// `burst_ns / prev_assigned_slice_ns` — fraction of the *assigned* slice consumed.
    /// This is the primary classification feature.
    pub cpu_intensity: f32,
    /// `burst_ns / exec_runtime` — freshness proxy.
    /// Near 1.0 = just woke (interactive/IO); near 0.0 = spinning (compute).
    pub exec_ratio: f32,
    /// Normalised scheduler weight (`weight / 10000`, 0..1).
    pub weight_norm: f32,
    /// Allowed CPUs / total online CPUs (0..1).
    /// Reserved for future heuristic conditions.
    #[allow(dead_code)]
    pub cpu_affinity: f32,
}

/// Deterministic, stateless heuristic task classifier.
///
/// Classifies each scheduling event in O(1) using only the `cpu_intensity`
/// feature (plus a `weight_norm` guard for real-time tasks). There is no
/// sliding window, no voting, and no per-PID state, which keeps the fallback
/// path predictable and easy to reason about.
pub struct HeuristicClassifier;

impl HeuristicClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify a task based on its feature vector.
    ///
    /// | `cpu_intensity`     | `exec_ratio` | Label       | Rationale                                     |
    /// |:--------------------|:-------------|:------------|:----------------------------------------------|
    /// | > 0.85              | **< 0.30**   | Compute     | High CPU + never sleeps = truly CPU-bound     |
    /// | > 0.85              | ≥ 0.30       | Interactive | High burst but just woke (e.g. 120fps render) |
    /// | 0.10 – 0.85         | any          | Interactive | Yields regularly; latency-sensitive           |
    /// | < 0.10              | any          | IoWait      | Released CPU before slice expired             |
    /// | weight_norm > 0.95  | any          | RealTime    | SCHED_FIFO / SCHED_RR                         |
    ///
    /// The `exec_ratio` guard is critical: `exec_runtime` resets on every wakeup
    /// (`ops.runnable`), so a browser rendering WebGL frames at 120fps gets
    /// `exec_ratio ≈ 1.0` even at 100% CPU per slice. Without this guard the
    /// monitor shows `Interactive:1 Compute:77` — the root cause of the
    /// 10× throughput regression in benchmarks.
    pub fn classify(&self, f: &TaskFeatures) -> TaskLabel {
        if f.weight_norm > 0.95 {
            return TaskLabel::RealTime;
        }
        // Compute requires BOTH high cpu_intensity AND low exec_ratio.
        // exec_runtime resets to 0 on every wakeup (ops.runnable), so:
        //   - Browser rendering at 120fps: exec_ratio ≈ 1.0 (just woke from vsync sleep)
        //   - stress-ng / compiler: exec_ratio ≈ 0  (never sleeps, accumulates forever)
        // Without this guard the monitor shows Interactive:1 Compute:77 for WebGL workloads.
        if f.cpu_intensity > 0.85 && f.exec_ratio < 0.30 {
            return TaskLabel::Compute;
        }
        if f.cpu_intensity < 0.10 {
            return TaskLabel::IoWait;
        }
        TaskLabel::Interactive
    }
}

impl Default for HeuristicClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shorthand: feat(cpu_intensity, runnable_ratio, exec_ratio)
    fn feat(cpu: f32, io: f32, exec: f32) -> TaskFeatures {
        TaskFeatures {
            runnable_ratio: io,
            cpu_intensity: cpu,
            exec_ratio: exec,
            weight_norm: 0.01,
            cpu_affinity: 1.0,
        }
    }

    #[test]
    fn heuristic_compute() {
        let clf = HeuristicClassifier::new();
        // cpu_intensity = 0.9 (used 90% of slice) AND exec_ratio = 0.001 (never sleeps)
        // → Compute.
        assert_eq!(clf.classify(&feat(0.9, 0.8, 0.001)), TaskLabel::Compute);
    }

    #[test]
    fn high_cpu_fresh_wakeup_is_interactive() {
        let clf = HeuristicClassifier::new();
        // cpu_intensity = 0.95 (used full slice) but exec_ratio = 0.95 (just woke from sleep).
        // e.g. a browser rendering one WebGL frame at 120fps: sleeps every ~8ms for vsync,
        // resets exec_runtime on wakeup, so exec_ratio ≈ 1.0 even at 100% CPU per slice.
        // Must be Interactive, NOT Compute.
        assert_eq!(clf.classify(&feat(0.95, 0.2, 0.95)), TaskLabel::Interactive);
    }

    #[test]
    fn heuristic_interactive() {
        let clf = HeuristicClassifier::new();
        // cpu_intensity = 0.45 → used 45 % of assigned slice → Interactive.
        assert_eq!(
            clf.classify(&feat(0.45, 0.02, 0.95)),
            TaskLabel::Interactive
        );
    }

    #[test]
    fn heuristic_iowait() {
        let clf = HeuristicClassifier::new();
        // cpu_intensity = 0.04 → used only 4 % of assigned slice → IoWait.
        assert_eq!(clf.classify(&feat(0.04, 0.04, 0.5)), TaskLabel::IoWait);
    }

    #[test]
    fn heuristic_boundary_interactive_low() {
        let clf = HeuristicClassifier::new();
        // cpu_intensity = 0.10 → at IoWait boundary → Interactive (exclusive lower bound).
        assert_eq!(clf.classify(&feat(0.10, 0.1, 0.5)), TaskLabel::Interactive);
    }

    #[test]
    fn heuristic_boundary_compute_high() {
        let clf = HeuristicClassifier::new();
        // cpu_intensity = 0.85 → at Compute boundary → Interactive (exclusive upper bound).
        assert_eq!(clf.classify(&feat(0.85, 0.8, 0.01)), TaskLabel::Interactive);
    }

    #[test]
    fn heuristic_realtime() {
        let clf = HeuristicClassifier::new();
        // weight_norm = 0.99 → SCHED_FIFO/RR → RealTime regardless of cpu_intensity.
        let f = TaskFeatures {
            runnable_ratio: 0.5,
            cpu_intensity: 0.5,
            exec_ratio: 0.5,
            weight_norm: 0.99,
            cpu_affinity: 1.0,
        };
        assert_eq!(clf.classify(&f), TaskLabel::RealTime);
    }
}
