// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Latency type being tracked
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LatencyType {
    WakeupToRun,
    DsqWait,
    CpuMigration,
    SchedulingDelay,
}

/// Latency tracker
pub struct LatencyTracker {
    latencies: HashMap<LatencyType, Vec<u64>>,
    breakdown_by_cpu: HashMap<(LatencyType, u32), Vec<u64>>,
    breakdown_by_pid: HashMap<(LatencyType, u32), Vec<u64>>,
    window_start: u64,
    #[allow(dead_code)]
    window_duration_ms: u64,
    enabled: bool,
}

impl LatencyTracker {
    pub fn new(window_duration_ms: u64) -> Self {
        let window_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            latencies: HashMap::new(),
            breakdown_by_cpu: HashMap::new(),
            breakdown_by_pid: HashMap::new(),
            window_start,
            window_duration_ms,
            enabled: false, // Disabled by default
        }
    }

    /// Enable latency tracking
    pub fn start(&mut self) {
        self.enabled = true;
        self.window_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    /// Disable latency tracking
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if tracker is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.latencies.clear();
        self.breakdown_by_cpu.clear();
        self.breakdown_by_pid.clear();
        self.window_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    pub fn add_latency(
        &mut self,
        lat_type: LatencyType,
        latency_us: u64,
        cpu: Option<u32>,
        pid: Option<u32>,
    ) {
        if !self.enabled {
            return;
        }
        // Add to overall stats
        self.latencies
            .entry(lat_type.clone())
            .or_default()
            .push(latency_us);

        // Add to CPU breakdown
        if let Some(cpu) = cpu {
            self.breakdown_by_cpu
                .entry((lat_type.clone(), cpu))
                .or_default()
                .push(latency_us);
        }

        // Add to PID breakdown
        if let Some(pid) = pid {
            self.breakdown_by_pid
                .entry((lat_type, pid))
                .or_default()
                .push(latency_us);
        }
    }

    pub fn compute_histogram(
        &self,
        lat_type: &LatencyType,
        buckets: &[u64],
    ) -> HashMap<String, u64> {
        let latencies = match self.latencies.get(lat_type) {
            Some(v) => v,
            None => return HashMap::new(),
        };

        let mut histogram = HashMap::new();
        for &latency in latencies {
            let bucket = self.find_bucket(latency, buckets);
            *histogram.entry(bucket).or_insert(0) += 1;
        }

        histogram
    }

    fn find_bucket(&self, value: u64, buckets: &[u64]) -> String {
        for (i, &bucket) in buckets.iter().enumerate() {
            if value < bucket {
                if i == 0 {
                    return format!("0-{}us", bucket);
                } else {
                    return format!("{}-{}us", buckets[i - 1], bucket);
                }
            }
        }
        format!(">{}us", buckets.last().unwrap_or(&0))
    }

    pub fn get_stats(&self, lat_type: &LatencyType) -> Option<LatencyStats> {
        let latencies = self.latencies.get(lat_type)?;
        if latencies.is_empty() {
            return None;
        }

        let mut sorted = latencies.clone();
        sorted.sort_unstable();

        Some(LatencyStats {
            count: sorted.len() as u64,
            min: *sorted.first().unwrap(),
            max: *sorted.last().unwrap(),
            mean: sorted.iter().sum::<u64>() as f64 / sorted.len() as f64,
            p50: percentile(&sorted, 50.0),
            p95: percentile(&sorted, 95.0),
            p99: percentile(&sorted, 99.0),
        })
    }

    pub fn get_cpu_breakdown(&self, lat_type: &LatencyType, top_n: usize) -> Vec<CpuLatencyStats> {
        let mut stats: Vec<_> = self
            .breakdown_by_cpu
            .iter()
            .filter(|((lt, _), _)| lt == lat_type)
            .map(|((_, cpu), latencies)| {
                let mut sorted = latencies.clone();
                sorted.sort_unstable();

                CpuLatencyStats {
                    cpu: *cpu,
                    count: sorted.len() as u64,
                    p99: percentile(&sorted, 99.0),
                    max: *sorted.last().unwrap(),
                }
            })
            .collect();

        stats.sort_by(|a, b| b.p99.partial_cmp(&a.p99).unwrap());
        stats.truncate(top_n);
        stats
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LatencyStats {
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub mean: f64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuLatencyStats {
    pub cpu: u32,
    pub count: u64,
    pub p99: u64,
    pub max: u64,
}

/// CPU hotspot analyzer
pub struct CpuHotspotAnalyzer {
    window_duration_ms: u64,
    window_start: u64,
    context_switches_per_cpu: HashMap<u32, u64>,
    ipis_per_cpu: HashMap<u32, u64>,
    migrations_per_cpu: HashMap<u32, u64>,
    avg_latency_per_cpu: HashMap<u32, Vec<u64>>,
    enabled: bool,
}

impl CpuHotspotAnalyzer {
    pub fn new(window_duration_ms: u64) -> Self {
        Self {
            window_duration_ms,
            window_start: now_ms(),
            context_switches_per_cpu: HashMap::new(),
            ipis_per_cpu: HashMap::new(),
            migrations_per_cpu: HashMap::new(),
            avg_latency_per_cpu: HashMap::new(),
            enabled: false, // Disabled by default
        }
    }

    /// Enable CPU hotspot analysis
    pub fn start(&mut self) {
        self.enabled = true;
        self.window_start = now_ms();
    }

    /// Disable CPU hotspot analysis
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if analyzer is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.context_switches_per_cpu.clear();
        self.ipis_per_cpu.clear();
        self.migrations_per_cpu.clear();
        self.avg_latency_per_cpu.clear();
        self.window_start = now_ms();
    }

    pub fn record_event(&mut self, json: &Value) {
        if !self.enabled {
            return;
        }
        if let Some(event_type) = json.get("type").and_then(|v| v.as_str()) {
            let cpu = json.get("cpu").and_then(|v| v.as_u64()).map(|v| v as u32);

            match event_type {
                "sched_switch" => {
                    if let Some(cpu) = cpu {
                        *self.context_switches_per_cpu.entry(cpu).or_insert(0) += 1;

                        if let Some(lat) = json.get("next_dsq_lat_us").and_then(|v| v.as_u64()) {
                            self.avg_latency_per_cpu.entry(cpu).or_default().push(lat);
                        }
                    }
                }
                "ipi" => {
                    if let Some(cpu) = cpu {
                        *self.ipis_per_cpu.entry(cpu).or_insert(0) += 1;
                    }
                }
                "sched_migrate_task" => {
                    if let Some(cpu) = json
                        .get("dest_cpu")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32)
                    {
                        *self.migrations_per_cpu.entry(cpu).or_insert(0) += 1;
                    }
                }
                _ => {}
            }
        }
    }

    pub fn compute_hotspots(&self, threshold_percentile: f64) -> Vec<CpuHotspot> {
        let window_duration_sec = self.window_duration_ms as f64 / 1000.0;

        // Calculate rates
        let cpu_metrics: Vec<_> = self
            .context_switches_per_cpu
            .keys()
            .map(|cpu| {
                let cs_rate = *self.context_switches_per_cpu.get(cpu).unwrap_or(&0) as f64
                    / window_duration_sec;
                let ipi_rate =
                    *self.ipis_per_cpu.get(cpu).unwrap_or(&0) as f64 / window_duration_sec;
                let migration_rate =
                    *self.migrations_per_cpu.get(cpu).unwrap_or(&0) as f64 / window_duration_sec;
                let avg_latency = self
                    .avg_latency_per_cpu
                    .get(cpu)
                    .map(|lats| {
                        if !lats.is_empty() {
                            lats.iter().sum::<u64>() as f64 / lats.len() as f64
                        } else {
                            0.0
                        }
                    })
                    .unwrap_or(0.0);

                (*cpu, cs_rate, ipi_rate, migration_rate, avg_latency)
            })
            .collect();

        // Find hotspots (CPUs above threshold percentile)
        let cs_threshold = calculate_threshold(
            &cpu_metrics
                .iter()
                .map(|(_, cs, _, _, _)| *cs)
                .collect::<Vec<_>>(),
            threshold_percentile,
        );

        let mut hotspots: Vec<_> = cpu_metrics
            .iter()
            .filter(|(_, cs_rate, _, _, _)| *cs_rate >= cs_threshold)
            .map(|(cpu, cs_rate, ipi_rate, migration_rate, avg_latency)| {
                let percentile = calculate_percentile_rank(
                    *cs_rate,
                    &cpu_metrics
                        .iter()
                        .map(|(_, cs, _, _, _)| *cs)
                        .collect::<Vec<_>>(),
                );
                let concern_level = if percentile > 99.0 {
                    "critical"
                } else if percentile > 95.0 {
                    "high"
                } else {
                    "medium"
                };

                CpuHotspot {
                    cpu: *cpu,
                    context_switch_rate: *cs_rate,
                    ipi_rate: *ipi_rate,
                    migration_rate: *migration_rate,
                    avg_latency: *avg_latency,
                    percentile,
                    concern_level: concern_level.to_string(),
                }
            })
            .collect();

        hotspots.sort_by(|a, b| b.percentile.partial_cmp(&a.percentile).unwrap());
        hotspots
    }

    pub fn system_averages(&self) -> SystemAverages {
        let window_duration_sec = self.window_duration_ms as f64 / 1000.0;
        let num_cpus = self.context_switches_per_cpu.len() as f64;

        SystemAverages {
            context_switch_rate: self.context_switches_per_cpu.values().sum::<u64>() as f64
                / window_duration_sec
                / num_cpus,
            ipi_rate: self.ipis_per_cpu.values().sum::<u64>() as f64
                / window_duration_sec
                / num_cpus,
            migration_rate: self.migrations_per_cpu.values().sum::<u64>() as f64
                / window_duration_sec
                / num_cpus,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuHotspot {
    pub cpu: u32,
    pub context_switch_rate: f64,
    pub ipi_rate: f64,
    pub migration_rate: f64,
    pub avg_latency: f64,
    pub percentile: f64,
    pub concern_level: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemAverages {
    pub context_switch_rate: f64,
    pub ipi_rate: f64,
    pub migration_rate: f64,
}

/// Migration pattern analyzer
pub struct MigrationAnalyzer {
    migrations: Vec<MigrationEvent>,
    window_start: u64,
    window_duration_ms: u64,
    enabled: bool,
}

#[derive(Clone, Debug)]
struct MigrationEvent {
    #[allow(dead_code)]
    timestamp: u64,
    pid: u32,
    comm: String,
    from_cpu: u32,
    to_cpu: u32,
}

impl MigrationAnalyzer {
    pub fn new(window_duration_ms: u64) -> Self {
        Self {
            migrations: Vec::new(),
            window_start: now_ms(),
            window_duration_ms,
            enabled: false, // Disabled by default
        }
    }

    /// Enable migration tracking
    pub fn start(&mut self) {
        self.enabled = true;
        self.window_start = now_ms();
    }

    /// Disable migration tracking
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if analyzer is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.migrations.clear();
        self.window_start = now_ms();
    }

    pub fn record_migration(&mut self, json: &Value, timestamp: u64) {
        if !self.enabled {
            return;
        }
        if json.get("type").and_then(|v| v.as_str()) == Some("sched_migrate_task") {
            let pid = json.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
            let comm = json
                .get("comm")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let from_cpu = json.get("cpu").and_then(|v| v.as_u64()).map(|v| v as u32);
            let to_cpu = json
                .get("dest_cpu")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);

            if let (Some(pid), Some(from_cpu), Some(to_cpu)) = (pid, from_cpu, to_cpu) {
                self.migrations.push(MigrationEvent {
                    timestamp,
                    pid,
                    comm,
                    from_cpu,
                    to_cpu,
                });
            }
        }
    }

    pub fn analyze(&self) -> MigrationAnalysis {
        let total_migrations = self.migrations.len() as u64;
        let window_duration_sec = self.window_duration_ms as f64 / 1000.0;
        let migration_rate = total_migrations as f64 / window_duration_sec;

        // Per-process analysis
        let mut per_process: HashMap<u32, ProcessMigrationStats> = HashMap::new();
        for mig in &self.migrations {
            let stats = per_process
                .entry(mig.pid)
                .or_insert_with(|| ProcessMigrationStats {
                    pid: mig.pid,
                    comm: mig.comm.clone(),
                    migration_count: 0,
                    cpu_affinity: Vec::new(),
                    ping_pong_count: 0,
                });

            stats.migration_count += 1;
            if !stats.cpu_affinity.contains(&mig.from_cpu) {
                stats.cpu_affinity.push(mig.from_cpu);
            }
            if !stats.cpu_affinity.contains(&mig.to_cpu) {
                stats.cpu_affinity.push(mig.to_cpu);
            }
        }

        // Detect ping-pong migrations
        for mig_group in self.migrations.windows(2) {
            if mig_group[0].pid == mig_group[1].pid
                && mig_group[0].to_cpu == mig_group[1].from_cpu
                && mig_group[0].from_cpu == mig_group[1].to_cpu
            {
                if let Some(stats) = per_process.get_mut(&mig_group[0].pid) {
                    stats.ping_pong_count += 1;
                }
            }
        }

        let mut process_patterns: Vec<_> = per_process.into_values().collect();
        process_patterns.sort_by(|a, b| b.migration_count.cmp(&a.migration_count));
        process_patterns.truncate(20);

        // CPU pair analysis
        let mut cpu_pairs: HashMap<(u32, u32), u64> = HashMap::new();
        for mig in &self.migrations {
            *cpu_pairs.entry((mig.from_cpu, mig.to_cpu)).or_insert(0) += 1;
        }

        let mut cpu_pair_stats: Vec<_> = cpu_pairs
            .into_iter()
            .map(|((from, to), count)| CpuPairMigration {
                from_cpu: from,
                to_cpu: to,
                count,
            })
            .collect();

        cpu_pair_stats.sort_by(|a, b| b.count.cmp(&a.count));
        cpu_pair_stats.truncate(20);

        MigrationAnalysis {
            total_migrations,
            migration_rate,
            process_patterns,
            cpu_pairs: cpu_pair_stats,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MigrationAnalysis {
    pub total_migrations: u64,
    pub migration_rate: f64,
    pub process_patterns: Vec<ProcessMigrationStats>,
    pub cpu_pairs: Vec<CpuPairMigration>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessMigrationStats {
    pub pid: u32,
    pub comm: String,
    pub migration_count: u64,
    pub cpu_affinity: Vec<u32>,
    pub ping_pong_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuPairMigration {
    pub from_cpu: u32,
    pub to_cpu: u32,
    pub count: u64,
}

// Helper functions

fn percentile(sorted_values: &[u64], p: f64) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted_values.len() - 1) as f64).round() as usize;
    sorted_values[idx]
}

fn calculate_threshold(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((percentile / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx]
}

fn calculate_percentile_rank(value: f64, values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let count_below = values.iter().filter(|&&v| v < value).count();
    (count_below as f64 / values.len() as f64) * 100.0
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
