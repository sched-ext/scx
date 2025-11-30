// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use libbpf_rs::{query::ProgInfoIter, ProgramType};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SAMPLES: usize = 100;

#[derive(Clone, Debug)]
struct BpfProgSample {
    timestamp_ns: u64,
    run_time_ns: u64,
    run_count: u64,
}

#[derive(Clone, Debug)]
struct BpfProgStats {
    id: u32,
    name: String,
    prog_type: String,
    verified_insns: u32,
    samples: VecDeque<BpfProgSample>,
}

impl BpfProgStats {
    fn new(id: u32, name: String, prog_type: String, verified_insns: u32) -> Self {
        Self {
            id,
            name,
            prog_type,
            verified_insns,
            samples: VecDeque::new(),
        }
    }

    fn add_sample(&mut self, run_time_ns: u64, run_count: u64) {
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        self.samples.push_back(BpfProgSample {
            timestamp_ns,
            run_time_ns,
            run_count,
        });

        // Keep only the last MAX_SAMPLES
        while self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    fn compute_runtime_per_call_deltas(&self) -> Vec<f64> {
        let mut deltas = Vec::new();

        for i in 1..self.samples.len() {
            let prev = &self.samples[i - 1];
            let curr = &self.samples[i];

            let runtime_delta = curr.run_time_ns.saturating_sub(prev.run_time_ns);
            let calls_delta = curr.run_count.saturating_sub(prev.run_count);

            if calls_delta > 0 {
                deltas.push(runtime_delta as f64 / calls_delta as f64);
            }
        }

        deltas
    }

    fn compute_call_rate(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }

        let first = &self.samples[0];
        let last = &self.samples[self.samples.len() - 1];

        let time_delta_ns = last.timestamp_ns.saturating_sub(first.timestamp_ns);
        let calls_delta = last.run_count.saturating_sub(first.run_count);

        if time_delta_ns == 0 {
            return 0.0;
        }

        // Convert to calls per second
        (calls_delta as f64 / time_delta_ns as f64) * 1_000_000_000.0
    }

    fn compute_percentile(sorted_data: &[f64], percentile: f64) -> f64 {
        if sorted_data.is_empty() {
            return 0.0;
        }

        let n = sorted_data.len() as f64;
        let rank = (percentile / 100.0) * (n - 1.0);
        let rank_floor = rank.floor() as usize;
        let rank_ceil = rank.ceil() as usize;

        if rank_floor == rank_ceil || rank_ceil >= sorted_data.len() {
            sorted_data[rank_floor]
        } else {
            let d0 = sorted_data[rank_floor];
            let d1 = sorted_data[rank_ceil];
            d0 + (rank - rank_floor as f64) * (d1 - d0)
        }
    }

    fn get_statistics(&self) -> serde_json::Value {
        let runtime_deltas = self.compute_runtime_per_call_deltas();

        if runtime_deltas.is_empty() {
            return serde_json::json!({
                "samples": self.samples.len(),
                "avg_runtime_per_call_ns": 0,
                "p50_runtime_per_call_ns": 0,
                "p90_runtime_per_call_ns": 0,
                "p99_runtime_per_call_ns": 0,
                "call_rate_per_sec": 0,
            });
        }

        let mut sorted_deltas = runtime_deltas.clone();
        sorted_deltas.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let avg: f64 = sorted_deltas.iter().sum::<f64>() / sorted_deltas.len() as f64;
        let p50 = Self::compute_percentile(&sorted_deltas, 50.0);
        let p90 = Self::compute_percentile(&sorted_deltas, 90.0);
        let p99 = Self::compute_percentile(&sorted_deltas, 99.0);
        let call_rate = self.compute_call_rate();

        serde_json::json!({
            "samples": self.samples.len(),
            "avg_runtime_per_call_ns": avg as u64,
            "p50_runtime_per_call_ns": p50 as u64,
            "p90_runtime_per_call_ns": p90 as u64,
            "p99_runtime_per_call_ns": p99 as u64,
            "call_rate_per_sec": call_rate,
        })
    }
}

pub struct BpfStatsCollector {
    stats: Arc<Mutex<HashMap<u32, BpfProgStats>>>,
}

impl BpfStatsCollector {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn collect_sample(&self) -> Result<()> {
        let mut stats = self.stats.lock().unwrap();

        for prog_info in ProgInfoIter::default() {
            let prog_type = match prog_info.ty {
                ProgramType::Kprobe => "kprobe",
                ProgramType::Tracepoint => "tracepoint",
                ProgramType::RawTracepoint => "raw_tracepoint",
                ProgramType::PerfEvent => "perf_event",
                ProgramType::Tracing => "tracing",
                ProgramType::SchedAct => "sched_ext",
                ProgramType::Syscall => "syscall",
                _ => "other",
            };

            let entry = stats.entry(prog_info.id).or_insert_with(|| {
                BpfProgStats::new(
                    prog_info.id,
                    prog_info.name.to_string_lossy().to_string(),
                    prog_type.to_string(),
                    prog_info.xlated_prog_insns.len() as u32,
                )
            });

            entry.add_sample(prog_info.run_time_ns, prog_info.run_cnt);
        }

        Ok(())
    }

    pub fn get_stats(&self) -> serde_json::Value {
        let stats = self.stats.lock().unwrap();
        let mut programs = Vec::new();

        for prog_stats in stats.values() {
            let latest_sample = prog_stats.samples.back();

            let mut prog_data = serde_json::json!({
                "id": prog_stats.id,
                "name": prog_stats.name,
                "type": prog_stats.prog_type,
                "verified_insns": prog_stats.verified_insns,
            });

            if let Some(sample) = latest_sample {
                prog_data["run_time_ns"] = serde_json::json!(sample.run_time_ns);
                prog_data["run_count"] = serde_json::json!(sample.run_count);
            } else {
                prog_data["run_time_ns"] = serde_json::json!(0);
                prog_data["run_count"] = serde_json::json!(0);
            }

            let statistics = prog_stats.get_statistics();
            prog_data["statistics"] = statistics;

            programs.push(prog_data);
        }

        // Group programs by type
        let mut by_type: HashMap<String, Vec<_>> = HashMap::new();
        for prog in &programs {
            let prog_type = prog["type"].as_str().unwrap_or("unknown").to_string();
            by_type.entry(prog_type).or_default().push(prog.clone());
        }

        serde_json::json!({
            "programs": programs,
            "total_count": programs.len(),
            "by_type": by_type,
        })
    }
}

impl Default for BpfStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}
