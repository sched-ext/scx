// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::process::PerfScriptRecord;
use anyhow::{Context as _, Result};
use clap::Parser;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const DEFAULT_WORKLOAD_CGROUP_REGEX: &str = "workload.slice";
const DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX: &str = r"workload-tw-[^/]+\.allotment\.slice";

#[derive(Debug, Parser)]
pub struct ExtractOpts {
    /// Path to perf.jsonl file
    #[clap(short = 'f', long)]
    pub file: PathBuf,

    /// Regex pattern for workload cgroup
    #[clap(long, default_value = DEFAULT_WORKLOAD_CGROUP_REGEX)]
    pub workload_cgroup_regex: String,

    /// Regex pattern for workload allotment cgroups
    #[clap(long, default_value = DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX)]
    pub workload_allotment_cgroup_regex: String,

    /// Print detailed stats instead of config output
    #[clap(short, long)]
    pub verbose: bool,
}

fn classify_cgroup<'a>(cgroup: &'a str, workload_cgroup: &'a str, allotment_re: &Regex) -> &'a str {
    if !cgroup.contains(workload_cgroup) {
        return "rest";
    }

    if let Some(m) = allotment_re.find(cgroup) {
        return m.as_str();
    }

    workload_cgroup
}

struct GroupStats {
    comm_counts: HashMap<String, u64>,
    total: u64,
}

impl GroupStats {
    fn new() -> Self {
        Self {
            comm_counts: HashMap::new(),
            total: 0,
        }
    }

    fn add(&mut self, comm: &str) {
        *self.comm_counts.entry(comm.to_string()).or_insert(0) += 1;
        self.total += 1;
    }

    fn print(&self, group_name: &str, global_total: u64) {
        let group_pct = (self.total as f64 / global_total as f64) * 100.0;
        eprintln!("\n{}: {} samples ({:.2}%)", group_name, self.total, group_pct);

        let mut counts: Vec<_> = self.comm_counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));

        for (comm, count) in counts {
            let pct = (*count as f64 / self.total as f64) * 100.0;
            eprintln!("  {}: {} ({:.2}%)", comm, count, pct);
        }
    }
}

/// Result of clustering analysis for a group
struct ClusterResult {
    /// Comms that exceed the significance threshold
    significant_comms: Vec<String>,
}

/// Compute clustering for a set of group stats
fn compute_clusters(stats_list: &[&GroupStats], threshold_pct: f64) -> ClusterResult {
    let mut comm_counts: HashMap<String, u64> = HashMap::new();
    let mut total: u64 = 0;

    for stats in stats_list {
        for (comm, count) in &stats.comm_counts {
            *comm_counts.entry(comm.clone()).or_insert(0) += count;
        }
        total += stats.total;
    }

    let mut significant_comms = Vec::new();
    if total > 0 {
        for (comm, count) in &comm_counts {
            let pct = (*count as f64 / total as f64) * 100.0;
            if pct > threshold_pct {
                significant_comms.push(comm.clone());
            }
        }
    }
    significant_comms.sort();

    ClusterResult { significant_comms }
}

/// Build child cells from clustering result
fn build_subcells_from_clusters(result: &ClusterResult) -> Vec<CellSpec> {
    let mut subcells = Vec::new();

    for comm in &result.significant_comms {
        subcells.push(CellSpec {
            name: comm.clone(),
            cell_match: None,
            matches: vec![vec![CellMatch::CommPrefix(comm.clone())]],
            subcells: Vec::new(),
        });
    }

    subcells.push(CellSpec {
        name: "rest".to_string(),
        cell_match: None,
        matches: vec![vec![]],
        subcells: Vec::new(),
    });

    subcells
}

#[derive(Debug, Clone, Serialize)]
enum CellMatch {
    CgroupRegex(String),
    CgroupContains(String),
    CommPrefix(String),
}

#[derive(Debug, Clone, Serialize)]
struct CellSpec {
    name: String,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    cell_match: Option<CellMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matches: Vec<Vec<CellMatch>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subcells: Vec<CellSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
struct CellConfig {
    specs: Vec<CellSpec>,
}

pub fn cmd_extract(opts: ExtractOpts) -> Result<()> {
    let file = File::open(&opts.file).context("failed to open perf.jsonl")?;
    let reader = BufReader::new(file);

    let allotment_re = Regex::new(&opts.workload_allotment_cgroup_regex)
        .context("invalid allotment regex")?;
    let workload_cgroup = &opts.workload_cgroup_regex;

    let mut groups: HashMap<String, GroupStats> = HashMap::new();
    let mut global_total: u64 = 0;

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        let record: PerfScriptRecord =
            serde_json::from_str(&line).context("failed to parse record")?;

        let group = classify_cgroup(&record.cgroup, workload_cgroup, &allotment_re);
        groups.entry(group.to_string()).or_insert_with(GroupStats::new).add(&record.comm);
        global_total += 1;
    }

    let mut group_names: Vec<_> = groups.keys().cloned().collect();
    group_names.sort_by(|a, b| {
        let order = |s: &str| -> u8 {
            if s == "rest" { 2 }
            else if s == workload_cgroup { 1 }
            else { 0 }
        };
        order(a).cmp(&order(b)).then_with(|| a.cmp(b))
    });

    if opts.verbose {
        eprintln!("Total samples: {}", global_total);
        for name in &group_names {
            if let Some(stats) = groups.get(name) {
                stats.print(name, global_total);
            }
        }
    }

    let config = generate_config(&groups, &group_names, workload_cgroup, &opts.workload_allotment_cgroup_regex);
    let json = serde_json::to_string_pretty(&config).context("failed to serialize config")?;
    println!("{}", json);

    Ok(())
}

fn generate_config(
    groups: &HashMap<String, GroupStats>,
    group_names: &[String],
    workload_cgroup: &str,
    allotment_regex: &str,
) -> CellConfig {
    let mut specs = Vec::new();

    // Collect allotment group stats
    let allotment_stats: Vec<&GroupStats> = group_names
        .iter()
        .filter(|n| *n != "rest" && *n != workload_cgroup)
        .filter_map(|n| groups.get(n))
        .collect();

    // Compute clusters for allotments
    if !allotment_stats.is_empty() {
        let allotment_clusters = compute_clusters(&allotment_stats, 5.0);
        let subcells = build_subcells_from_clusters(&allotment_clusters);

        specs.push(CellSpec {
            name: "allotment".to_string(),
            cell_match: Some(CellMatch::CgroupRegex(allotment_regex.to_string())),
            matches: Vec::new(),
            subcells,
        });
    }

    // TODO(kkd): Compute clusters for workload.slice
    if groups.contains_key(workload_cgroup) {
        specs.push(CellSpec {
            name: workload_cgroup.to_string(),
            cell_match: None,
            matches: vec![vec![CellMatch::CgroupContains(workload_cgroup.to_string())]],
            subcells: Vec::new(),
        });
    }

    // TODO(kkd): Compute clusters for rest
    if groups.contains_key("rest") {
        specs.push(CellSpec {
            name: "rest".to_string(),
            cell_match: None,
            matches: vec![vec![]],
            subcells: Vec::new(),
        });
    }

    CellConfig { specs }
}
