// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::process::PerfScriptRecord;
use anyhow::{Context as _, Result};
use clap::{ArgAction, Parser};
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

    /// Verbosity level (-v for summary, -vv for detailed output)
    #[clap(short, long, action = ArgAction::Count)]
    pub verbose: u8,
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

/// Samples belonging to a group, in time order
struct GroupData {
    samples: Vec<PerfScriptRecord>,
}

impl GroupData {
    fn new() -> Self {
        Self { samples: Vec::new() }
    }

    fn push(&mut self, sample: PerfScriptRecord) {
        self.samples.push(sample);
    }

    fn samples(&self) -> &[PerfScriptRecord] {
        &self.samples
    }

    fn print(&self, group_name: &str, global_total: u64, verbosity: u8) {
        let group_pct = (self.samples.len() as f64 / global_total as f64) * 100.0;
        eprintln!("\n{}: {} samples ({:.2}%)", group_name, self.samples.len(), group_pct);

        let mut comm_counts: HashMap<String, u64> = HashMap::new();
        for sample in &self.samples {
            *comm_counts.entry(sample.comm.clone()).or_insert(0) += 1;
        }

        let mut counts: Vec<_> = comm_counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));

        let mut skipped = 0;
        for (comm, count) in counts {
            let pct = (*count as f64 / self.samples.len() as f64) * 100.0;
            if verbosity >= 2 || pct > 1.0 {
                eprintln!("  {}: {} ({:.2}%)", comm, count, pct);
            } else {
                skipped += 1;
            }
        }
        if skipped > 0 {
            eprintln!("  ... {} more below 1%", skipped);
        }
    }
}

/// Result of clustering analysis for a group
struct ClusterResult {
    /// Comms that exceed the significance threshold
    significant_comms: Vec<String>,
}

/// Group type for clustering decisions
#[derive(Debug, Clone, Copy, PartialEq)]
enum GroupType {
    Allotment,
    Workload,
    Rest,
}

/// Compute clustering for samples. Returns empty result for group types
/// where clustering is not yet implemented.
fn compute_clusters(
    group_type: GroupType,
    samples: &[&PerfScriptRecord],
    threshold_pct: f64,
) -> ClusterResult {
    // TODO(kkd): Enable clustering for Workload and Rest
    if group_type != GroupType::Allotment {
        return ClusterResult {
            significant_comms: Vec::new(),
        };
    }

    let total = samples.len();

    let mut comm_counts: HashMap<&str, u64> = HashMap::new();
    for sample in samples {
        *comm_counts.entry(&sample.comm).or_insert(0) += 1;
    }

    let mut significant_comms = Vec::new();
    if total > 0 {
        for (comm, count) in &comm_counts {
            let pct = (*count as f64 / total as f64) * 100.0;
            if pct > threshold_pct {
                significant_comms.push((*comm).to_string());
            }
        }
    }
    significant_comms.sort();

    ClusterResult { significant_comms }
}

/// Build subcells from clustering result. Returns empty if no significant comms.
fn build_subcells_from_clusters(result: &ClusterResult) -> Vec<CellSpec> {
    if result.significant_comms.is_empty() {
        return Vec::new();
    }

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

    let mut groups: HashMap<String, GroupData> = HashMap::new();
    let mut global_total: u64 = 0;

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        let record: PerfScriptRecord =
            serde_json::from_str(&line).context("failed to parse record")?;

        let group = classify_cgroup(&record.cgroup, workload_cgroup, &allotment_re);
        groups.entry(group.to_string()).or_insert_with(GroupData::new).push(record);
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

    if opts.verbose > 0 {
        eprintln!("Total samples: {}", global_total);
        for name in &group_names {
            if let Some(data) = groups.get(name) {
                data.print(name, global_total, opts.verbose);
            }
        }
    }

    let config = generate_config(&groups, &group_names, workload_cgroup, &opts.workload_allotment_cgroup_regex);
    let json = serde_json::to_string_pretty(&config).context("failed to serialize config")?;
    println!("{}", json);

    Ok(())
}

fn generate_config(
    groups: &HashMap<String, GroupData>,
    group_names: &[String],
    workload_cgroup: &str,
    allotment_regex: &str,
) -> CellConfig {
    let mut specs = Vec::new();

    // Process each group type uniformly
    let group_types = [
        (GroupType::Allotment, "allotment"),
        (GroupType::Workload, workload_cgroup),
        (GroupType::Rest, "rest"),
    ];

    for (group_type, name) in group_types {
        // Collect samples for this group type
        let samples: Vec<&PerfScriptRecord> = match group_type {
            GroupType::Allotment => group_names
                .iter()
                .filter(|n| *n != "rest" && *n != workload_cgroup)
                .filter_map(|n| groups.get(n))
                .flat_map(|g| g.samples())
                .collect(),
            GroupType::Workload => groups
                .get(workload_cgroup)
                .map(|g| g.samples().iter().collect())
                .unwrap_or_default(),
            GroupType::Rest => groups
                .get("rest")
                .map(|g| g.samples().iter().collect())
                .unwrap_or_default(),
        };

        if samples.is_empty() {
            continue;
        }

        // Compute clusters
        let clusters = compute_clusters(group_type, &samples, 5.0);
        let subcells = build_subcells_from_clusters(&clusters);

        // Build cell match based on group type
        let (cell_match, matches) = match group_type {
            GroupType::Allotment => (
                Some(CellMatch::CgroupRegex(allotment_regex.to_string())),
                Vec::new(),
            ),
            GroupType::Workload => (
                None,
                vec![vec![CellMatch::CgroupContains(workload_cgroup.to_string())]],
            ),
            GroupType::Rest => (None, vec![vec![]]),
        };

        specs.push(CellSpec {
            name: name.to_string(),
            cell_match,
            matches,
            subcells,
        });
    }

    CellConfig { specs }
}
