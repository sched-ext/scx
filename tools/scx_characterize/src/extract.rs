// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::process::PerfMemRecord;
use anyhow::{Context as _, Result};
use clap::{ArgAction, Parser, Subcommand};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const DEFAULT_WORKLOAD_CGROUP_REGEX: &str = "workload.slice";
const DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX: &str = r"workload-tw-[^/]+\.allotment\.slice";

#[derive(Debug, Parser)]
pub struct ExtractMemOpts {
    /// Path to perf.mem.jsonl file
    #[clap(short = 'f', long)]
    pub file: PathBuf,

    /// Regex pattern for workload cgroup
    #[clap(long, default_value = DEFAULT_WORKLOAD_CGROUP_REGEX)]
    pub workload_cgroup_regex: String,

    /// Regex pattern for workload allotment cgroups
    #[clap(long, default_value = DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX)]
    pub workload_allotment_cgroup_regex: String,

    /// Split significant comm subcells further by hint values
    #[clap(long)]
    pub use_hints: bool,

    /// Verbosity level (-v for summary, -vv for detailed output)
    #[clap(short, long, action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Parser)]
pub struct ExtractOpts {
    #[clap(subcommand)]
    pub command: ExtractCommand,
}

#[derive(Debug, Subcommand)]
pub enum ExtractCommand {
    /// Extract workload cell config from perf.mem.jsonl
    Mem(ExtractMemOpts),
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
    samples: Vec<PerfMemRecord>,
}

impl GroupData {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn push(&mut self, sample: PerfMemRecord) {
        self.samples.push(sample);
    }

    fn samples(&self) -> &[PerfMemRecord] {
        &self.samples
    }

    fn print(&self, group_name: &str, global_total: u64, verbosity: u8, use_hints: bool) {
        let group_pct = (self.samples.len() as f64 / global_total as f64) * 100.0;
        eprintln!(
            "\n{}: {} samples ({:.2}%)",
            group_name,
            self.samples.len(),
            group_pct
        );

        let sample_refs: Vec<_> = self.samples.iter().collect();
        let counts = summarize_comm_groups(&sample_refs);
        let mut printed_aggregated_marker_note = false;

        let mut skipped = 0;
        for entry in counts {
            let pct = (entry.count as f64 / self.samples.len() as f64) * 100.0;
            if verbosity >= 2 || pct > 1.0 {
                let display_name = if entry.aggregated_numeric_suffixes {
                    printed_aggregated_marker_note = true;
                    format!("{}*", entry.name)
                } else {
                    entry.name.clone()
                };
                eprintln!("  {}: {} ({:.2}%)", display_name, entry.count, pct);
                if use_hints && entry.hint_counts.len() > 1 {
                    let mut skipped_hints = 0;
                    for (hint, count) in entry.hint_counts {
                        let hint_pct = (count as f64 / entry.count as f64) * 100.0;
                        if verbosity >= 2 || hint_pct > 1.0 {
                            eprintln!("    hint={}: {} ({:.2}%)", hint, count, hint_pct);
                        } else {
                            skipped_hints += 1;
                        }
                    }
                    if skipped_hints > 0 {
                        eprintln!("    ... {} more hints below 1%", skipped_hints);
                    }
                }
                if verbosity >= 2 && entry.concrete_counts.len() > 1 {
                    for (comm, count) in entry.concrete_counts {
                        let comm_pct = (count as f64 / entry.count as f64) * 100.0;
                        eprintln!("    {}: {} ({:.2}%)", comm, count, comm_pct);
                    }
                }
            } else {
                skipped += 1;
            }
        }
        if skipped > 0 {
            eprintln!("  ... {} more below 1%", skipped);
        }
        if printed_aggregated_marker_note {
            eprintln!("  * trailing numeric suffixes merged");
        }
    }
}

/// Result of clustering analysis for a group
struct ClusterResult {
    /// Comms that exceed the significance threshold, optionally with hint splits
    significant_comms: Vec<CommCluster>,
}

/// Clustering result for a single comm
struct CommCluster {
    name: String,
    match_comms: Vec<String>,
    significant_hints: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommSummary {
    name: String,
    count: u64,
    aggregated_numeric_suffixes: bool,
    hint_counts: Vec<(u64, u64)>,
    concrete_counts: Vec<(String, u64)>,
}

#[derive(Debug, Default)]
struct GroupedCommSamples<'a> {
    samples: Vec<&'a PerfMemRecord>,
    hint_counts: HashMap<u64, u64>,
    concrete_counts: HashMap<String, u64>,
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
    samples: &[&PerfMemRecord],
    threshold_pct: f64,
    use_hints: bool,
) -> ClusterResult {
    // TODO(kkd): Enable clustering for Workload and Rest
    if group_type != GroupType::Allotment {
        return ClusterResult {
            significant_comms: Vec::new(),
        };
    }

    let total = samples.len();
    let grouped_samples = group_samples_by_normalized_comm(samples);

    let mut significant_comms = Vec::new();
    if total > 0 {
        for (cluster_name, group) in grouped_samples {
            let count = group.samples.len() as u64;
            let pct = (count as f64 / total as f64) * 100.0;
            if pct > threshold_pct {
                let significant_hints = if use_hints {
                    compute_significant_hints(&group.samples, threshold_pct)
                } else {
                    Vec::new()
                };
                significant_comms.push(CommCluster {
                    name: cluster_name.clone(),
                    match_comms: group
                        .concrete_counts
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    significant_hints,
                });
            }
        }
    }
    significant_comms.sort_by(|a, b| a.name.cmp(&b.name));

    ClusterResult { significant_comms }
}

fn group_samples_by_normalized_comm<'a>(
    samples: &[&'a PerfMemRecord],
) -> HashMap<String, GroupedCommSamples<'a>> {
    let mut grouped = HashMap::new();
    for sample in samples {
        let cluster_name = normalize_comm_for_cluster(&sample.comm);
        let entry = grouped
            .entry(cluster_name)
            .or_insert_with(GroupedCommSamples::default);
        entry.samples.push(*sample);
        *entry.hint_counts.entry(sample.hint).or_insert(0) += 1;
        *entry
            .concrete_counts
            .entry(sample.comm.clone())
            .or_insert(0) += 1;
    }
    grouped
}

fn normalize_comm_for_cluster(comm: &str) -> String {
    let normalized = comm.trim_end_matches(|ch: char| ch.is_ascii_digit());
    if normalized.is_empty() {
        comm.to_string()
    } else {
        normalized.to_string()
    }
}

fn compute_significant_hints(samples: &[&PerfMemRecord], threshold_pct: f64) -> Vec<u64> {
    let mut hint_counts: HashMap<u64, u64> = HashMap::new();
    for sample in samples {
        *hint_counts.entry(sample.hint).or_insert(0) += 1;
    }

    if hint_counts.len() <= 1 {
        return Vec::new();
    }

    let total = samples.len();
    let mut significant_hints = Vec::new();
    if total > 0 {
        for (hint, count) in hint_counts {
            let pct = (count as f64 / total as f64) * 100.0;
            if pct > threshold_pct {
                significant_hints.push(hint);
            }
        }
    }
    significant_hints.sort_unstable();
    significant_hints
}

fn summarize_comm_groups(samples: &[&PerfMemRecord]) -> Vec<CommSummary> {
    let mut summary: Vec<_> = group_samples_by_normalized_comm(samples)
        .into_iter()
        .map(|(name, group)| {
            let mut hint_counts: Vec<_> = group.hint_counts.into_iter().collect();
            hint_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let mut concrete_counts: Vec<_> = group.concrete_counts.into_iter().collect();
            concrete_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            CommSummary {
                name,
                count: group.samples.len() as u64,
                aggregated_numeric_suffixes: concrete_counts.len() > 1,
                hint_counts,
                concrete_counts,
            }
        })
        .collect();

    summary.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    summary
}

/// Build subcells from clustering result. Returns empty if no significant comms.
fn build_subcells_from_clusters(result: &ClusterResult) -> Vec<CellSpec> {
    if result.significant_comms.is_empty() {
        return Vec::new();
    }

    let mut subcells = Vec::new();

    for comm in &result.significant_comms {
        if comm.significant_hints.is_empty() {
            subcells.push(CellSpec {
                name: comm.name.clone(),
                matches: CellMatches::complex(build_comm_match_clauses(comm, None)),
                subcells: Vec::new(),
            });
        } else {
            for hint in &comm.significant_hints {
                subcells.push(CellSpec {
                    name: format!("{}@hint={hint}", comm.name),
                    matches: CellMatches::complex(build_comm_match_clauses(comm, Some(*hint))),
                    subcells: Vec::new(),
                });
            }
        }
    }

    subcells.push(CellSpec {
        name: "rest".to_string(),
        matches: CellMatches::complex(vec![vec![]]),
        subcells: Vec::new(),
    });

    subcells
}

fn build_comm_match_clauses(comm: &CommCluster, hint: Option<u64>) -> Vec<Vec<CellMatch>> {
    let comm_patterns = emitted_comm_patterns(comm);

    comm_patterns
        .iter()
        .map(|exact_comm| {
            let mut clause = vec![CellMatch::CommPrefix(exact_comm.clone())];
            if let Some(hint) = hint {
                clause.push(CellMatch::Hint(hint));
            }
            clause
        })
        .collect()
}

fn emitted_comm_patterns(comm: &CommCluster) -> Vec<String> {
    if comm.match_comms.len() > 1
        && !comm.name.is_empty()
        && comm
            .match_comms
            .iter()
            .all(|match_comm| match_comm.starts_with(&comm.name))
    {
        vec![comm.name.clone()]
    } else {
        comm.match_comms.clone()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum CellMatch {
    CommPrefix(String),
    Hint(u64),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum CellMatches {
    Simple(SimpleCellMatches),
    Complex(Vec<Vec<CellMatch>>),
}

impl CellMatches {
    fn simple(matches: SimpleCellMatches) -> Self {
        Self::Simple(matches)
    }

    fn complex(matches: Vec<Vec<CellMatch>>) -> Self {
        Self::Complex(matches)
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct SimpleCellMatches {
    #[serde(rename = "CgroupRegex", skip_serializing_if = "Option::is_none")]
    cgroup_regex: Option<String>,
    #[serde(rename = "CgroupContains", skip_serializing_if = "Option::is_none")]
    cgroup_contains: Option<String>,
}

impl SimpleCellMatches {
    fn cgroup_regex(value: String) -> Self {
        Self {
            cgroup_regex: Some(value),
            cgroup_contains: None,
        }
    }

    fn cgroup_contains(value: String) -> Self {
        Self {
            cgroup_regex: None,
            cgroup_contains: Some(value),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CellSpec {
    name: String,
    matches: CellMatches,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subcells: Vec<CellSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
struct CellConfig {
    specs: Vec<CellSpec>,
}

pub fn cmd_extract_mem(opts: ExtractMemOpts) -> Result<()> {
    let file = File::open(&opts.file).context("failed to open perf.mem.jsonl")?;
    let reader = BufReader::new(file);

    let allotment_re =
        Regex::new(&opts.workload_allotment_cgroup_regex).context("invalid allotment regex")?;
    let workload_cgroup = &opts.workload_cgroup_regex;

    let mut groups: HashMap<String, GroupData> = HashMap::new();
    let mut global_total: u64 = 0;

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        let record: PerfMemRecord =
            serde_json::from_str(&line).context("failed to parse record")?;

        let group = classify_cgroup(&record.cgroup, workload_cgroup, &allotment_re);
        groups
            .entry(group.to_string())
            .or_insert_with(GroupData::new)
            .push(record);
        global_total += 1;
    }

    let mut group_names: Vec<_> = groups.keys().cloned().collect();
    group_names.sort_by(|a, b| {
        let order = |s: &str| -> u8 {
            if s == "rest" {
                2
            } else if s == workload_cgroup {
                1
            } else {
                0
            }
        };
        order(a).cmp(&order(b)).then_with(|| a.cmp(b))
    });

    if opts.verbose > 0 {
        eprintln!("Total samples: {}", global_total);
        for name in &group_names {
            if let Some(data) = groups.get(name) {
                data.print(name, global_total, opts.verbose, opts.use_hints);
            }
        }
    }

    let config = generate_config(
        &groups,
        &group_names,
        workload_cgroup,
        &opts.workload_allotment_cgroup_regex,
        opts.use_hints,
    );
    let json = serde_json::to_string_pretty(&config).context("failed to serialize config")?;
    println!("{}", json);

    Ok(())
}

pub fn cmd_extract(opts: ExtractOpts) -> Result<()> {
    match opts.command {
        ExtractCommand::Mem(opts) => cmd_extract_mem(opts),
    }
}

fn generate_config(
    groups: &HashMap<String, GroupData>,
    group_names: &[String],
    workload_cgroup: &str,
    allotment_regex: &str,
    use_hints: bool,
) -> CellConfig {
    let mut specs = Vec::new();

    let group_types = [
        (GroupType::Allotment, "allotment"),
        (GroupType::Workload, workload_cgroup),
        (GroupType::Rest, "rest"),
    ];

    for (group_type, name) in group_types {
        let samples: Vec<&PerfMemRecord> = match group_type {
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

        let clusters = compute_clusters(group_type, &samples, 5.0, use_hints);
        let subcells = build_subcells_from_clusters(&clusters);

        let matches = match group_type {
            GroupType::Allotment => {
                CellMatches::simple(SimpleCellMatches::cgroup_regex(allotment_regex.to_string()))
            }
            GroupType::Workload => CellMatches::simple(SimpleCellMatches::cgroup_contains(
                workload_cgroup.to_string(),
            )),
            GroupType::Rest => CellMatches::simple(SimpleCellMatches::default()),
        };

        specs.push(CellSpec {
            name: name.to_string(),
            matches,
            subcells,
        });
    }

    CellConfig { specs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample(comm: &str, cgroup: &str, hint: u64) -> PerfMemRecord {
        serde_json::from_value(json!({
            "comm": comm,
            "tid": 1,
            "pid": 1,
            "time": "0",
            "addr": "0",
            "cgroup": cgroup,
            "ip": "0",
            "sym": "sym",
            "dso": "dso",
            "phys_addr": "0",
            "data_page_size": 4096,
            "hint": hint,
        }))
        .expect("failed to build PerfMemRecord test sample")
    }

    fn push_samples(
        groups: &mut HashMap<String, GroupData>,
        group: &str,
        comm: &str,
        hint: u64,
        count: usize,
    ) {
        let data = groups
            .entry(group.to_string())
            .or_insert_with(GroupData::new);
        for _ in 0..count {
            data.push(sample(comm, group, hint));
        }
    }

    #[test]
    fn mem_extract_does_not_split_comms_by_hint_without_flag() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "alpha", 0, 60);
        push_samples(&mut groups, allotment, "alpha", 7, 20);
        push_samples(&mut groups, allotment, "alpha", 9, 10);
        push_samples(&mut groups, allotment, "beta", 0, 10);

        let group_names = vec![allotment.to_string()];
        let config = generate_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        let alpha = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha")
            .expect("missing alpha comm subcell");

        assert!(alpha.subcells.is_empty());
    }

    #[test]
    fn mem_extract_splits_significant_comms_by_hint_with_flag() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "alpha", 0, 60);
        push_samples(&mut groups, allotment, "alpha", 7, 20);
        push_samples(&mut groups, allotment, "alpha", 9, 10);
        push_samples(&mut groups, allotment, "beta", 0, 10);

        let group_names = vec![allotment.to_string()];
        let config = generate_config(&groups, &group_names, workload, "allotment-regex", true);

        let allotment_spec = &config.specs[0];
        let alpha_hint_0 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha@hint=0")
            .expect("missing alpha@hint=0 subcell");
        let alpha_hint_7 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha@hint=7")
            .expect("missing alpha@hint=7 subcell");
        let alpha_hint_9 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha@hint=9")
            .expect("missing alpha@hint=9 subcell");

        assert_eq!(
            alpha_hint_0.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("alpha".to_string()),
                CellMatch::Hint(0),
            ]])
        );
        assert_eq!(
            alpha_hint_7.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("alpha".to_string()),
                CellMatch::Hint(7),
            ]])
        );
        assert_eq!(
            alpha_hint_9.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("alpha".to_string()),
                CellMatch::Hint(9),
            ]])
        );

        let beta = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "beta")
            .expect("missing beta comm subcell");
        assert!(beta.subcells.is_empty());
    }

    #[test]
    fn mem_extract_uses_single_match_statement_for_top_level_cells() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "alpha", 0, 10);
        push_samples(&mut groups, workload, "beta", 0, 10);
        push_samples(&mut groups, "rest", "gamma", 0, 10);

        let mut group_names = vec![
            allotment.to_string(),
            workload.to_string(),
            "rest".to_string(),
        ];
        group_names.sort();

        let config = generate_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = config
            .specs
            .iter()
            .find(|spec| spec.name == "allotment")
            .expect("missing allotment spec");
        assert_eq!(
            allotment_spec.matches,
            CellMatches::simple(SimpleCellMatches::cgroup_regex(
                "allotment-regex".to_string()
            ))
        );

        let workload_spec = config
            .specs
            .iter()
            .find(|spec| spec.name == workload)
            .expect("missing workload spec");
        assert_eq!(
            workload_spec.matches,
            CellMatches::simple(SimpleCellMatches::cgroup_contains(workload.to_string()))
        );

        let rest_spec = config
            .specs
            .iter()
            .find(|spec| spec.name == "rest")
            .expect("missing rest spec");
        assert_eq!(
            rest_spec.matches,
            CellMatches::simple(SimpleCellMatches::default())
        );
    }

    #[test]
    fn mem_extract_clusters_numeric_suffix_comms_for_dominance() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "mcrpxy-webNR1", 0, 4);
        push_samples(&mut groups, allotment, "mcrpxy-webNR2", 0, 4);
        push_samples(&mut groups, allotment, "beta", 0, 92);

        let group_names = vec![allotment.to_string()];
        let config = generate_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        let merged = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "mcrpxy-webNR")
            .expect("missing merged numeric-suffix comm subcell");

        assert_eq!(
            merged.matches,
            CellMatches::complex(vec![vec![CellMatch::CommPrefix(
                "mcrpxy-webNR".to_string()
            )]])
        );
        assert!(allotment_spec
            .subcells
            .iter()
            .all(|spec| spec.name != "mcrpxy-webNR1" && spec.name != "mcrpxy-webNR2"));
    }

    #[test]
    fn mem_extract_splits_merged_numeric_suffix_comm_by_hint_with_flag() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "mcrpxy-webNR1", 0, 3);
        push_samples(&mut groups, allotment, "mcrpxy-webNR1", 7, 1);
        push_samples(&mut groups, allotment, "mcrpxy-webNR2", 7, 3);
        push_samples(&mut groups, allotment, "mcrpxy-webNR2", 9, 1);
        push_samples(&mut groups, allotment, "beta", 0, 92);

        let group_names = vec![allotment.to_string()];
        let config = generate_config(&groups, &group_names, workload, "allotment-regex", true);

        let allotment_spec = &config.specs[0];
        let merged_hint_0 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "mcrpxy-webNR@hint=0")
            .expect("missing merged numeric-suffix hint=0 subcell");
        let merged_hint_7 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "mcrpxy-webNR@hint=7")
            .expect("missing merged numeric-suffix hint=7 subcell");
        let merged_hint_9 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "mcrpxy-webNR@hint=9")
            .expect("missing merged numeric-suffix hint=9 subcell");
        assert_eq!(
            merged_hint_0.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("mcrpxy-webNR".to_string()),
                CellMatch::Hint(0),
            ]])
        );
        assert_eq!(
            merged_hint_7.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("mcrpxy-webNR".to_string()),
                CellMatch::Hint(7),
            ]])
        );
        assert_eq!(
            merged_hint_9.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("mcrpxy-webNR".to_string()),
                CellMatch::Hint(9),
            ]])
        );
    }

    #[test]
    fn mem_extract_summary_groups_numeric_suffix_comms_and_reports_hints() {
        let samples = vec![
            sample("mcrpxy-webNR1", "cg", 0),
            sample("mcrpxy-webNR2", "cg", 7),
            sample("mcrpxy-webNR3", "cg", 7),
        ];
        let sample_refs: Vec<_> = samples.iter().collect();
        let summary = summarize_comm_groups(&sample_refs);

        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].name, "mcrpxy-webNR");
        assert_eq!(summary[0].count, 3);
        assert!(summary[0].aggregated_numeric_suffixes);
        assert_eq!(summary[0].hint_counts, vec![(7, 2), (0, 1)]);
        assert_eq!(
            summary[0].concrete_counts,
            vec![
                ("mcrpxy-webNR1".to_string(), 1),
                ("mcrpxy-webNR2".to_string(), 1),
                ("mcrpxy-webNR3".to_string(), 1),
            ]
        );
    }
}
