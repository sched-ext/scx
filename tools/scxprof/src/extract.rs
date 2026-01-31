// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::process::PerfScriptRecord;
use anyhow::{Context as _, Result};
use clap::Parser;
use regex::Regex;
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
        println!("\n{}: {} samples ({:.2}%)", group_name, self.total, group_pct);

        let mut counts: Vec<_> = self.comm_counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));

        for (comm, count) in counts {
            let pct = (*count as f64 / self.total as f64) * 100.0;
            println!("  {}: {} ({:.2}%)", comm, count, pct);
        }
    }
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

    println!("Total samples: {}", global_total);

    let mut group_names: Vec<_> = groups.keys().cloned().collect();
    group_names.sort_by(|a, b| {
        let order = |s: &str| -> u8 {
            if s == "rest" { 2 }
            else if s == workload_cgroup { 1 }
            else { 0 }
        };
        order(a).cmp(&order(b)).then_with(|| a.cmp(b))
    });

    for name in group_names {
        if let Some(stats) = groups.get(&name) {
            stats.print(&name, global_total);
        }
    }

    Ok(())
}
