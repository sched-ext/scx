// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::process::PerfScriptRecord;
use anyhow::{Context as _, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct ExtractOpts {
    /// Path to perf.jsonl file
    #[clap(short = 'f', long)]
    pub file: PathBuf,
}

pub fn cmd_extract(opts: ExtractOpts) -> Result<()> {
    let file = File::open(&opts.file).context("failed to open perf.jsonl")?;
    let reader = BufReader::new(file);

    let mut comm_counts: HashMap<String, u64> = HashMap::new();

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        let record: PerfScriptRecord =
            serde_json::from_str(&line).context("failed to parse record")?;
        *comm_counts.entry(record.comm).or_insert(0) += 1;
    }

    let mut counts: Vec<_> = comm_counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1));

    let total: u64 = counts.iter().map(|(_, c)| c).sum();

    for (comm, count) in counts {
        let pct = (count as f64 / total as f64) * 100.0;
        println!("{}: {} ({:.2}%)", comm, count, pct);
    }

    Ok(())
}
