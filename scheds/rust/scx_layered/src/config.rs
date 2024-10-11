// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::fs;
use std::io::Read;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::LayerGrowthAlgo;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LayerConfig {
    pub specs: Vec<LayerSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerSpec {
    pub name: String,
    pub comment: Option<String>,
    pub matches: Vec<Vec<LayerMatch>>,
    pub kind: LayerKind,
}

impl LayerSpec {
    pub fn parse(input: &str) -> Result<Vec<Self>> {
        let config: LayerConfig = if input.starts_with("f:") || input.starts_with("file:") {
            let mut f = fs::OpenOptions::new()
                .read(true)
                .open(input.split_once(':').unwrap().1)?;
            let mut content = String::new();
            f.read_to_string(&mut content)?;
            serde_json::from_str(&content)?
        } else {
            serde_json::from_str(input)?
        };
        Ok(config.specs)
    }

    pub fn nodes(&self) -> Vec<usize> {
        match &self.kind {
            LayerKind::Confined { nodes, .. }
            | LayerKind::Open { nodes, .. }
            | LayerKind::Grouped { nodes, .. } => nodes.clone(),
        }
    }

    pub fn llcs(&self) -> Vec<usize> {
        match &self.kind {
            LayerKind::Confined { llcs, .. }
            | LayerKind::Open { llcs, .. }
            | LayerKind::Grouped { llcs, .. } => llcs.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerMatch {
    CgroupPrefix(String),
    CommPrefix(String),
    PcommPrefix(String),
    NiceAbove(i32),
    NiceBelow(i32),
    NiceEquals(i32),
    UIDEquals(u32),
    GIDEquals(u32),
    PIDEquals(u32),
    PPIDEquals(u32),
    TGIDEquals(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerKind {
    Confined {
        util_range: (f64, f64),
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,
        #[serde(default)]
        min_exec_us: u64,
        #[serde(default)]
        yield_ignore: f64,
        #[serde(default)]
        slice_us: u64,
        #[serde(default)]
        preempt: bool,
        #[serde(default)]
        preempt_first: bool,
        #[serde(default)]
        exclusive: bool,
        #[serde(default)]
        weight: u32,
        #[serde(default)]
        idle_smt: bool,
        #[serde(default)]
        growth_algo: LayerGrowthAlgo,
        #[serde(default)]
        perf: u64,
        #[serde(default)]
        nodes: Vec<usize>,
        #[serde(default)]
        llcs: Vec<usize>,
    },
    Grouped {
        util_range: (f64, f64),
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,
        #[serde(default)]
        min_exec_us: u64,
        #[serde(default)]
        yield_ignore: f64,
        #[serde(default)]
        slice_us: u64,
        #[serde(default)]
        preempt: bool,
        #[serde(default)]
        preempt_first: bool,
        #[serde(default)]
        exclusive: bool,
        #[serde(default)]
        weight: u32,
        #[serde(default)]
        idle_smt: bool,
        #[serde(default)]
        growth_algo: LayerGrowthAlgo,
        #[serde(default)]
        perf: u64,
        #[serde(default)]
        nodes: Vec<usize>,
        #[serde(default)]
        llcs: Vec<usize>,
    },
    Open {
        #[serde(default)]
        min_exec_us: u64,
        #[serde(default)]
        yield_ignore: f64,
        #[serde(default)]
        slice_us: u64,
        #[serde(default)]
        preempt: bool,
        #[serde(default)]
        preempt_first: bool,
        #[serde(default)]
        exclusive: bool,
        #[serde(default)]
        weight: u32,
        #[serde(default)]
        idle_smt: bool,
        #[serde(default)]
        growth_algo: LayerGrowthAlgo,
        #[serde(default)]
        perf: u64,
        #[serde(default)]
        nodes: Vec<usize>,
        #[serde(default)]
        llcs: Vec<usize>,
    },
}
