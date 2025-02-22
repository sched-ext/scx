// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::fs;
use std::io::Read;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::bpf_intf;
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

    pub fn nodes(&self) -> &Vec<usize> {
        &self.kind.common().nodes
    }

    pub fn llcs(&self) -> &Vec<usize> {
        &self.kind.common().llcs
    }

    pub fn nodes_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().nodes
    }

    pub fn llcs_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().llcs
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
    NSPIDEquals(u64, u32),
    NSEquals(u32),
    CmdJoin(String),
    IsGroupLeader(bool),
    UsedGpuTid(bool),
    UsedGpuPid(bool),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerCommon {
    #[serde(default)]
    pub min_exec_us: u64,
    #[serde(default)]
    pub yield_ignore: f64,
    #[serde(default)]
    pub slice_us: u64,
    #[serde(default)]
    pub fifo: bool,
    #[serde(default)]
    pub preempt: bool,
    #[serde(default)]
    pub preempt_first: bool,
    #[serde(default)]
    pub exclusive: bool,
    #[serde(default)]
    pub allow_node_aligned: bool,
    #[serde(default)]
    pub weight: u32,
    #[serde(default)]
    pub disallow_open_after_us: Option<u64>,
    #[serde(default)]
    pub disallow_preempt_after_us: Option<u64>,
    #[serde(default)]
    pub xllc_mig_min_us: f64,
    #[serde(default, skip_serializing)]
    pub idle_smt: Option<bool>,
    #[serde(default)]
    pub growth_algo: LayerGrowthAlgo,
    #[serde(default)]
    pub perf: u64,
    #[serde(default)]
    pub nodes: Vec<usize>,
    #[serde(default)]
    pub llcs: Vec<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerKind {
    Confined {
        util_range: (f64, f64),
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        #[serde(flatten)]
        common: LayerCommon,
    },
    Grouped {
        util_range: (f64, f64),
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        #[serde(flatten)]
        common: LayerCommon,
    },
    Open {
        #[serde(flatten)]
        common: LayerCommon,
    },
}

impl LayerKind {
    pub fn as_bpf_enum(&self) -> i32 {
        match self {
            LayerKind::Confined { .. } => bpf_intf::layer_kind_LAYER_KIND_CONFINED as i32,
            LayerKind::Grouped { .. } => bpf_intf::layer_kind_LAYER_KIND_GROUPED as i32,
            LayerKind::Open { .. } => bpf_intf::layer_kind_LAYER_KIND_OPEN as i32,
        }
    }

    pub fn common(&self) -> &LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn common_mut(&mut self) -> &mut LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn util_range(&self) -> Option<(f64, f64)> {
        match self {
            LayerKind::Confined { util_range, .. } | LayerKind::Grouped { util_range, .. } => {
                Some(*util_range)
            }
            _ => None,
        }
    }
}
