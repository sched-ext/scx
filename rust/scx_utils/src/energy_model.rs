// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Energy Model
//!
//! A crate that allows schedulers to inspect and model the host's energy model,
//! which is loaded from debugfs.

use crate::compat;
use crate::compat::ROOT_PREFIX;
use crate::misc::read_from_file;
use crate::Cpumask;
use anyhow::bail;
use anyhow::Result;
use glob::glob;
use num::clamp;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Eq, Hash, Ord, PartialOrd)]
pub struct PerfState {
    pub cost: usize,
    pub frequency: usize,
    pub inefficient: usize,
    pub performance: usize,
    pub power: usize,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialOrd)]
pub struct PerfDomain {
    /// Monotonically increasing unique id.
    pub id: usize,
    /// Cpumask of all CPUs in this performance domain.
    pub span: Cpumask,
    /// Table of performance states indexed by performance.
    pub perf_table: BTreeMap<usize, Arc<PerfState>>,
}

#[derive(Debug)]
pub struct EnergyModel {
    /// Performance domains indexed by domain id
    pub perf_doms: BTreeMap<usize, Arc<PerfDomain>>,
}

impl EnergyModel {
    pub fn has_energy_model() -> bool {
        get_pd_paths().is_ok()
    }

    /// Build a complete EnergyModel
    pub fn new() -> Result<EnergyModel> {
        let mut perf_doms = BTreeMap::new();
        let pd_paths = match get_pd_paths() {
            Ok(pd_paths) => pd_paths,
            Err(_) => {
                bail!("Fail to locate the energy model directory");
            }
        };

        for (pd_id, pd_path) in pd_paths {
            let pd = PerfDomain::new(pd_id, pd_path)?;
            perf_doms.insert(pd.id, pd.into());
        }

        Ok(EnergyModel { perf_doms })
    }

    pub fn get_pd_by_cpu_id(&self, cpu_id: usize) -> Option<&PerfDomain> {
        self.perf_doms
            .values()
            .find(|&pd| pd.span.test_cpu(cpu_id))
            .map(|c| c as _)
    }

    pub fn perf_total(&self) -> usize {
        let mut total = 0;

        for (_, pd) in self.perf_doms.iter() {
            total += pd.perf_total();
        }

        total
    }
}

impl PerfDomain {
    /// Build a PerfDomain
    pub fn new(id: usize, root: String) -> Result<PerfDomain> {
        let mut perf_table = BTreeMap::new();
        let cpulist = std::fs::read_to_string(root.clone() + "/cpus")?;
        let span = Cpumask::from_cpulist(&cpulist)?;

        for ps_path in get_ps_paths(root)? {
            let ps = PerfState::new(ps_path)?;
            perf_table.insert(ps.performance, ps.into());
        }

        Ok(PerfDomain {
            id,
            span,
            perf_table,
        })
    }

    /// Lookup a performance state by a given CPU utilization.
    /// @util is in %, ranging [0, 100].
    pub fn select_perf_state(&self, util: f32) -> Option<&Arc<PerfState>> {
        let util = clamp(util, 0.0, 100.0);
        let (perf_max, _) = self.perf_table.last_key_value()?;
        let perf_max = *perf_max as f32;
        let req_perf = (perf_max * (util / 100.0)) as usize;
        for (perf, ps) in self.perf_table.iter() {
            if *perf >= req_perf {
                return Some(ps);
            }
        }
        None
    }

    pub fn perf_total(&self) -> usize {
        let (_, ps) = self.perf_table.last_key_value().unwrap();
        ps.performance * self.span.weight()
    }
}

impl PartialEq for PerfDomain {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.span == other.span && self.perf_table == other.perf_table
    }
}

impl PerfState {
    /// Build a PerfState
    pub fn new(root: String) -> Result<PerfState> {
        let cost = read_from_file(Path::new(&(root.clone() + "/cost")))?;
        let frequency = read_from_file(Path::new(&(root.clone() + "/frequency")))?;
        let inefficient = read_from_file(Path::new(&(root.clone() + "/inefficient")))?;
        let performance = read_from_file(Path::new(&(root.clone() + "/performance")))?;
        let power = read_from_file(Path::new(&(root.clone() + "/power")))?;

        Ok(PerfState {
            cost,
            frequency,
            inefficient,
            performance,
            power,
        })
    }
}

impl PartialEq for PerfState {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
            && self.frequency == other.frequency
            && self.performance == other.performance
            && self.power == other.power
    }
}

impl fmt::Display for EnergyModel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (_, pd) in self.perf_doms.iter() {
            writeln!(f, "{pd:#}")?;
        }
        Ok(())
    }
}

impl fmt::Display for PerfDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "# perf domain: {:#}, cpus: {:#}", self.id, self.span)?;
        writeln!(f, "cost, frequency, inefficient, performance, power")?;
        for (_, ps) in self.perf_table.iter() {
            writeln!(f, "{ps:#}")?;
        }
        Ok(())
    }
}

impl fmt::Display for PerfState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}, {}, {}, {}, {}",
            self.cost, self.frequency, self.inefficient, self.performance, self.power
        )?;
        Ok(())
    }
}

/*********************************************************
 * Helper structs/functions for creating the EnergyModel *
 *********************************************************/
fn get_ps_paths(root: String) -> Result<Vec<String>> {
    let ps_paths = glob(&(root.clone() + "/ps:[0-9]*"))?;
    let mut ps_vec = vec![];
    for ps_path in ps_paths.filter_map(Result::ok) {
        let ps_str = ps_path.to_string_lossy().into_owned();
        ps_vec.push(ps_str);
    }

    Ok(ps_vec)
}

fn get_pd_paths() -> Result<Vec<(usize, String)>> {
    let prefix = get_em_root()? + "/cpu";
    let pd_paths = glob(&(prefix.clone() + "[0-9]*"))?;

    let mut pd_vec = vec![];
    for pd_path in pd_paths.filter_map(Result::ok) {
        let pd_str = pd_path.to_string_lossy().into_owned();
        let pd_id: usize = pd_str[prefix.len()..].parse()?;
        pd_vec.push((pd_id, pd_str));
    }
    if pd_vec.is_empty() {
        bail!("There is no performance domain.");
    }
    pd_vec.sort();

    let mut pd_vec2 = vec![];
    for (id, (_, pd_str)) in pd_vec.into_iter().enumerate() {
        pd_vec2.push((id, pd_str));
    }

    Ok(pd_vec2)
}

fn get_em_root() -> Result<String> {
    if ROOT_PREFIX.is_empty() {
        let root = compat::debugfs_mount()?.join("energy_model");
        Ok(root.display().to_string())
    } else {
        let root = format!("{}/sys/kernel/debug/energy_model", *ROOT_PREFIX);
        Ok(root)
    }
}
