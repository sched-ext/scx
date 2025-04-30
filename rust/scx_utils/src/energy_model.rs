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
use crate::misc::read_from_file;
use crate::Cpumask;
use anyhow::bail;
use anyhow::Result;
use glob::glob;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct PerfState {
    pub cost: usize,
    pub frequency: usize,
    pub inefficient: usize,
    pub performance: usize,
    pub power: usize,
}

#[derive(Debug)]
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
            let pd = PerfDomain::new(pd_id, pd_path).unwrap();
            perf_doms.insert(pd.id, pd.into());
        }

        Ok(EnergyModel { perf_doms })
    }

    pub fn get_pd(&self, cpu_id: usize) -> Option<&PerfDomain> {
        for (_, pd) in self.perf_doms.iter() {
            if pd.span.test_cpu(cpu_id) {
                return Some(&pd);
            }
        }
        None
    }
}

impl PerfDomain {
    /// Build a PerfDomain
    pub fn new(id: usize, root: String) -> Result<PerfDomain> {
        let mut perf_table = BTreeMap::new();
        let cpulist = std::fs::read_to_string(root.clone() + "/cpus")?;
        let span = Cpumask::from_cpulist(&cpulist)?;

        for ps_path in get_ps_paths(root).unwrap() {
            let ps = PerfState::new(ps_path).unwrap();
            perf_table.insert(ps.performance, ps.into());
        }

        Ok(PerfDomain {
            id,
            span,
            perf_table,
        })
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

impl fmt::Display for EnergyModel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (_, pd) in self.perf_doms.iter() {
            writeln!(f, "{:#}", pd)?;
        }
        Ok(())
    }
}

impl fmt::Display for PerfDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "# perf domain: {:#}, cpus: {:#}", self.id, self.span)?;
        writeln!(f, "cost, frequency, inefficient, performance, power")?;
        for (_, ps) in self.perf_table.iter() {
            writeln!(f, "{:#}", ps)?;
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
        let ps_str = ps_path.into_os_string().into_string().unwrap();
        ps_vec.push(ps_str);
    }

    Ok(ps_vec)
}

fn get_pd_paths() -> Result<Vec<(usize, String)>> {
    let prefix = get_em_root().unwrap() + "/cpu";
    let pd_paths = glob(&(prefix.clone() + "[0-9]*"))?;

    let mut pd_vec = vec![];
    for pd_path in pd_paths.filter_map(Result::ok) {
        let pd_str = pd_path.into_os_string().into_string().unwrap();
        let pd_id: usize = pd_str[prefix.len()..].parse().unwrap();
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
    let root = compat::debugfs_mount().unwrap().join("energy_model");
    Ok(root.display().to_string())
}
