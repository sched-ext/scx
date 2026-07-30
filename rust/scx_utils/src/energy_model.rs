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

/// A set of performance domains sharing an identical performance table.
///
/// How many CPUs a performance domain covers is processor-specific: it can be a
/// cluster, a core, or a single CPU. Intel hybrid processors, for instance, have
/// one performance domain per CPU, so all the P-cores (or all the E-cores) are
/// represented by separate performance domains even though they are identical.
/// Such domains are interchangeable, so a search for the cheapest set of CPUs
/// can consider how many CPUs to take from an equivalence performance domain
/// rather than which performance domains to activate, reducing the search space
/// from `2^nr_perf_doms` to `prod(weight_i + 1)`.
#[derive(Debug, Clone)]
pub struct EqPerfDomain {
    /// Monotonically increasing unique id.
    pub id: usize,
    /// Member performance domains in ascending domain id order.
    pub perf_doms: Vec<Arc<PerfDomain>>,
    /// Cpumask of all CPUs in this equivalence performance domain.
    pub span: Cpumask,
    /// Table of performance states indexed by performance, shared by all
    /// member performance domains.
    pub perf_table: BTreeMap<usize, Arc<PerfState>>,
}

#[derive(Debug)]
pub struct EnergyModel {
    /// Performance domains indexed by domain id
    pub perf_doms: BTreeMap<usize, Arc<PerfDomain>>,
    /// Equivalence performance domains indexed by equivalence domain id
    pub eq_perf_doms: BTreeMap<usize, Arc<EqPerfDomain>>,
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
        let eq_perf_doms = Self::group_perf_doms(&perf_doms);

        Ok(EnergyModel {
            perf_doms,
            eq_perf_doms,
        })
    }

    /// Group performance domains sharing an identical performance table into
    /// equivalence performance domains. Since @perf_doms is visited in
    /// ascending domain id order, both the members of an equivalence
    /// performance domain and the equivalence performance domains themselves
    /// are ordered by performance domain id.
    fn group_perf_doms(
        perf_doms: &BTreeMap<usize, Arc<PerfDomain>>,
    ) -> BTreeMap<usize, Arc<EqPerfDomain>> {
        let mut eq_perf_doms: Vec<EqPerfDomain> = vec![];

        for pd in perf_doms.values() {
            match eq_perf_doms
                .iter_mut()
                .find(|eq_pd| eq_pd.perf_table == pd.perf_table)
            {
                Some(eq_pd) => {
                    eq_pd.span = eq_pd.span.or(&pd.span);
                    eq_pd.perf_doms.push(pd.clone());
                }
                None => {
                    eq_perf_doms.push(EqPerfDomain {
                        id: eq_perf_doms.len(),
                        perf_doms: vec![pd.clone()],
                        span: pd.span.clone(),
                        perf_table: pd.perf_table.clone(),
                    });
                }
            }
        }

        eq_perf_doms
            .into_iter()
            .map(|eq_pd| (eq_pd.id, eq_pd.into()))
            .collect()
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
        for (_, eq_pd) in self.eq_perf_doms.iter() {
            writeln!(f, "{eq_pd:#}")?;
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

impl fmt::Display for EqPerfDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pd_ids: Vec<String> = self.perf_doms.iter().map(|pd| pd.id.to_string()).collect();
        writeln!(
            f,
            "# eq perf domain: {:#}, cpus: {:#}, perf domains: {}",
            self.id,
            self.span,
            pd_ids.join(",")
        )?;
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

/// Tests for grouping performance domains into equivalence performance
/// domains. The performance domains are built directly instead of read from
/// debugfs, so the topologies of interest can be exercised on any host.
#[cfg(test)]
mod tests {
    use super::*;

    fn perf_table(states: &[(usize, usize)]) -> BTreeMap<usize, Arc<PerfState>> {
        states
            .iter()
            .map(|&(performance, power)| {
                let ps = PerfState {
                    cost: performance,
                    frequency: performance,
                    inefficient: 0,
                    performance,
                    power,
                };
                (performance, ps.into())
            })
            .collect()
    }

    /// Build a performance domain covering a single CPU (@id), as on an Intel
    /// hybrid processor.
    fn perf_dom(id: usize, perf_table: BTreeMap<usize, Arc<PerfState>>) -> Arc<PerfDomain> {
        PerfDomain {
            id,
            span: Cpumask::from_vec(vec![1u64 << id]),
            perf_table,
        }
        .into()
    }

    /// A 28-thread hybrid CPU (8 P-cores, 16 E-cores, and 4 LP-E-cores) with
    /// one performance domain per CPU thread, as reported in
    /// <https://github.com/sched-ext/scx/issues/3340>. It collapses into three
    /// equivalence performance domains.
    #[test]
    fn test_group_hybrid_perf_doms() {
        let p_core = perf_table(&[(100, 50)]);
        let e_core = perf_table(&[(60, 20)]);
        let lpe_core = perf_table(&[(30, 5)]);

        let mut perf_doms = BTreeMap::new();
        for id in 0..28 {
            let table = if id < 8 {
                p_core.clone()
            } else if id < 24 {
                e_core.clone()
            } else {
                lpe_core.clone()
            };
            perf_doms.insert(id, perf_dom(id, table));
        }

        let eq_perf_doms = EnergyModel::group_perf_doms(&perf_doms);

        let weights: Vec<usize> = eq_perf_doms.values().map(|e| e.span.weight()).collect();
        assert_eq!(weights, vec![8, 16, 4]);

        for (&id, eq_pd) in eq_perf_doms.iter() {
            assert_eq!(eq_pd.id, id);
            assert_eq!(eq_pd.perf_doms.len(), eq_pd.span.weight());

            let member_ids: Vec<usize> = eq_pd.perf_doms.iter().map(|pd| pd.id).collect();
            assert!(member_ids.windows(2).all(|ids| ids[0] < ids[1]));

            for pd in eq_pd.perf_doms.iter() {
                assert_eq!(pd.perf_table, eq_pd.perf_table);
                assert!(eq_pd.span.test_cpu(pd.id));
            }
        }
    }

    /// Every performance domain has a distinct performance table, as per-core
    /// binning could produce, so no grouping is possible.
    #[test]
    fn test_group_distinct_perf_doms() {
        let mut perf_doms = BTreeMap::new();
        for id in 0..24 {
            perf_doms.insert(id, perf_dom(id, perf_table(&[(id + 1, id + 1)])));
        }

        let eq_perf_doms = EnergyModel::group_perf_doms(&perf_doms);

        assert_eq!(eq_perf_doms.len(), 24);
        for eq_pd in eq_perf_doms.values() {
            assert_eq!(eq_pd.perf_doms.len(), 1);
            assert_eq!(eq_pd.span.weight(), 1);
        }
    }

    /// All the performance domains share one performance table, so they
    /// collapse into a single equivalence performance domain.
    #[test]
    fn test_group_uniform_perf_doms() {
        let table = perf_table(&[(100, 50)]);
        let mut perf_doms = BTreeMap::new();
        for id in 0..8 {
            perf_doms.insert(id, perf_dom(id, table.clone()));
        }

        let eq_perf_doms = EnergyModel::group_perf_doms(&perf_doms);

        assert_eq!(eq_perf_doms.len(), 1);
        let eq_pd = eq_perf_doms.get(&0).unwrap();
        assert_eq!(eq_pd.perf_doms.len(), 8);
        assert_eq!(eq_pd.span.weight(), 8);
    }
}
