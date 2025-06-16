// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use itertools::iproduct;
use log::debug;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::EnergyModel;
use scx_utils::Topology;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone)]
pub struct CpuId {
    // - *_adx: an absolute index within a system scope
    // - *_rdx: a relative index under a parent
    //
    // - node_adx: a NUMA domain within a system
    // - pd_adx: a performance domain (CPU frequency domain) within a system
    //   - llc_rdx: an LLC domain (CCX) under a NUMA domain
    //     - core_rdx: a core under a LLC domain
    //       - cpu_rdx: a CPU under a core
    pub node_adx: usize,
    pub pd_adx: usize,
    pub llc_rdx: usize,
    pub core_rdx: usize,
    pub cpu_rdx: usize,
    pub cpu_adx: usize,
    pub smt_level: usize,
    pub cache_size: usize,
    pub cpu_cap: usize,
    pub big_core: bool,
    pub turbo_core: bool,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ComputeDomainId {
    pub node_adx: usize,
    pub llc_rdx: usize,
    pub is_big: bool,
}

#[derive(Debug, Clone)]
pub struct ComputeDomain {
    pub cpdom_id: usize,
    pub cpdom_alt_id: Cell<usize>,
    pub cpu_ids: Vec<usize>,
    pub neighbor_map: RefCell<BTreeMap<usize, RefCell<Vec<usize>>>>,
}

#[derive(Debug)]
pub struct CpuOrder {
    pub all_cpus_mask: Cpumask,
    pub cpus_pf: Vec<CpuId>,
    pub cpus_ps: Vec<CpuId>,
    pub cpdom_map: BTreeMap<ComputeDomainId, ComputeDomain>,
    pub smt_enabled: bool,
    pub has_biglittle: bool,
}

impl fmt::Display for CpuOrder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for cpu_id in self.cpus_pf.iter() {
            write!(f, "\nCPU in performance: {:?}", cpu_id).ok();
        }
        for cpu_id in self.cpus_ps.iter() {
            write!(f, "\nCPU in powersave: {:?}", cpu_id).ok();
        }
        for (k, v) in self.cpdom_map.iter() {
            write!(f, "\nCPDOM: {:?} {:?}", k, v).ok();
        }
        write!(f, "SMT: {}", self.smt_enabled).ok();
        write!(f, "big/LITTLE: {}", self.has_biglittle).ok();
        Ok(())
    }
}

impl CpuOrder {
    /// Build a cpu preference order
    pub fn new() -> Result<CpuOrder> {
        let sys_topo = Topology::new().expect("Failed to build host topology");
        let sys_em = EnergyModel::new();
        debug!("{:#?}", sys_topo);
        debug!("{:#?}", sys_em);

        let cpus_pf = Self::build_cpu_order(&sys_topo, &sys_em, false).unwrap();
        let cpus_ps = Self::build_cpu_order(&sys_topo, &sys_em, true).unwrap();

        // Note that building compute domain is independent to CPU orer
        // so it is okay to use any cpus_*.
        let cpdom_map = Self::build_cpdom(&cpus_pf).unwrap();

        let has_biglittle = sys_topo.has_little_cores();
        Ok(CpuOrder {
            all_cpus_mask: sys_topo.span,
            cpus_pf,
            cpus_ps,
            cpdom_map,
            smt_enabled: sys_topo.smt_enabled,
            has_biglittle,
        })
    }

    /// Build a CPU preference order based on its optimization target
    fn build_cpu_order(
        sys_topo: &Topology,
        em: &Result<EnergyModel>,
        prefer_powersave: bool,
    ) -> Option<Vec<CpuId>> {
        let mut cpu_ids = Vec::new();

        // Build a vector of cpu ids.
        for (&node_adx, node) in sys_topo.nodes.iter() {
            for (llc_rdx, (_llc_adx, llc)) in node.llcs.iter().enumerate() {
                for (core_rdx, (_core_adx, core)) in llc.cores.iter().enumerate() {
                    for (cpu_rdx, (cpu_adx, cpu)) in core.cpus.iter().enumerate() {
                        let cpu_adx = *cpu_adx;
                        let pd_adx = Self::get_pd_id(em, cpu_adx, node_adx);
                        let cpu_id = CpuId {
                            node_adx,
                            pd_adx,
                            llc_rdx,
                            core_rdx,
                            cpu_rdx,
                            cpu_adx,
                            smt_level: cpu.smt_level,
                            cache_size: cpu.cache_size,
                            cpu_cap: cpu.cpu_capacity,
                            big_core: cpu.core_type != CoreType::Little,
                            turbo_core: cpu.core_type == CoreType::Big { turbo: true },
                        };
                        cpu_ids.push(RefCell::new(cpu_id));
                    }
                }
            }
        }

        // Convert a vector of RefCell to a vector of plain cpu_ids
        let mut cpu_ids2 = Vec::new();
        for cpu_id in cpu_ids.iter() {
            cpu_ids2.push(cpu_id.borrow().clone());
        }
        let mut cpu_ids = cpu_ids2;

        // Sort the cpu_ids
        let has_biglittle = sys_topo.has_little_cores();
        match (prefer_powersave, has_biglittle) {
            // 1. powersave,      no  big/little
            //     * within the same LLC domain
            //         - node_adx, llc_rdx,
            //     * prefer more capable CPU with higher capacity
            //       and larger cache
            //         - ^cpu_cap (chip binning), ^cache_size,
            //     * prefere the SMT core within the same performance domain
            //         - pd_adx, core_rdx, ^smt_level, cpu_rdx
            (true, false) => {
                cpu_ids.sort_by(|a, b| {
                    a.node_adx
                        .cmp(&b.node_adx)
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| b.cpu_cap.cmp(&a.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| b.smt_level.cmp(&a.smt_level))
                        .then_with(|| a.cpu_rdx.cmp(&b.cpu_rdx))
                });
            }
            // 2. powersave,      yes big/little
            //     * within the same LLC domain
            //         - node_adx, llc_rdx,
            //     * prefer energy-efficient LITTLE CPU with a larger cache
            //         - cpu_cap (big/little), ^cache_size,
            //     * prefere the SMT core within the same performance domain
            //         - pd_adx, core_rdx, ^smt_level, cpu_rdx
            (true, true) => {
                cpu_ids.sort_by(|a, b| {
                    a.node_adx
                        .cmp(&b.node_adx)
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| a.cpu_cap.cmp(&b.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| b.smt_level.cmp(&a.smt_level))
                        .then_with(|| a.cpu_rdx.cmp(&b.cpu_rdx))
                });
            }
            // 3. performance,    no  big/little
            // 4. performance,    yes big/little
            //     * prefer the non-SMT core
            //         - cpu_rdx,
            //     * fill the same LLC domain first
            //         - node_adx, llc_rdx,
            //     * prefer more capable CPU with higher capacity
            //       (chip binning or big/little) and larger cache
            //         - ^cpu_cap, ^cache_size, smt_level
            //     * within the same power domain
            //         - pd_adx, core_rdx
            _ => {
                cpu_ids.sort_by(|a, b| {
                    a.cpu_rdx
                        .cmp(&b.cpu_rdx)
                        .then_with(|| a.node_adx.cmp(&b.node_adx))
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| b.cpu_cap.cmp(&a.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.smt_level.cmp(&b.smt_level))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                });
            }
        }

        Some(cpu_ids)
    }

    /// Get the performance domain (i.e., CPU frequency domain) ID for a CPU.
    /// If the energy model is not available, use NUMA node ID instead.
    fn get_pd_id(em: &Result<EnergyModel>, cpu_adx: usize, node_adx: usize) -> usize {
        match em {
            Ok(em) => em.get_pd(cpu_adx).unwrap().id,
            Err(_) => node_adx,
        }
    }

    /// Build a list of compute domains
    fn build_cpdom(cpu_ids: &Vec<CpuId>) -> Option<BTreeMap<ComputeDomainId, ComputeDomain>> {
        // Creat a compute domain map, where a compute domain is a CPUs that
        // are under the same node and LLC and have the same core type.
        let mut cpdom_id = 0;
        let mut cpdom_map: BTreeMap<ComputeDomainId, ComputeDomain> = BTreeMap::new();
        let mut cpdom_types: BTreeMap<usize, bool> = BTreeMap::new();
        for cpu_id in cpu_ids.iter() {
            let key = ComputeDomainId {
                node_adx: cpu_id.node_adx,
                llc_rdx: cpu_id.llc_rdx,
                is_big: cpu_id.big_core,
            };
            let value = cpdom_map.entry(key.clone()).or_insert_with(|| {
                let val = ComputeDomain {
                    cpdom_id,
                    cpdom_alt_id: Cell::new(cpdom_id),
                    cpu_ids: Vec::new(),
                    neighbor_map: RefCell::new(BTreeMap::new()),
                };
                cpdom_types.insert(cpdom_id, key.is_big);

                cpdom_id += 1;
                val
            });
            value.cpu_ids.push(cpu_id.cpu_adx);
        }

        // Build a neighbor map for each compute domain, where neighbors are
        // ordered by core type, node, and LLC.
        for ((from_k, from_v), (to_k, to_v)) in iproduct!(cpdom_map.iter(), cpdom_map.iter()) {
            if from_k == to_k {
                continue;
            }

            let d = Self::dist(from_k, to_k);
            let mut map = from_v.neighbor_map.borrow_mut();
            match map.get(&d) {
                Some(v) => {
                    v.borrow_mut().push(to_v.cpdom_id);
                }
                None => {
                    map.insert(d, RefCell::new(vec![to_v.cpdom_id]));
                }
            }
        }

        // Fill up cpdom_alt_id for each compute domain.
        for (k, v) in cpdom_map.iter() {
            let mut key = k.clone();
            key.is_big = !k.is_big;

            if let Some(alt_v) = cpdom_map.get(&key) {
                // First, try to find an alternative domain
                // under the same node/LLC.
                v.cpdom_alt_id.set(alt_v.cpdom_id);
            } else {
                // If there is no alternative domain in the same node/LLC,
                // choose the closest one.
                //
                // Note that currently, the idle CPU selection (pick_idle_cpu)
                // is not optimized for this kind of architecture, where big
                // and LITTLE cores are in different node/LLCs.
                'outer: for (_dist, ncpdoms) in v.neighbor_map.borrow().iter() {
                    for ncpdom_id in ncpdoms.borrow().iter() {
                        if let Some(is_big) = cpdom_types.get(ncpdom_id) {
                            if *is_big == key.is_big {
                                v.cpdom_alt_id.set(*ncpdom_id);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        Some(cpdom_map)
    }

    /// Calculate distance from two compute domains
    fn dist(from: &ComputeDomainId, to: &ComputeDomainId) -> usize {
        let mut d = 0;
        // code type > numa node > llc
        if from.is_big != to.is_big {
            d += 3;
        }
        if from.node_adx != to.node_adx {
            d += 2;
        } else {
            if from.llc_rdx != to.llc_rdx {
                d += 1;
            }
        }
        d
    }
}
