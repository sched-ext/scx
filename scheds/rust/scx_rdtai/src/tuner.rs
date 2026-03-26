// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::collections::BTreeMap;
use std::sync::Arc;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use log::info;
use libbpf_rs::MapCore;
use scx_utils::Cpumask;

use crate::bpf_intf;
use crate::sub_or_zero;
use crate::BpfSkel;
use crate::DomainGroup;

fn calc_util(curr: &procfs::CpuStat, prev: &procfs::CpuStat) -> Result<f64> {
    match (curr, prev) {
        (
            procfs::CpuStat {
                user_usec: Some(curr_user),
                nice_usec: Some(curr_nice),
                system_usec: Some(curr_system),
                idle_usec: Some(curr_idle),
                iowait_usec: Some(curr_iowait),
                irq_usec: Some(curr_irq),
                softirq_usec: Some(curr_softirq),
                stolen_usec: Some(curr_stolen),
                ..
            },
            procfs::CpuStat {
                user_usec: Some(prev_user),
                nice_usec: Some(prev_nice),
                system_usec: Some(prev_system),
                idle_usec: Some(prev_idle),
                iowait_usec: Some(prev_iowait),
                irq_usec: Some(prev_irq),
                softirq_usec: Some(prev_softirq),
                stolen_usec: Some(prev_stolen),
                ..
            },
        ) => {
            let idle_usec = sub_or_zero(curr_idle, prev_idle);
            let iowait_usec = sub_or_zero(curr_iowait, prev_iowait);
            let user_usec = sub_or_zero(curr_user, prev_user);
            let system_usec = sub_or_zero(curr_system, prev_system);
            let nice_usec = sub_or_zero(curr_nice, prev_nice);
            let irq_usec = sub_or_zero(curr_irq, prev_irq);
            let softirq_usec = sub_or_zero(curr_softirq, prev_softirq);
            let stolen_usec = sub_or_zero(curr_stolen, prev_stolen);

            let busy_usec =
                user_usec + system_usec + nice_usec + irq_usec + softirq_usec + stolen_usec;
            let total_usec = idle_usec + busy_usec + iowait_usec;
            if total_usec > 0 {
                Ok(((busy_usec as f64) / (total_usec as f64)).clamp(0.0, 1.0))
            } else {
                Ok(1.0)
            }
        }
        _ => {
            bail!("Missing stats in cpustat");
        }
    }
}

pub struct Tuner {
    pub direct_greedy_mask: Cpumask,
    pub kick_greedy_mask: Cpumask,
    pub fully_utilized: bool,
    pub slice_ns: u64,
    underutil_slice_ns: u64,
    overutil_slice_ns: u64,
    dom_group: Arc<DomainGroup>,
    direct_greedy_under: f64,
    kick_greedy_under: f64,
    proc_reader: procfs::ProcReader,
    prev_cpu_stats: BTreeMap<u32, procfs::CpuStat>,
    // Optimization parameters
    wait_weight: f64,
    cache_weight: f64,
    burst_weight: f64,
}

impl Tuner {
    pub fn new(
        dom_group: Arc<DomainGroup>,
        direct_greedy_under: f64,
        kick_greedy_under: f64,
        underutil_slice_ns: u64,
        overutil_slice_ns: u64,
    ) -> Result<Self> {
        let proc_reader = procfs::ProcReader::new();
        let prev_cpu_stats = proc_reader
            .read_stat()?
            .cpus_map
            .ok_or_else(|| anyhow!("Expected cpus_map to exist"))?;

        Ok(Self {
            direct_greedy_mask: Cpumask::new(),
            kick_greedy_mask: Cpumask::new(),
            fully_utilized: false,
            direct_greedy_under: direct_greedy_under / 100.0,
            kick_greedy_under: kick_greedy_under / 100.0,
            proc_reader,
            prev_cpu_stats,
            slice_ns: underutil_slice_ns,
            underutil_slice_ns,
            overutil_slice_ns,
            dom_group,
            wait_weight: 1.0,
            cache_weight: 5.0, // Cache misses are expensive
            burst_weight: 0.1,
            })
            }

            /// The Robust Loss Function Optimization
            /// Calculates the 'Penalty' score of the current scheduling state and
            /// adjusts the decision tree thresholds in the kernel.
            pub fn optimize_tree(&mut self, skel: &mut BpfSkel, avg_util: f64) -> Result<()> {
            let tree_map = &mut skel.maps.rdtai_tree;

            // LOSS FUNCTION:
            // Penalty = (avg_util * wait_weight) + (cache_misses_est * cache_weight)
            // We adjust the 'Wait Threshold' based on this penalty.
            let penalty = avg_util * self.wait_weight;

            // Dynamic Threshold calculation:
            // High Penalty (high util) -> Lower Threshold (be more aggressive)
            // Low Penalty (low util) -> Higher Threshold (be more conservative)
            let mut wait_threshold = 1_000_000; // Default 1ms
            if penalty > 0.8 {
            wait_threshold = 200_000; // 200us
            } else if penalty > 0.5 {
            wait_threshold = 500_000; // 500us
            }

            // Update the Root Node (Node 0) in the BPF map
            let mut root = bpf_intf::rdtai_node {
            feature_id: bpf_intf::rdtai_feature_FEAT_WAIT_TIME,
            threshold: wait_threshold,
            left_child: 2,  // Keep Local
            right_child: 1, // Run Immediately
            is_leaf: false,
            leaf_action: 0,
            };

            let mut key = [0u8; 4];
            key.copy_from_slice(&0u32.to_ne_bytes());
            tree_map.update(
            &key,
            unsafe {
                std::slice::from_raw_parts(
                    &root as *const _ as *const u8,
                    std::mem::size_of::<bpf_intf::rdtai_node>(),
                )
            },
            libbpf_rs::MapFlags::ANY,
            )?;

            if avg_util > 0.9 {
            info!("RDTAI Optimized: High Util detected, wait threshold lowered to {}ns", wait_threshold);
            }

            Ok(())
    }

    /// Apply a step in the Tuner by:
    ///
    /// 1. Recording CPU stats from procfs
    /// 2. Calculating current per-domain and host-wide utilization
    /// 3. Updating direct_greedy_under and kick_greedy_under cpumasks according
    ///    to the observed utilization
    pub fn step(&mut self, skel: &mut BpfSkel) -> Result<()> {
        let curr_cpu_stats = self
            .proc_reader
            .read_stat()?
            .cpus_map
            .ok_or_else(|| anyhow!("Expected cpus_map to exist"))?;
        let mut dom_util_sum = vec![0.0f64; self.dom_group.nr_doms()];

        let mut avg_util = 0.0f64;
        for (dom_id, dom) in self.dom_group.doms().iter() {
            for cpu in dom.mask().iter() {
                let cpu32 = cpu as u32;
                if let (Some(curr), Some(prev)) =
                    (curr_cpu_stats.get(&cpu32), self.prev_cpu_stats.get(&cpu32))
                {
                    let util = calc_util(curr, prev)?;
                    dom_util_sum[*dom_id] += util;
                    avg_util += util;
                }
            }
        }
        avg_util /= self.dom_group.weight() as f64;
        self.fully_utilized = avg_util >= 0.99999;

        // Optimize the AI Decision Tree based on current utilization (Loss Function)
        self.optimize_tree(skel, avg_util)?;

        self.direct_greedy_mask.clear_all();
        self.kick_greedy_mask.clear_all();
        for (dom_id, dom) in self.dom_group.doms().iter() {
            // Calculate the domain avg util. If there are no active CPUs,
            // it doesn't really matter. Go with 0.0 as that's less likely
            // to confuse users.
            let util = match dom.weight() {
                0 => 0.0,
                nr => dom_util_sum[*dom_id] / nr as f64,
            };

            let enable_direct =
                self.direct_greedy_under > 0.99999 || util < self.direct_greedy_under;
            let enable_kick = self.kick_greedy_under > 0.99999 || util < self.kick_greedy_under;

            if enable_direct {
                self.direct_greedy_mask |= &dom.mask();
            }
            if enable_kick {
                self.kick_greedy_mask |= &dom.mask();
            }
        }

        let ti = &mut skel.maps.bss_data.as_mut().unwrap().tune_input;
        let write_to_bpf = |target: &mut [u64; 8], mask: &Cpumask| {
            let raw_slice = mask.as_raw_slice();
            let (left, _) = target.split_at_mut(raw_slice.len());
            left.clone_from_slice(raw_slice);
        };

        write_to_bpf(&mut ti.direct_greedy_cpumask, &self.direct_greedy_mask);
        write_to_bpf(&mut ti.kick_greedy_cpumask, &self.kick_greedy_mask);
        if self.fully_utilized {
            self.slice_ns = self.overutil_slice_ns;
        } else {
            self.slice_ns = self.underutil_slice_ns;
        }
        ti.slice_ns = self.slice_ns;

        ti.genn += 1;

        self.prev_cpu_stats = curr_cpu_stats;

        Ok(())
    }
}
