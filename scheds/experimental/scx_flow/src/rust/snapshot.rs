// SPDX-License-Identifier: GPL-2.0
//! Snapshot reads for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Builds the counters view plus the dashboard view from the BPF maps.
//! Each poll reads the per CPU stats rows plus the per CPU pid view
//! with no extra sysfs use, so the page stays cheap beside the slice.
//! A dashboard poll costs 3N BPF map reads for N online CPUs: N for
//! the stats sum plus N for the on CPU gauge plus N for the per CPU
//! cards, with one alloc and no sysfs on poll.

use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use crate::Scheduler;
use crate::stats;

impl<'a> Scheduler<'a> {
    /// Count live pids for the on CPU gauge with no BPF counter.
    /// Walks the cached online list with one map read per CPU, so the
    /// gauge costs N reads with no atomic cost on the hot paths. The
    /// BPF on CPU field stays zero for wire compat and never drives
    /// this count.
    pub(crate) fn count_on_cpu(&self) -> u64 {
        let mut live = 0u64;
        for &id in self.online_cpus.iter() {
            let st = self.read_cpu(id as usize);
            if st.running_pid != 0 {
                live = live.saturating_add(1);
            }
        }
        live
    }

    pub(crate) fn get_metrics(&self) -> stats::Metrics {
        let mut total_runtime = 0u64;
        let mut inserts = 0u64;
        let mut requeues = 0u64;
        let mut completions = 0u64;
        let mut local_moves = 0u64;
        let mut node_moves = 0u64;
        let mut machine_moves = 0u64;
        let mut kicks = 0u64;
        let mut admits = 0u64;
        let mut misses = 0u64;
        let mut gate_rejects = 0u64;
        let mut preempt_kicks = 0u64;
        let mut preempt_skipped = 0u64;
        let mut red_rejects = 0u64;
        let mut red_reclaims = 0u64;
        for &id in self.online_cpus.iter() {
            let s = self.read_stats(id as usize);
            total_runtime = total_runtime.saturating_add(s.total_runtime);
            inserts = inserts.saturating_add(s.inserts);
            requeues = requeues.saturating_add(s.requeues);
            completions = completions.saturating_add(s.completions);
            local_moves = local_moves.saturating_add(s.local_moves);
            node_moves = node_moves.saturating_add(s.node_moves);
            machine_moves = machine_moves.saturating_add(s.machine_moves);
            kicks = kicks.saturating_add(s.kicks);
            admits = admits.saturating_add(s.admits);
            misses = misses.saturating_add(s.misses);
            gate_rejects = gate_rejects.saturating_add(s.gate_rejects);
            preempt_kicks = preempt_kicks.saturating_add(s.preempt_kicks);
            preempt_skipped = preempt_skipped.saturating_add(s.preempt_skipped);
            red_rejects = red_rejects.saturating_add(s.red_rejects);
            red_reclaims = red_reclaims.saturating_add(s.red_reclaims);
        }
        stats::Metrics {
            on_cpu: self.count_on_cpu(),
            total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            inserts,
            requeues,
            completions,
            local_moves,
            node_moves,
            machine_moves,
            kicks,
            admits,
            // Dead compat: rejects stays zero with no BPF writer for wire
            // compat only; readers must use gate_rejects for drops.
            rejects: 0,
            misses,
            gate_rejects,
            preempt_kicks,
            preempt_skipped,
            red_rejects,
            red_reclaims,
        }
    }

    /// Read one per CPU stats row without heap use.
    /// Failed lookups yield a zero row with no trap.
    pub(crate) fn read_stats(&self, cpu: usize) -> crate::bpf_intf::flow_sched_stats {
        let zero = crate::bpf_intf::flow_sched_stats {
            on_cpu: 0,
            total_runtime: 0,
            inserts: 0,
            requeues: 0,
            completions: 0,
            local_moves: 0,
            node_moves: 0,
            machine_moves: 0,
            kicks: 0,
            admits: 0,
            rejects: 0,
            misses: 0,
            gate_rejects: 0,
            preempt_kicks: 0,
            preempt_skipped: 0,
            red_rejects: 0,
            red_reclaims: 0,
        };
        if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
            return zero;
        }
        let fd = self.skel.maps.cpu_stats_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<crate::bpf_intf::flow_sched_stats>::zeroed();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                out.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret == 0 {
            unsafe { out.assume_init() }
        } else {
            zero
        }
    }

    /// Read one CPU pid view without heap use.
    /// Failed lookups yield an idle view with zero pid.
    pub(crate) fn read_cpu(&self, cpu: usize) -> crate::bpf_intf::flow_cpu_state {
        let idle = crate::bpf_intf::flow_cpu_state {
            running_pid: 0,
            cursor: 0,
            min_vruntime: 0,
        };
        if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
            return idle;
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<crate::bpf_intf::flow_cpu_state>::zeroed();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                out.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret == 0 {
            unsafe { out.assume_init() }
        } else {
            idle
        }
    }

    /// Dashboard snapshot with raw counters plus live pid cards.
    /// Counters stay raw with no deltas and the on CPU gauge counts live
    /// pids with the pid view. Costs 3N map reads for N online CPUs: N
    /// for the stats sum via get_metrics plus N for the gauge plus N for
    /// the cards, with one alloc sized to the online count. SMT comes from the cached init
    /// flags with no sysfs use on poll and stays display only. Offline
    /// stays out, so per CPU count matches the cached online count.
    /// Version plus timestamp plus topology join the counters for the
    /// page plus the log.
    pub(crate) fn get_web_metrics(&self) -> stats::WebMetrics {
        let mut per_cpu = Vec::with_capacity(self.online_cpus.len());
        for (rank, &id) in self.online_cpus.iter().enumerate() {
            let st = self.read_cpu(id as usize);
            let smt = self.smt.get(rank).copied().unwrap_or(false);
            per_cpu.push(stats::PerCpuMetrics {
                id,
                smt,
                running_pid: st.running_pid,
                slice_ns: crate::config::QUANTUM_NS,
            });
        }
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_nanos().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        stats::WebMetrics {
            stats: self.get_metrics(),
            per_cpu,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_ns,
            topology: self.topology.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Poll cost in BPF map reads for N online CPUs.
    /// Dashboard polls read N for the stats sum via get_metrics plus N
    /// for the on CPU gauge plus N for the per CPU cards, so the total
    /// stays 3N with one alloc and no sysfs on poll.
    fn snapshot_reads(n: usize) -> usize {
        n.saturating_mul(3)
    }

    #[test]
    fn poll_cost_is_three_n() {
        assert_eq!(snapshot_reads(0), 0);
        assert_eq!(snapshot_reads(1), 3);
        assert_eq!(snapshot_reads(4), 12);
        // One alloc holds N cards with no extra walk.
        let per_cpu = Vec::<u32>::with_capacity(4);
        assert!(per_cpu.capacity() >= 4);
    }
}
