// SPDX-License-Identifier: GPL-2.0
//! Collection of the BPF counters of scx_flow.
//!
//! The BPF program counts events per CPU and publishes the queue length of
//! each LLC. The counters are folded per LLC here using the CPU to LLC
//! table the program was loaded with.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use log::warn;

use crate::BpfSkel;
use crate::bpf_intf;
use crate::stats::Metrics;

const NR_STATS: usize = bpf_intf::flow_stat_idx_FLOW_NR_STATS as usize;

/// Counters of one CPU, indexed by `enum flow_stat_idx`.
fn parse_cpu_stats(val: &[u8]) -> [u64; NR_STATS] {
    let mut cnt = [0u64; NR_STATS];

    for (slot, bytes) in cnt.iter_mut().zip(val.as_chunks::<8>().0) {
        *slot = u64::from_ne_bytes(*bytes);
    }
    cnt
}

fn add_cpu_stats(row: &mut Metrics, cnt: &[u64; NR_STATS]) {
    let get = |idx: bpf_intf::flow_stat_idx| cnt[idx as usize];

    row.add(&Metrics {
        queued: 0,
        dispatched: get(bpf_intf::flow_stat_idx_FLOW_STAT_DISPATCHED),
        direct: get(bpf_intf::flow_stat_idx_FLOW_STAT_DIRECT),
        steal: get(bpf_intf::flow_stat_idx_FLOW_STAT_STEAL),
        fallback: get(bpf_intf::flow_stat_idx_FLOW_STAT_FALLBACK),
        kick_idle: get(bpf_intf::flow_stat_idx_FLOW_STAT_KICK_IDLE),
        kick_preempt: get(bpf_intf::flow_stat_idx_FLOW_STAT_KICK_PREEMPT),
        keep: get(bpf_intf::flow_stat_idx_FLOW_STAT_KEEP),
        preempted: get(bpf_intf::flow_stat_idx_FLOW_STAT_PREEMPTED),
    });
}

/// Counters of each LLC, indexed by the LLC id of the BPF program.
pub fn collect_per_llc(skel: &BpfSkel<'_>) -> Vec<Metrics> {
    let (Some(rodata), Some(bss)) = (skel.maps.rodata_data.as_ref(), skel.maps.bss_data.as_ref())
    else {
        warn!("BPF global data is not mapped");
        return Vec::new();
    };
    let mut rows = vec![Metrics::default(); rodata.flow_nr_llcs as usize];

    for (row, queued) in rows.iter_mut().zip(bss.flow_llc_nr_queued.iter()) {
        row.queued = *queued;
    }

    match skel
        .maps
        .cpu_stats
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)
    {
        Ok(Some(per_cpu)) => {
            for (cpu, val) in per_cpu.iter().enumerate() {
                let llc = rodata.flow_cpu_llc.get(cpu).copied().unwrap_or(0) as usize;
                if let Some(row) = rows.get_mut(llc) {
                    add_cpu_stats(row, &parse_cpu_stats(val));
                }
            }
        }
        Ok(None) => {}
        Err(e) => warn!("failed to read the CPU counters: {e:#}"),
    }
    rows
}

/// Counters summed over all LLCs.
pub fn collect(skel: &BpfSkel<'_>) -> Metrics {
    collect_per_llc(skel)
        .iter()
        .fold(Metrics::default(), |mut total, row| {
            total.add(row);
            total
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_stats_follow_the_enum_order() {
        let mut val = Vec::new();
        for i in 0..NR_STATS as u64 {
            val.extend_from_slice(&(i + 1).to_ne_bytes());
        }
        let cnt = parse_cpu_stats(&val);
        let mut row = Metrics::default();
        add_cpu_stats(&mut row, &cnt);

        assert_eq!(
            row.dispatched,
            1 + bpf_intf::flow_stat_idx_FLOW_STAT_DISPATCHED as u64
        );
        assert_eq!(
            row.preempted,
            1 + bpf_intf::flow_stat_idx_FLOW_STAT_PREEMPTED as u64
        );
        assert_eq!(row.queued, 0);
    }

    #[test]
    fn short_values_leave_zeros() {
        let cnt = parse_cpu_stats(&7u64.to_ne_bytes());
        assert_eq!(cnt[0], 7);
        assert!(cnt[1..].iter().all(|c| *c == 0));
    }
}
