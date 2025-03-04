// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_intf;
use crate::bpf_skel::BpfSkel;

use libbpf_rs::MapCore;

const STAT_DROPPED_EVENTS: usize = bpf_intf::stat_id_STAT_DROPPED_EVENTS as usize;

#[derive(Default, Debug)]
pub struct BpfStats {
    pub dropped_events: u64,
}

impl BpfStats {
    pub fn get_from_skel(skel: &BpfSkel<'_>) -> anyhow::Result<BpfStats> {
        let all_cpus = skel
            .maps
            .stats
            .lookup_percpu(&0_u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)?
            .expect("BPF_MAP_TYPE_PERCPU_ARRAY");

        let read_stat = |idx| {
            all_cpus
                .iter()
                .map(|pcpu| {
                    // pcpu comes in as unaligned u8s. stride over 8 of them for each stat index.
                    let val = &pcpu[idx * 8..];
                    u64::from_ne_bytes(val.try_into().expect("all stats are u64s"))
                })
                .sum()
        };

        Ok(BpfStats {
            dropped_events: read_stat(STAT_DROPPED_EVENTS),
        })
    }
}
