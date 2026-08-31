// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

use scx_utils::Topology;

/*
 * The BPF side derives its LLC and shard layout from the kernel cid tables in
 * ops.init(). Userspace only keeps the cpu-to-LLC map for the cell manager's
 * reporting.
 */
pub struct MitosisTopology {
    pub cpu_to_llc: BTreeMap<usize, usize>,
}

impl MitosisTopology {
    pub fn new(topology: &Topology) -> Self {
        let mut cpu_to_llc = BTreeMap::new();
        for cpu in 0..*scx_utils::NR_CPUS_POSSIBLE {
            cpu_to_llc.insert(
                cpu,
                topology
                    .all_cpus
                    .get(&cpu)
                    .map(|cpu| cpu.llc_id)
                    .unwrap_or(0),
            );
        }

        MitosisTopology { cpu_to_llc }
    }
}
