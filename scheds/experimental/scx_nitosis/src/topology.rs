// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use scx_utils::{Cpumask, Topology};

use crate::bpf_intf;
use crate::bpf_skel::types::llc_cpumask;
use crate::bpf_skel::OpenBpfSkel;

const MAX_LLCS: usize = bpf_intf::consts_MAX_LLCS as usize;
const CPUMASK_LONG_ENTRIES: usize = bpf_intf::consts_CPUMASK_LONG_ENTRIES as usize;

pub struct MitosisTopology {
    pub cpu_to_llc: BTreeMap<usize, usize>,
    pub llc_to_cpus: BTreeMap<usize, Cpumask>,
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

        let mut llc_to_cpus = BTreeMap::new();
        for llc in topology.all_llcs.values() {
            llc_to_cpus.insert(llc.id, llc.span.clone());
        }

        MitosisTopology {
            cpu_to_llc,
            llc_to_cpus,
        }
    }

    pub fn apply(&self, skel: &mut OpenBpfSkel) -> Result<()> {
        // TODO: rodata
        let bss = skel
            .maps
            .bss_data
            .as_mut()
            .ok_or_else(|| anyhow!("bss_data not available"))?;
        self.apply_topology(&mut bss.cpu_to_llc, &mut bss.llc_to_cpus)
    }

    fn apply_topology(
        &self,
        cpu_to_llc: &mut [u32],
        llc_to_cpus: &mut [llc_cpumask; MAX_LLCS],
    ) -> Result<()> {
        for (&cpu, &llc_id) in &self.cpu_to_llc {
            if cpu >= cpu_to_llc.len() {
                bail!("invalid cpu {cpu}");
            }
            cpu_to_llc[cpu] = llc_id as u32;
        }

        for (&llc, cpumask) in &self.llc_to_cpus {
            if llc >= llc_to_cpus.len() {
                bail!("invalid llc {llc}");
            }

            let raw_span = cpumask.as_raw_slice();
            // Is this overkill?
            if raw_span.len() > llc_to_cpus[llc].bits.len() {
                bail!(
                    "invalid span {llc}: {} > {}",
                    raw_span.len(),
                    llc_to_cpus[llc].bits.len()
                );
            }

            llc_to_cpus[llc].bits = [0; CPUMASK_LONG_ENTRIES];
            llc_to_cpus[llc].bits[..raw_span.len()].copy_from_slice(raw_span);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_llc_cpu(llc_to_cpus: &[llc_cpumask; MAX_LLCS], llc: usize, cpu: usize) -> bool {
        let long_idx = cpu / 64;
        let bit_idx = cpu % 64;
        llc_to_cpus[llc].bits[long_idx] & (1u64 << bit_idx) != 0
    }

    #[test]
    fn test_topology() {
        let (topology, _) = scx_utils::testutils::make_test_topo(
            1,  // nodes
            16, // llcs
            8,  // cores
            2,  // cpus
        );
        let mut cpu_to_llc_map = BTreeMap::new();
        for cpu in 0..256 {
            cpu_to_llc_map.insert(cpu, cpu / 16);
        }
        let llc_to_cpus_map = topology
            .all_llcs
            .values()
            .map(|llc| (llc.id, llc.span.clone()))
            .collect();
        let mitosis_topology = MitosisTopology {
            cpu_to_llc: cpu_to_llc_map,
            llc_to_cpus: llc_to_cpus_map,
        };

        let mut cpu_to_llc = [0u32; bpf_intf::consts_MAX_CPUS as usize];
        let mut llc_to_cpus = [llc_cpumask {
            bits: [0; CPUMASK_LONG_ENTRIES],
        }; MAX_LLCS];

        mitosis_topology
            .apply_topology(&mut cpu_to_llc, &mut llc_to_cpus)
            .unwrap();

        assert_eq!(cpu_to_llc[0], 0);
        assert_eq!(cpu_to_llc[15], 0);
        assert_eq!(cpu_to_llc[16], 1);
        assert_eq!(cpu_to_llc[255], 15);

        for llc in 0..MAX_LLCS {
            let first_cpu = llc * 16;
            let last_cpu = first_cpu + 15;

            assert!(check_llc_cpu(&llc_to_cpus, llc, first_cpu));
            assert!(check_llc_cpu(&llc_to_cpus, llc, last_cpu));

            if llc > 0 {
                assert!(!check_llc_cpu(&llc_to_cpus, llc, first_cpu - 1));
            }
            if llc + 1 < MAX_LLCS {
                assert!(!check_llc_cpu(&llc_to_cpus, llc, last_cpu + 1));
            }
        }
    }
}
