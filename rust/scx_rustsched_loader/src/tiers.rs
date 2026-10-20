// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! CPU capacities and asymmetric packing priorities, the loader's half of
//! scx_rustsched's tiers.rs and topology.rs. The capacities and the
//! scheduling-domain spans come from scx_utils' Topology. The ITMT priority
//! and SD_ASYM_PACKING come from the kernel through the rust_cpu_priority()
//! syscall program, since neither has a user-space ABI. The result goes to
//! the BPF program per CPU, which translates it to CIDs at init.
//!
//! Capacity and packing are separate kernel policies with separate tiers,
//! 0 the most preferred in both. Capacity tiers group CPUs of close
//! capacity; packing tiers group CPUs of equal priority, or follow the
//! capacity tiers when the kernel does not pack.

use std::ffi::OsStr;

use anyhow::{Context, Result, bail, ensure};
use libbpf_rs::{
    Btf, MapCore, MapFlags, Object, ProgramInput,
    btf::types::{Composite, Enum, MemberAttr, Struct},
};

/// The BPF program's per-CPU table, see scx_rustsched's tiers.rs.
pub const MAX_CPUS: usize = 8192;
const _: () = assert!(
    MAX_CPUS <= 0x3fff,
    "the asymmetric capacity span takes 14 bits"
);

/// How capacities are chosen.
#[derive(Clone, Copy, PartialEq)]
pub enum CapacityMode {
    /// The kernel's cpu_capacity, which fair.c builds its domains from.
    Kernel,
    /// Every CPU the same.
    Uniform,
    /// scx_utils' hardware estimate, which can tell hybrid x86 cores apart
    /// where the kernel does not.
    Hardware,
}

#[derive(Clone)]
pub struct Cpu {
    pub id: usize,
    /// Normalized to 1..=1024, the fastest at 1024.
    pub capacity: u64,
    pub capacity_tier: u64,
    pub place_tier: u64,
    /// The SMT domain itself packs, so a core's threads rank too.
    pub smt_asym_packing: bool,
    /// The lowest domain spanning every capacity class, 0 for none.
    pub asym_capacity_span: u64,
}

pub struct Tiers {
    pub cpus: Vec<Cpu>,
    pub nr_capacity_tiers: u64,
    pub nr_place_tiers: u64,
    /// Placement and balance follow capacity.
    pub asym_capacity: bool,
    /// The kernel has an SD_ASYM_CPUCAPACITY domain.
    pub sched_asym_capacity: bool,
    /// The hardware estimate was asked for, which makes placement follow
    /// capacity whether or not the kernel has such a domain.
    pub forced: bool,
    pub asym_packing: bool,
    /// Where the capacities came from: the kernel's falls back to the
    /// hardware estimate when the kernel exports none.
    pub mode: CapacityMode,
    /// Largest capacity difference, in percent, within one tier.
    pub tolerance: u32,
}

/// Assign sorted, descending capacities to tiers. Each capacity is compared
/// with the fastest CPU of the current tier rather than the previous CPU,
/// so that a chain of small steps does not merge CPUs far apart.
pub fn capacity_tiers(capacities: &[u64], tolerance_pct: u32) -> Vec<u64> {
    let Some(&first) = capacities.first() else {
        return Vec::new();
    };
    let keep_pct = 100 - u64::from(tolerance_pct);
    let mut anchor = first;
    let mut tier = 0;
    capacities
        .iter()
        .map(|&capacity| {
            if capacity.saturating_mul(100) < anchor.saturating_mul(keep_pct) {
                tier += 1;
                anchor = capacity;
            }
            tier
        })
        .collect()
}

/// Packing tiers from (cpu, priority) pairs: equal priorities share a tier,
/// the highest priority is tier 0. Returns the tier per pair, in the order
/// given.
pub fn priority_tiers(priorities: &[(usize, i64)]) -> Vec<u64> {
    let mut sorted: Vec<i64> = priorities.iter().map(|&(_, priority)| priority).collect();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.dedup();
    priorities
        .iter()
        .map(|(_, priority)| sorted.iter().position(|p| p == priority).unwrap() as u64)
        .collect()
}

impl Tiers {
    /// Capacities and capacity tiers, from the topology before load.
    pub fn new(mode: CapacityMode, tolerance_pct: Option<u32>) -> Result<Self> {
        let topology = scx_utils::Topology::new().context("read CPU topology")?;
        let forced = mode == CapacityMode::Hardware;
        let mut mode = mode;
        let mut cpus: Vec<(usize, usize)> = match mode {
            CapacityMode::Uniform => topology.all_cpus.keys().map(|&id| (id, 1024)).collect(),
            CapacityMode::Hardware => topology
                .all_cpus
                .values()
                .map(|cpu| (cpu.id, cpu.cpu_capacity))
                .collect(),
            CapacityMode::Kernel => {
                match topology
                    .all_cpus
                    .values()
                    .map(|cpu| Some((cpu.id, cpu.kernel_cpu_capacity?)))
                    .collect::<Option<Vec<_>>>()
                {
                    Some(cpus) => cpus,
                    None => {
                        mode = CapacityMode::Hardware;
                        topology
                            .all_cpus
                            .values()
                            .map(|cpu| (cpu.id, cpu.cpu_capacity))
                            .collect()
                    }
                }
            }
        };
        ensure!(
            cpus.iter().all(|&(id, _)| id < MAX_CPUS),
            "more than {MAX_CPUS} CPUs"
        );
        let tolerance = tolerance_pct.unwrap_or(if mode == CapacityMode::Hardware { 5 } else { 0 });
        cpus.sort_by_key(|&(id, capacity)| (std::cmp::Reverse(capacity), id));
        let max = cpus.first().map_or(1, |&(_, capacity)| capacity.max(1));
        let capacities: Vec<u64> = cpus
            .iter()
            .map(|&(_, capacity)| (capacity * 1024 / max).clamp(1, 1024) as u64)
            .collect();
        let tiers = capacity_tiers(&capacities, tolerance);
        let nr_capacity_tiers = tiers.last().map_or(1, |tier| tier + 1);
        let mut entries = Vec::with_capacity(cpus.len());
        for ((&(id, _), &capacity), &tier) in cpus.iter().zip(&capacities).zip(&tiers) {
            let domains = topology
                .sched_domain_info(id)
                .context("read scheduler domains")?;
            entries.push(Cpu {
                id,
                capacity,
                capacity_tier: tier,
                place_tier: tier,
                smt_asym_packing: false,
                asym_capacity_span: domains.asym_capacity_span as u64,
            });
        }
        let sched_asym_capacity =
            mode != CapacityMode::Uniform && entries.iter().any(|cpu| cpu.asym_capacity_span != 0);
        // A hardware estimate the kernel fell back to does not by itself
        // make placement follow capacity: only asking for it does.
        let asym_capacity = nr_capacity_tiers > 1 && (sched_asym_capacity || forced);
        Ok(Self {
            cpus: entries,
            nr_capacity_tiers,
            nr_place_tiers: 1,
            asym_capacity,
            sched_asym_capacity,
            forced,
            asym_packing: false,
            mode,
            tolerance,
        })
    }

    /// Ask the kernel for each CPU's packing priority, after load, and set
    /// the packing tiers: from the priorities if every CPU packs and they
    /// differ, otherwise from the capacity tiers if placement follows
    /// capacity, otherwise one tier.
    pub fn read_priorities(&mut self, object: &mut Object, disable: bool) -> Result<()> {
        let btf = Btf::from_vmlinux().context("read running kernel BTF")?;
        let (flags_offset, child_offset) = domain_offsets(&btf)?;
        let (asym_packing_flag, share_capacity_flag) = domain_flags(&btf)?;
        let program = object
            .progs_mut()
            .find(|program| program.name() == OsStr::new("rust_cpu_priority"))
            .context("find rust_cpu_priority")?;
        let mut priorities = Vec::with_capacity(self.cpus.len());
        let mut all_pack = !disable;
        for cpu in &mut self.cpus {
            let mut args = [
                cpu.id as u64,
                flags_offset,
                child_offset,
                asym_packing_flag,
                share_capacity_flag,
                0,
                0,
                0,
            ];
            let input = ProgramInput {
                context_in: Some(unsafe {
                    std::slice::from_raw_parts_mut(
                        args.as_mut_ptr().cast::<u8>(),
                        size_of_val(&args),
                    )
                }),
                ..Default::default()
            };
            let output = program.test_run(input).context("run rust_cpu_priority")?;
            ensure!(output.return_value == 0, "rust_cpu_priority failed");
            if !disable {
                all_pack &= args[6] != 0;
                cpu.smt_asym_packing = args[7] != 0;
                priorities.push((cpu.id, args[5] as i64));
            }
        }
        let distinct = priorities.windows(2).any(|pair| pair[0].1 != pair[1].1);
        self.asym_packing = all_pack && distinct;
        if self.asym_packing {
            let tiers = priority_tiers(&priorities);
            for (cpu, tier) in self.cpus.iter_mut().zip(tiers) {
                cpu.place_tier = tier;
            }
            self.nr_place_tiers = self
                .cpus
                .iter()
                .map(|cpu| cpu.place_tier)
                .max()
                .unwrap_or(0)
                + 1;
        } else {
            for cpu in &mut self.cpus {
                cpu.place_tier = if self.asym_capacity {
                    cpu.capacity_tier
                } else {
                    0
                };
                cpu.smt_asym_packing = false;
            }
            self.nr_place_tiers = if self.asym_capacity {
                self.nr_capacity_tiers
            } else {
                1
            };
        }
        Ok(())
    }

    /// Hand the tiers to the BPF program, before it attaches.
    pub fn publish(&self, object: &Object) -> Result<()> {
        let map = object
            .maps()
            .find(|map| map.name() == OsStr::new(".data.tiers"))
            .context("find the CPU tier table")?;
        let mut words = vec![0_u64; 4 + MAX_CPUS];
        words[0] = self.nr_capacity_tiers;
        words[1] = self.nr_place_tiers;
        words[2] = u64::from(self.asym_capacity)
            | u64::from(self.sched_asym_capacity) << 1
            | u64::from(self.asym_packing) << 2
            | u64::from(self.forced) << 3
            | u64::from(self.cpus.iter().any(|cpu| cpu.smt_asym_packing)) << 4;
        for cpu in &self.cpus {
            words[4 + cpu.id] = 1 << 63
                | cpu.capacity
                | cpu.capacity_tier << 16
                | cpu.place_tier << 32
                | u64::from(cpu.smt_asym_packing) << 48
                | cpu.asym_capacity_span.min(0x3fff) << 49;
        }
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_ne_bytes()).collect();
        map.update(&0_u32.to_ne_bytes(), &bytes, MapFlags::ANY)
            .context("write the CPU tier table")
    }
}

/// struct sched_domain's flags and child offsets.
fn domain_offsets(btf: &Btf<'_>) -> Result<(u64, u64)> {
    let domain = btf
        .type_by_name::<Struct<'_>>("sched_domain")
        .context("find struct sched_domain")?;
    let composite = Composite::from(domain);
    let offset = |name: &str| -> Result<u64> {
        let member = composite
            .iter()
            .find(|member| member.name == Some(OsStr::new(name)))
            .with_context(|| format!("sched_domain has no {name}"))?;
        match member.attr {
            MemberAttr::Normal { offset } if offset % 8 == 0 => Ok(u64::from(offset / 8)),
            _ => bail!("sched_domain.{name} is not byte aligned"),
        }
    };
    Ok((offset("flags")?, offset("child")?))
}

/// The SD_ASYM_PACKING and SD_SHARE_CPUCAPACITY bits, enumerators of an
/// anonymous kernel enum.
fn domain_flags(btf: &Btf<'_>) -> Result<(u64, u64)> {
    let (mut packing, mut share) = (None, None);
    for enumeration in btf.type_by_kind::<Enum<'_>>() {
        for member in enumeration.iter() {
            match member.name.and_then(OsStr::to_str) {
                Some("SD_ASYM_PACKING") => packing = Some(member.value as u64),
                Some("SD_SHARE_CPUCAPACITY") => share = Some(member.value as u64),
                _ => {}
            }
        }
    }
    Ok((
        packing.context("kernel BTF has no SD_ASYM_PACKING")?,
        share.context("kernel BTF has no SD_SHARE_CPUCAPACITY")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_tiers_anchor_on_the_fastest_of_a_tier() {
        // 5% tolerance: 1000 and 960 share a tier, 920 is within 5% of 960
        // but not of 1000, the tier's fastest, so it starts the next one.
        assert_eq!(
            capacity_tiers(&[1000, 960, 920, 900, 500], 5),
            [0, 0, 1, 1, 2]
        );
        assert_eq!(capacity_tiers(&[1024, 1024, 1023], 0), [0, 0, 1]);
        assert!(capacity_tiers(&[], 5).is_empty());
    }

    #[test]
    fn priority_tiers_rank_equal_priorities_together() {
        let priorities = [(0, 70), (1, 70), (4, 80), (12, 50), (13, 50)];
        assert_eq!(priority_tiers(&priorities), [1, 1, 0, 2, 2]);
    }
}
