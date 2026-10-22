// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Per-NUMA-node DRAM traffic from memory-controller (uncore) PMUs.
//!
//! Unlike resctrl MBM, which counts traffic leaving each L3 regardless of
//! where it is served, memory-controller counters count the reads and writes
//! each DRAM channel actually performs. This includes hardware prefetches,
//! writebacks, non-temporal stores, DMA and remote-socket accesses, and is
//! charged to the node that owns the memory, which is what node capacity
//! describes. The counters cannot be attributed to tasks, so they only provide
//! node totals.

use std::collections::BTreeMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use scx_utils::Topology;
use scx_utils::perf;
use tracing::warn;

const PMU_DEVICES: &str = "/sys/bus/event_source/devices";

/// AMD UMC CAS command count with rdwrmask=0 (umc_cas_cmd.all). Each CAS
/// command transfers one 64-byte line.
const AMD_UMC_CAS_CMD_ALL: u64 = 0x0a;
const BYTES_PER_CAS: u64 = 64;

struct Counter {
    node: usize,
    fd: OwnedFd,
    // (value, time_enabled, time_running) at the previous read.
    prev: [u64; 3],
}

pub struct MemCtlCounters {
    counters: Vec<Counter>,
    node_bytes: Vec<u64>,
    warned_multiplexed: bool,
}

fn read_counter(fd: &OwnedFd) -> Result<[u64; 3]> {
    let mut buf = [0u64; 3];
    let len = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            std::mem::size_of_val(&buf),
        )
    };
    if len != std::mem::size_of_val(&buf) as isize {
        bail!(
            "short memory-controller counter read: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(buf)
}

impl MemCtlCounters {
    /// Open one CAS counter per AMD UMC and map each to the NUMA node of
    /// the CPU that perf reads it on.
    pub fn open(topo: &Topology) -> Result<Self> {
        // A UMC PMU exposes a single CPU per package in its cpumask, so a
        // counter can only be mapped to a node when packages and nodes are
        // one-to-one. NPS2/NPS4 split a package's channels across nodes.
        let mut package_node = BTreeMap::new();
        for cpu in topo.all_cpus.values() {
            if *package_node.entry(cpu.package_id).or_insert(cpu.node_id) != cpu.node_id {
                bail!(
                    "package {} spans multiple NUMA nodes; memory-controller counters cannot be attributed per node",
                    cpu.package_id
                );
            }
        }

        let mut pmus: Vec<_> = fs::read_dir(PMU_DEVICES)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("amd_umc_"))
            .map(|entry| entry.path())
            .collect();
        pmus.sort();
        if pmus.is_empty() {
            bail!("no supported memory-controller PMU found in {PMU_DEVICES}");
        }

        let mut counters = Vec::with_capacity(pmus.len());
        for pmu in &pmus {
            let (cpu, fd) = Self::open_counter(pmu)?;
            let node = topo
                .all_cpus
                .get(&cpu)
                .map(|cpu| cpu.node_id)
                .with_context(|| format!("{}: CPU {cpu} is not in the topology", pmu.display()))?;
            let prev = read_counter(&fd)?;
            counters.push(Counter { node, fd, prev });
        }

        let nr_nodes = topo.nodes.len();
        if let Some(node) =
            (0..nr_nodes).find(|node| !counters.iter().any(|counter| counter.node == *node))
        {
            bail!("no memory-controller counter maps to NUMA node {node}");
        }

        Ok(Self {
            counters,
            node_bytes: vec![0; nr_nodes],
            warned_multiplexed: false,
        })
    }

    fn open_counter(pmu: &Path) -> Result<(usize, OwnedFd)> {
        let pmu_type = fs::read_to_string(pmu.join("type"))?
            .trim()
            .parse::<u32>()
            .with_context(|| format!("{}: invalid PMU type", pmu.display()))?;
        let cpumask = fs::read_to_string(pmu.join("cpumask"))?;
        let cpu = cpumask
            .trim()
            .split([',', '-'])
            .next()
            .and_then(|cpu| cpu.parse::<usize>().ok())
            .with_context(|| format!("{}: invalid cpumask {cpumask:?}", pmu.display()))?;

        let mut attr = perf::bindings::perf_event_attr {
            size: std::mem::size_of::<perf::bindings::perf_event_attr>() as u32,
            type_: pmu_type,
            config: AMD_UMC_CAS_CMD_ALL,
            read_format: (perf::bindings::PERF_FORMAT_TOTAL_TIME_ENABLED
                | perf::bindings::PERF_FORMAT_TOTAL_TIME_RUNNING) as u64,
            ..Default::default()
        };
        attr.set_disabled(0);

        let fd = unsafe { perf::perf_event_open(&mut attr, -1, cpu as i32, -1, 0) };
        if fd < 0 {
            bail!(
                "{}: perf_event_open failed on CPU {cpu}: {}",
                pmu.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok((cpu, unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Return cumulative DRAM bytes per NUMA node. Each counter's delta is
    /// scaled by enabled/running time, so perf multiplexing with other users
    /// of the same UMC extrapolates instead of silently undercounting.
    pub fn read_node_bytes(&mut self) -> Result<Vec<u64>> {
        let mut multiplexed = false;
        for counter in &mut self.counters {
            let cur = read_counter(&counter.fd)?;
            let value = cur[0].saturating_sub(counter.prev[0]);
            let enabled = cur[1].saturating_sub(counter.prev[1]);
            let running = cur[2].saturating_sub(counter.prev[2]);
            counter.prev = cur;

            let cas = if running == 0 {
                // Never scheduled during the interval; nothing to scale.
                multiplexed |= enabled > 0;
                0
            } else if running < enabled {
                multiplexed = true;
                (value as f64 * enabled as f64 / running as f64) as u64
            } else {
                value
            };
            self.node_bytes[counter.node] =
                self.node_bytes[counter.node].saturating_add(cas.saturating_mul(BYTES_PER_CAS));
        }

        if multiplexed && !self.warned_multiplexed {
            warn!(
                "memory-controller counters are multiplexed with other perf users; bandwidth is extrapolated"
            );
            self.warned_multiplexed = true;
        }

        Ok(self.node_bytes.clone())
    }
}
