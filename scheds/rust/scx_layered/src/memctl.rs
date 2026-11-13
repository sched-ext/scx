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
    bytes_per_count: u64,
    fd: OwnedFd,
    // (value, time_enabled, time_running) at the previous read.
    prev: [u64; 3],
}

/// Grace SCF reads count 32-byte beats, while writes count bytes directly.
/// CMEM events count traffic served by this socket's CPU memory, including
/// other sockets' requests. GPU and PCIe traffic have separate PMUs.
fn grace_events(pmu: &Path) -> Result<[(u64, u64); 2]> {
    let event = |name: &str| -> Result<u64> {
        let path = pmu.join("events").join(name);
        let spec = fs::read_to_string(&path)?;
        let value = spec
            .trim()
            .strip_prefix("event=0x")
            .with_context(|| format!("{}: unsupported event encoding {spec:?}", path.display()))?;
        u64::from_str_radix(value, 16)
            .with_context(|| format!("{}: invalid event encoding", path.display()))
    };
    // Do not assume the event selector layout on a different SCF version.
    let format = fs::read_to_string(pmu.join("format/event"))?;
    if format.trim() != "config:0-32" {
        bail!("{}: unsupported SCF event format {format:?}", pmu.display());
    }
    Ok([
        (event("cmem_rd_data")?, 32),
        (event("cmem_wr_total_bytes")?, 1),
    ])
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
    /// Open AMD UMC CAS or Grace SCF CMEM counters and map each to the
    /// NUMA node of the CPU that perf reads it on.
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
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("amd_umc_") || name.starts_with("nvidia_scf_pmu_")
            })
            .map(|entry| entry.path())
            .collect();
        pmus.sort();
        if pmus.is_empty() {
            bail!("no supported memory-controller PMU found in {PMU_DEVICES}");
        }

        let mut counters = Vec::with_capacity(pmus.len());
        for pmu in &pmus {
            let events = if pmu
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("nvidia_scf_pmu_")
            {
                // The ARM proxy does not distinguish local and remote
                // fills, so it cannot apportion multi-node CMEM traffic.
                if topo.nodes.len() != 1 {
                    bail!("Grace SCF bandwidth attribution requires a single NUMA node");
                }
                grace_events(pmu)?.to_vec()
            } else {
                vec![(AMD_UMC_CAS_CMD_ALL, BYTES_PER_CAS)]
            };
            for (event, bytes_per_count) in events {
                let (cpu, fd) = Self::open_counter(pmu, event)?;
                let node = topo
                    .all_cpus
                    .get(&cpu)
                    .map(|cpu| cpu.node_id)
                    .with_context(|| {
                        format!("{}: CPU {cpu} is not in the topology", pmu.display())
                    })?;
                let prev = read_counter(&fd)?;
                counters.push(Counter {
                    node,
                    bytes_per_count,
                    fd,
                    prev,
                });
            }
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

    fn open_counter(pmu: &Path, event: u64) -> Result<(usize, OwnedFd)> {
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
            config: event,
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
    /// of the same PMU extrapolates instead of silently undercounting.
    pub fn read_node_bytes(&mut self) -> Result<Vec<u64>> {
        let mut multiplexed = false;
        for counter in &mut self.counters {
            let cur = read_counter(&counter.fd)?;
            let value = cur[0].saturating_sub(counter.prev[0]);
            let enabled = cur[1].saturating_sub(counter.prev[1]);
            let running = cur[2].saturating_sub(counter.prev[2]);
            counter.prev = cur;

            let count = if running == 0 {
                // Never scheduled during the interval; nothing to scale.
                multiplexed |= enabled > 0;
                0
            } else if running < enabled {
                multiplexed = true;
                (value as f64 * enabled as f64 / running as f64) as u64
            } else {
                value
            };
            self.node_bytes[counter.node] = self.node_bytes[counter.node]
                .saturating_add(count.saturating_mul(counter.bytes_per_count));
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

#[cfg(test)]
mod tests {
    use super::*;

    // Feed perf's read format through pipes so the byte conversion and
    // incremental multiplex scaling can be checked without hardware PMUs.
    fn counter(bytes_per_count: u64) -> (Counter, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (
            Counter {
                node: 0,
                bytes_per_count,
                fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
                prev: [100, 100, 100],
            },
            unsafe { OwnedFd::from_raw_fd(fds[1]) },
        )
    }

    fn sample(fd: &OwnedFd, value: [u64; 3]) {
        let size = std::mem::size_of_val(&value);
        assert_eq!(
            unsafe { libc::write(fd.as_raw_fd(), value.as_ptr().cast(), size) },
            size as isize
        );
    }

    #[test]
    fn grace_read_beats_and_write_bytes_accumulate_with_multiplexing() {
        let (read, read_fd) = counter(32);
        let (write, write_fd) = counter(1);
        let mut counters = MemCtlCounters {
            counters: vec![read, write],
            node_bytes: vec![0],
            warned_multiplexed: false,
        };
        sample(&read_fd, [110, 200, 200]);
        sample(&write_fd, [164, 200, 200]);
        assert_eq!(counters.read_node_bytes().unwrap(), vec![384]);

        // Scale only this interval's counts, then apply each event's unit.
        sample(&read_fd, [120, 300, 250]);
        sample(&write_fd, [228, 300, 250]);
        assert_eq!(counters.read_node_bytes().unwrap(), vec![1152]);
        assert!(counters.warned_multiplexed);

        // A PMU that never ran supplies no usable delta.
        sample(&read_fd, [120, 400, 250]);
        sample(&write_fd, [228, 400, 250]);
        assert_eq!(counters.read_node_bytes().unwrap(), vec![1152]);
    }

    #[test]
    fn amd_cas_remains_64_bytes() {
        let (counter, fd) = counter(BYTES_PER_CAS);
        let mut counters = MemCtlCounters {
            counters: vec![counter],
            node_bytes: vec![0],
            warned_multiplexed: false,
        };
        sample(&fd, [110, 200, 200]);
        assert_eq!(counters.read_node_bytes().unwrap(), vec![640]);
    }
}
