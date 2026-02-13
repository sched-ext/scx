use crate::bpf_intf;
use anyhow::{bail, Result};
use scx_utils::Topology;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use crate::bpf_skel::OpenBpfSkel;

const CPUMASK_LONG_ENTRIES: usize = bpf_intf::consts_CPUMASK_LONG_ENTRIES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapKind {
    CpuToLLC,
    LLCToCpus,
}

impl std::str::FromStr for MapKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cpu_to_llc" => Ok(MapKind::CpuToLLC),
            "llc_to_cpus" => Ok(MapKind::LLCToCpus),
            _ => bail!("unknown map {s}"),
        }
    }
}

impl std::fmt::Display for MapKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MapKind::CpuToLLC => "cpu_to_llc",
            MapKind::LLCToCpus => "llc_to_cpus",
        })
    }
}

#[allow(dead_code)]
pub const SUPPORTED_MAPS: &[MapKind] = &[MapKind::CpuToLLC, MapKind::LLCToCpus];

/// Parse lines of the form `cpu,llc` from the provided reader.
fn parse_cpu_llc_map<R: BufRead>(reader: R) -> Result<Vec<(usize, usize)>> {
    let mut pairs = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        // Ignore blank lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(',');
        let cpu = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing cpu"))?
            .trim()
            .parse::<usize>()?;
        let llc = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing llc"))?
            .trim()
            .parse::<usize>()?;
        pairs.push((cpu, llc));
    }
    Ok(pairs)
}

/// Read CPU/LLC pairs either from a file or standard input.
fn read_cpu_llc_map(path: &str) -> Result<Vec<(usize, usize)>> {
    if path == "-" {
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        parse_cpu_llc_map(reader)
    } else {
        let file = std::fs::File::open(Path::new(path))?;
        let reader = BufReader::new(file);
        parse_cpu_llc_map(reader)
    }
}

/// Update global arrays for LLC topology before BPF program load.
/// This function writes directly to the skeleton's BSS section.
pub fn populate_topology_maps(
    skel: &mut OpenBpfSkel,
    map: MapKind,
    file: Option<String>,
) -> Result<()> {
    match map {
        MapKind::CpuToLLC => {
            let map_entries = if let Some(path) = file {
                read_cpu_llc_map(&path)?
            } else {
                let topo = Topology::new()?;
                (0..*scx_utils::NR_CPUS_POSSIBLE)
                    // Use 0 if a CPU is missing from the topology
                    .map(|cpu| (cpu, topo.all_cpus.get(&cpu).map(|c| c.llc_id).unwrap_or(0)))
                    .collect()
            };
            let bss = skel
                .maps
                .bss_data
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("bss_data not available"))?;
            for (cpu, llc) in map_entries {
                if cpu >= bss.cpu_to_llc.len() {
                    bail!("invalid cpu {cpu}");
                }
                bss.cpu_to_llc[cpu] = llc as u32;
            }
        }
        MapKind::LLCToCpus => {
            if file.is_some() {
                anyhow::bail!("Loading llc_to_cpus from file is not supported yet");
            }

            let topo = Topology::new()?;

            // Group CPUs by LLC cache ID
            let mut llc_to_cpus: HashMap<usize, Vec<usize>> = HashMap::new();
            for cpu in topo.all_cpus.values() {
                llc_to_cpus.entry(cpu.llc_id).or_default().push(cpu.id);
            }

            // For each LLC cache, create a cpumask and populate the array
            let bss = skel
                .maps
                .bss_data
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("bss_data not available"))?;
            for (llc_id, cpus) in llc_to_cpus {
                // Create a cpumask structure that matches the BPF side
                let mut cpumask_longs = [0u64; CPUMASK_LONG_ENTRIES];

                // Set bits for each CPU in this LLC cache
                for cpu in cpus {
                    let long_idx = cpu / 64;
                    let bit_idx = cpu % 64;
                    if long_idx < CPUMASK_LONG_ENTRIES {
                        cpumask_longs[long_idx] |= 1u64 << bit_idx;
                    }
                }
                if llc_id >= bss.llc_to_cpus.len() {
                    bail!("invalid llc_id {llc_id}");
                }

                bss.llc_to_cpus[llc_id].bits = cpumask_longs;
            }
        }
    }
    Ok(())
}

/// Display CPU to LLC cache relationships discovered from the host topology.
#[allow(dead_code)]
pub fn print_topology() -> Result<()> {
    let topo = Topology::new()?;
    println!("Number LLC caches: {}", topo.all_llcs.len());
    println!("CPU -> LLC id:");
    for cpu in topo.all_cpus.values() {
        println!("cpu {} -> {}", cpu.id, cpu.llc_id);
    }
    println!("\nLLC id -> [cpus]:");
    let mut by_llc: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for cpu in topo.all_cpus.values() {
        by_llc.entry(cpu.llc_id).or_default().push(cpu.id);
    }
    for (llc, mut cpus) in by_llc {
        cpus.sort_unstable();
        println!("{llc} -> {:?}", cpus);
    }
    Ok(())
}
