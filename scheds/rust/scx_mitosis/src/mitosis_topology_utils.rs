use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags};
use scx_utils::Topology;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use crate::bpf_skel::BpfSkel;

const CPUMASK_LONG_ENTRIES: usize = 128;

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
        println!("reading from stdin");
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        parse_cpu_llc_map(reader)
    } else {
        println!("reading from {path}");
        let file = std::fs::File::open(Path::new(path))?;
        let reader = BufReader::new(file);
        parse_cpu_llc_map(reader)
    }
}

/// Update map entries either from a file or from the host topology.
/// This function can be used by both the main scheduler and CLI tools.
pub fn populate_topology_maps(
    skel: &mut BpfSkel,
    map: MapKind,
    file: Option<String>,
) -> Result<()> {
    match map {
        MapKind::CpuToLLC => {
            let map_entries = if let Some(path) = file {
                println!("loading from {path}");
                read_cpu_llc_map(&path)?
            } else {
                println!("loading from host topology");
                let topo = Topology::new()?;
                (0..*scx_utils::NR_CPUS_POSSIBLE)
                    // Use 0 if a CPU is missing from the topology
                    .map(|cpu| (cpu, topo.all_cpus.get(&cpu).map(|c| c.llc_id).unwrap_or(0)))
                    .collect()
            };
            for (cpu, llc) in map_entries {
                // Each CPU index is stored as a 32bit key mapping to its LLC id
                let key = (cpu as u32).to_ne_bytes();
                let val = (llc as u32).to_ne_bytes();
                skel.maps.cpu_to_llc.update(&key, &val, MapFlags::ANY)?;
            }
        }
        MapKind::LLCToCpus => {
            if file.is_some() {
                anyhow::bail!("Loading llc_to_cpus from file is not supported yet");
            }

            println!("loading llc_to_cpus from host topology");
            let topo = Topology::new()?;

            // Group CPUs by LLC cache ID
            let mut llc_to_cpus: HashMap<usize, Vec<usize>> = HashMap::new();
            for cpu in topo.all_cpus.values() {
                llc_to_cpus.entry(cpu.llc_id).or_default().push(cpu.id);
            }

            // For each LLC cache, create a cpumask and populate the map
            for (llc_id, cpus) in llc_to_cpus {
                let key = (llc_id as u32).to_ne_bytes();

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

                // Convert to bytes for the map update
                let mut value_bytes = Vec::new();
                for long_val in cpumask_longs {
                    value_bytes.extend_from_slice(&long_val.to_ne_bytes());
                }

                skel.maps
                    .llc_to_cpus
                    .update(&key, &value_bytes, MapFlags::ANY)
                    .context(format!(
                        "Failed to update llc_to_cpus map for LLC {}",
                        llc_id
                    ))?;
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
