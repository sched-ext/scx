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
    CpuToL3,
    L3ToCpus,
}

impl std::str::FromStr for MapKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cpu_to_l3" => Ok(MapKind::CpuToL3),
            "l3_to_cpus" => Ok(MapKind::L3ToCpus),
            _ => bail!("unknown map {s}"),
        }
    }
}

impl std::fmt::Display for MapKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MapKind::CpuToL3 => "cpu_to_l3",
            MapKind::L3ToCpus => "l3_to_cpus",
        })
    }
}

pub const SUPPORTED_MAPS: &[MapKind] = &[MapKind::CpuToL3, MapKind::L3ToCpus];

/// Parse lines of the form `cpu,l3` from the provided reader.
fn parse_cpu_l3_map<R: BufRead>(reader: R) -> Result<Vec<(usize, usize)>> {
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
        let l3 = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing l3"))?
            .trim()
            .parse::<usize>()?;
        pairs.push((cpu, l3));
    }
    Ok(pairs)
}

/// Read CPU/L3 pairs either from a file or standard input.
fn read_cpu_l3_map(path: &str) -> Result<Vec<(usize, usize)>> {
    if path == "-" {
        println!("reading from stdin");
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        parse_cpu_l3_map(reader)
    } else {
        println!("reading from {path}");
        let file = std::fs::File::open(Path::new(path))?;
        let reader = BufReader::new(file);
        parse_cpu_l3_map(reader)
    }
}

/// Update map entries either from a file or from the host topology.
/// This function can be used by both the main scheduler and CLI tools.
pub fn populate_topology_maps(skel: &mut BpfSkel, map: MapKind, file: Option<String>) -> Result<()> {
    match map {
        MapKind::CpuToL3 => {
            let map_entries = if let Some(path) = file {
                println!("loading from {path}");
                read_cpu_l3_map(&path)?
            } else {
                println!("loading from host topology");
                let topo = Topology::new()?;
                (0..*scx_utils::NR_CPUS_POSSIBLE)
                    // Use 0 if a CPU is missing from the topology
                    .map(|cpu| (cpu, topo.all_cpus.get(&cpu).map(|c| c.l3_id).unwrap_or(0)))
                    .collect()
            };
            for (cpu, l3) in map_entries {
                // Each CPU index is stored as a 32bit key mapping to its L3 id
                let key = (cpu as u32).to_ne_bytes();
                let val = (l3 as u32).to_ne_bytes();
                skel.maps.cpu_to_l3.update(&key, &val, MapFlags::ANY)?;
            }
        }
        MapKind::L3ToCpus => {
            if file.is_some() {
                anyhow::bail!("Loading l3_to_cpus from file is not supported yet");
            }

            println!("loading l3_to_cpus from host topology");
            let topo = Topology::new()?;

            // Group CPUs by L3 cache ID
            let mut l3_to_cpus: HashMap<usize, Vec<usize>> = HashMap::new();
            for cpu in topo.all_cpus.values() {
                l3_to_cpus.entry(cpu.l3_id).or_default().push(cpu.id);
            }

            // For each L3 cache, create a cpumask and populate the map
            for (l3_id, cpus) in l3_to_cpus {
                let key = (l3_id as u32).to_ne_bytes();

                // Create a cpumask structure that matches the BPF side
                let mut cpumask_longs = [0u64; CPUMASK_LONG_ENTRIES];

                // Set bits for each CPU in this L3 cache
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

                skel.maps.l3_to_cpus.update(&key, &value_bytes, MapFlags::ANY)
                    .context(format!("Failed to update l3_to_cpus map for L3 {}", l3_id))?;
            }
        }
    }
    Ok(())
}


/// Display CPU to L3 cache relationships discovered from the host topology.
pub fn print_topology() -> Result<()> {
    let topo = Topology::new()?;
    println!("Number L3 caches: {}", topo.all_llcs.len());
    println!("CPU -> L3 id:");
    for cpu in topo.all_cpus.values() {
        println!("cpu {} -> {}", cpu.id, cpu.l3_id);
    }
    println!("\nL3 id -> [cpus]:");
    let mut by_l3: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for cpu in topo.all_cpus.values() {
        by_l3.entry(cpu.l3_id).or_default().push(cpu.id);
    }
    for (l3, mut cpus) in by_l3 {
        cpus.sort_unstable();
        println!("{l3} -> {:?}", cpus);
    }
    Ok(())
}
