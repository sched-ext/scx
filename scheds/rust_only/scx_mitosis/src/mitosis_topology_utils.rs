// SPDX-License-Identifier: GPL-2.0
//
// LLC topology utilities for scx_mitosis (pure Rust BPF).
//
// Ported from scx/scheds/rust/scx_mitosis/src/mitosis_topology_utils.rs
// (which uses scx_utils::Topology + libbpf skeleton BSS) to work with
// aya's override_global mechanism.
//
// This module populates the arrays that the BPF side declares as:
//   u32              cpu_to_llc[MAX_CPUS];       // BSS
//   struct llc_cpumask llc_to_cpus[MAX_LLCS];    // BSS
//
// where MAX_CPUS = 512, MAX_LLCS = 16, CPUMASK_LONG_ENTRIES = 128.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use anyhow::{bail, Context, Result};
use log::debug;

// ── Constants matching intf.h ────────────────────────────────────────

/// Maximum CPUs supported (1 << MAX_CPUS_SHIFT where MAX_CPUS_SHIFT = 9).
pub const MAX_CPUS: usize = 512;

/// Maximum LLC domains.
pub const MAX_LLCS: usize = 16;

/// Size of cpumask in u64 words (supports up to 8192 CPUs).
/// Matches intf.h `CPUMASK_LONG_ENTRIES = 128`.
pub const CPUMASK_LONG_ENTRIES: usize = 128;

// ── LLC cpumask (matches struct llc_cpumask in intf.h) ───────────────

/// Fixed-size cpumask matching the BPF-side `struct llc_cpumask`.
///
/// Each element is an unsigned long (u64 on 64-bit), with bit N
/// representing CPU N. The array is large enough for 8192 CPUs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LlcCpumask {
    pub bits: [u64; CPUMASK_LONG_ENTRIES],
}

impl LlcCpumask {
    pub const ZERO: Self = Self {
        bits: [0; CPUMASK_LONG_ENTRIES],
    };

    /// Set the bit for a given CPU.
    pub fn set_cpu(&mut self, cpu: usize) {
        let word = cpu / 64;
        let bit = cpu % 64;
        if word < CPUMASK_LONG_ENTRIES {
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Count the number of set bits.
    #[allow(dead_code)]
    pub fn weight(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Check if a CPU bit is set.
    #[allow(dead_code)]
    pub fn test_cpu(&self, cpu: usize) -> bool {
        let word = cpu / 64;
        let bit = cpu % 64;
        word < CPUMASK_LONG_ENTRIES && (self.bits[word] & (1u64 << bit)) != 0
    }
}

impl Default for LlcCpumask {
    fn default() -> Self {
        Self::ZERO
    }
}

// ── Topology source ─────────────────────────────────────────────────

/// How to obtain the CPU-to-LLC mapping.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum TopologySource {
    /// Auto-detect from sysfs (default).
    Sysfs,
    /// Read from a file with lines of `cpu,llc` pairs.
    File(String),
    /// Read from stdin (`-`).
    Stdin,
}

// ── LLC topology data ───────────────────────────────────────────────

/// Computed LLC topology arrays, ready for BPF global overrides.
///
/// These match the BPF-side globals:
///   `u32 cpu_to_llc[MAX_CPUS]`
///   `struct llc_cpumask llc_to_cpus[MAX_LLCS]`
pub struct LlcTopology {
    /// Maps CPU index -> normalized LLC ID (contiguous 0..nr_llcs-1).
    pub cpu_to_llc: [u32; MAX_CPUS],

    /// Maps LLC ID -> cpumask of CPUs belonging to that LLC.
    pub llc_to_cpus: [LlcCpumask; MAX_LLCS],

    /// Number of distinct LLCs detected.
    pub nr_llcs: u32,

    /// Per-LLC CPU counts (for display/debugging).
    pub llc_cpu_counts: [u32; MAX_LLCS],
}

impl LlcTopology {
    /// Build LLC topology from the given source.
    pub fn new(source: TopologySource, nr_cpus: usize) -> Result<Self> {
        let raw_pairs = match source {
            TopologySource::Sysfs => Self::detect_from_sysfs(nr_cpus),
            TopologySource::File(ref path) => Self::read_from_file(path)?,
            TopologySource::Stdin => Self::read_from_reader(BufReader::new(io::stdin().lock()))?,
        };

        Self::build(raw_pairs, nr_cpus)
    }

    /// Build from raw (cpu, llc_id) pairs.
    ///
    /// LLC IDs are normalized to a contiguous 0..n range so the BPF
    /// side can use them as direct array indices.
    fn build(raw_pairs: Vec<(usize, usize)>, nr_cpus: usize) -> Result<Self> {
        // Collect unique LLC IDs and assign contiguous indices.
        let mut unique_llcs: Vec<usize> = raw_pairs.iter().map(|&(_, llc)| llc).collect();
        unique_llcs.sort();
        unique_llcs.dedup();

        let nr_llcs = unique_llcs.len().max(1);
        if nr_llcs > MAX_LLCS {
            bail!(
                "System has {} LLCs but MAX_LLCS is {} — topology exceeds BPF limits",
                nr_llcs,
                MAX_LLCS,
            );
        }

        let mut id_map = BTreeMap::new();
        for (i, &raw_id) in unique_llcs.iter().enumerate() {
            id_map.insert(raw_id, i as u32);
        }

        let mut cpu_to_llc = [0u32; MAX_CPUS];
        let mut llc_to_cpus = [LlcCpumask::ZERO; MAX_LLCS];
        let mut llc_cpu_counts = [0u32; MAX_LLCS];

        for &(cpu, raw_llc) in &raw_pairs {
            let llc = *id_map.get(&raw_llc).unwrap_or(&0);

            if cpu >= MAX_CPUS {
                debug!("CPU {} exceeds MAX_CPUS ({}), skipping", cpu, MAX_CPUS);
                continue;
            }

            cpu_to_llc[cpu] = llc;
            llc_to_cpus[llc as usize].set_cpu(cpu);
            llc_cpu_counts[llc as usize] += 1;
        }

        // Fill in CPUs not in raw_pairs (e.g., offline CPUs) with LLC 0.
        // This matches the C behavior: `topo.all_cpus.get(&cpu).map(|c| c.llc_id).unwrap_or(0)`.
        for cpu in 0..nr_cpus.min(MAX_CPUS) {
            if !raw_pairs.iter().any(|&(c, _)| c == cpu) {
                cpu_to_llc[cpu] = 0;
            }
        }

        Ok(Self {
            cpu_to_llc,
            llc_to_cpus,
            nr_llcs: nr_llcs as u32,
            llc_cpu_counts,
        })
    }

    /// Auto-detect CPU-to-LLC mapping from sysfs.
    ///
    /// For each CPU, finds the highest-level cache (last-level cache) and
    /// uses its `shared_cpu_list` to derive a canonical LLC ID (the lowest
    /// CPU number sharing that cache).
    fn detect_from_sysfs(nr_cpus: usize) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();

        for cpu in 0..nr_cpus {
            // Find the highest cache index (LLC is typically the last one).
            let mut max_index: u32 = 0;
            let cache_dir = format!("/sys/devices/system/cpu/cpu{}/cache", cpu);
            if let Ok(entries) = fs::read_dir(&cache_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(idx_str) = name_str.strip_prefix("index") {
                        if let Ok(idx) = idx_str.parse::<u32>() {
                            if idx > max_index {
                                max_index = idx;
                            }
                        }
                    }
                }
            }

            // Read shared_cpu_list to get canonical LLC ID (lowest CPU in the group).
            let shared_path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index{}/shared_cpu_list",
                cpu, max_index
            );
            if let Ok(content) = fs::read_to_string(&shared_path) {
                let shared_cpus = parse_cpu_list(content.trim());
                // Use the lowest CPU in the shared list as the LLC ID.
                let llc_id = shared_cpus.first().copied().unwrap_or(0) as usize;
                pairs.push((cpu, llc_id));
            } else {
                // CPU has no cache info (offline?), assign to LLC 0.
                pairs.push((cpu, 0));
            }
        }

        pairs
    }

    /// Read CPU-to-LLC mapping from a file.
    ///
    /// File format: one `cpu,llc` pair per line. Lines starting with `#`
    /// and blank lines are ignored. Matches the C version's format.
    fn read_from_file(path: &str) -> Result<Vec<(usize, usize)>> {
        let file = fs::File::open(Path::new(path))
            .with_context(|| format!("Failed to open LLC map file: {}", path))?;
        Self::read_from_reader(BufReader::new(file))
    }

    /// Parse CPU-to-LLC pairs from a reader.
    fn read_from_reader<R: BufRead>(reader: R) -> Result<Vec<(usize, usize)>> {
        let mut pairs = Vec::new();
        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("Failed to read line {}", line_no + 1))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(',');
            let cpu: usize = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("line {}: missing cpu", line_no + 1))?
                .trim()
                .parse()
                .with_context(|| format!("line {}: invalid cpu", line_no + 1))?;
            let llc: usize = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("line {}: missing llc", line_no + 1))?
                .trim()
                .parse()
                .with_context(|| format!("line {}: invalid llc", line_no + 1))?;
            pairs.push((cpu, llc));
        }
        Ok(pairs)
    }

    /// Print a human-readable summary of the LLC topology.
    pub fn print_summary(&self) {
        println!("  LLC topology ({} domains):", self.nr_llcs);
        for llc in 0..self.nr_llcs as usize {
            let cpu_count = self.llc_cpu_counts[llc];
            if cpu_count == 0 {
                continue;
            }

            // Collect CPUs in this LLC for display.
            let cpus: Vec<u32> = (0..MAX_CPUS as u32)
                .filter(|&cpu| self.llc_to_cpus[llc].test_cpu(cpu as usize))
                .collect();

            println!(
                "    LLC {}: {} CPUs ({})",
                llc,
                cpu_count,
                format_cpu_range(&cpus),
            );
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Parse a CPU list string like "0-3,8-11" into a sorted Vec of CPU IDs.
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut cpus = Vec::new();
    for range in s.split(',') {
        let range = range.trim();
        if range.is_empty() {
            continue;
        }
        if let Some((start, end)) = range.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                for cpu in s..=e {
                    cpus.push(cpu);
                }
            }
        } else if let Ok(cpu) = range.parse::<u32>() {
            cpus.push(cpu);
        }
    }
    cpus.sort();
    cpus
}

/// Format a list of CPU IDs as a compact range string (e.g., "0-3,8-11").
pub fn format_cpu_range(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut ranges = Vec::new();
    let mut start = cpus[0];
    let mut end = cpus[0];
    for &cpu in &cpus[1..] {
        if cpu == end + 1 {
            end = cpu;
        } else {
            if start == end {
                ranges.push(format!("{}", start));
            } else {
                ranges.push(format!("{}-{}", start, end));
            }
            start = cpu;
            end = cpu;
        }
    }
    if start == end {
        ranges.push(format!("{}", start));
    } else {
        ranges.push(format!("{}-{}", start, end));
    }
    ranges.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_list() {
        assert_eq!(parse_cpu_list("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list("0,2,4"), vec![0, 2, 4]);
        assert_eq!(parse_cpu_list("0-1,4-5"), vec![0, 1, 4, 5]);
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
        assert_eq!(parse_cpu_list("7"), vec![7]);
    }

    #[test]
    fn test_format_cpu_range() {
        assert_eq!(format_cpu_range(&[0, 1, 2, 3]), "0-3");
        assert_eq!(format_cpu_range(&[0, 2, 4]), "0,2,4");
        assert_eq!(format_cpu_range(&[0, 1, 4, 5]), "0-1,4-5");
        assert_eq!(format_cpu_range(&[]), "");
        assert_eq!(format_cpu_range(&[7]), "7");
    }

    #[test]
    fn test_llc_cpumask_operations() {
        let mut mask = LlcCpumask::ZERO;
        assert_eq!(mask.weight(), 0);
        assert!(!mask.test_cpu(0));

        mask.set_cpu(0);
        mask.set_cpu(3);
        mask.set_cpu(127);
        assert!(mask.test_cpu(0));
        assert!(mask.test_cpu(3));
        assert!(!mask.test_cpu(1));
        assert!(mask.test_cpu(127));
        assert_eq!(mask.weight(), 3);
    }

    #[test]
    fn test_build_single_llc() {
        // All 4 CPUs on LLC 0.
        let pairs = vec![(0, 0), (1, 0), (2, 0), (3, 0)];
        let topo = LlcTopology::build(pairs, 4).unwrap();
        assert_eq!(topo.nr_llcs, 1);
        assert_eq!(topo.cpu_to_llc[0], 0);
        assert_eq!(topo.cpu_to_llc[3], 0);
        assert_eq!(topo.llc_cpu_counts[0], 4);
        assert!(topo.llc_to_cpus[0].test_cpu(0));
        assert!(topo.llc_to_cpus[0].test_cpu(3));
    }

    #[test]
    fn test_build_multi_llc_normalized() {
        // Raw LLC IDs 10 and 20 should be normalized to 0 and 1.
        let pairs = vec![(0, 10), (1, 10), (2, 20), (3, 20)];
        let topo = LlcTopology::build(pairs, 4).unwrap();
        assert_eq!(topo.nr_llcs, 2);
        assert_eq!(topo.cpu_to_llc[0], 0); // raw 10 -> 0
        assert_eq!(topo.cpu_to_llc[1], 0);
        assert_eq!(topo.cpu_to_llc[2], 1); // raw 20 -> 1
        assert_eq!(topo.cpu_to_llc[3], 1);
        assert_eq!(topo.llc_cpu_counts[0], 2);
        assert_eq!(topo.llc_cpu_counts[1], 2);
    }

    #[test]
    fn test_build_too_many_llcs() {
        // MAX_LLCS + 1 distinct LLCs should fail.
        let pairs: Vec<(usize, usize)> = (0..=MAX_LLCS).map(|i| (i, i)).collect();
        assert!(LlcTopology::build(pairs, MAX_LLCS + 1).is_err());
    }

    #[test]
    fn test_read_from_reader() {
        let input = "# comment\n0,0\n1,0\n2,1\n3,1\n\n";
        let pairs =
            LlcTopology::read_from_reader(BufReader::new(input.as_bytes())).unwrap();
        assert_eq!(pairs, vec![(0, 0), (1, 0), (2, 1), (3, 1)]);
    }
}
