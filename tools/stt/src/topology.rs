use anyhow::{Context, Result};
use scx_utils::Topology;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct LlcInfo {
    pub cpus: Vec<usize>,
    pub numa_node: usize,
}

#[derive(Debug, Clone)]
pub struct TestTopology {
    cpus: Vec<usize>,
    llcs: Vec<LlcInfo>,
    numa_nodes: BTreeSet<usize>,
}

impl TestTopology {
    pub fn from_system() -> Result<Self> {
        let topo = Topology::new().context("read topology")?;
        let mut cpus = BTreeSet::new();
        let mut llc_map: std::collections::BTreeMap<usize, LlcInfo> =
            std::collections::BTreeMap::new();
        let mut numa_nodes = BTreeSet::new();
        for (&cpu_id, cpu) in &topo.all_cpus {
            cpus.insert(cpu_id);
            numa_nodes.insert(cpu.node_id);
            llc_map
                .entry(cpu.llc_id)
                .and_modify(|info| info.cpus.push(cpu_id))
                .or_insert_with(|| LlcInfo {
                    cpus: vec![cpu_id],
                    numa_node: cpu.node_id,
                });
        }
        for info in llc_map.values_mut() {
            info.cpus.sort();
        }
        Ok(Self {
            cpus: cpus.into_iter().collect(),
            llcs: llc_map.into_values().collect(),
            numa_nodes,
        })
    }

    pub fn total_cpus(&self) -> usize {
        self.cpus.len()
    }
    pub fn num_llcs(&self) -> usize {
        self.llcs.len()
    }
    pub fn num_numa_nodes(&self) -> usize {
        self.numa_nodes.len()
    }
    pub fn llcs(&self) -> &[LlcInfo] {
        &self.llcs
    }
    pub fn all_cpus(&self) -> &[usize] {
        &self.cpus
    }
    pub fn cpus_in_llc(&self, idx: usize) -> &[usize] {
        &self.llcs[idx].cpus
    }
    pub fn llc_aligned_cpuset(&self, idx: usize) -> BTreeSet<usize> {
        self.llcs[idx].cpus.iter().copied().collect()
    }

    pub fn split_by_llc(&self) -> Vec<BTreeSet<usize>> {
        self.llcs
            .iter()
            .map(|l| l.cpus.iter().copied().collect())
            .collect()
    }

    pub fn overlapping_cpusets(&self, n: usize, overlap_frac: f64) -> Vec<BTreeSet<usize>> {
        let total = self.cpus.len();
        if n == 0 || total == 0 {
            return vec![];
        }
        let base = total / n;
        let overlap = ((base as f64) * overlap_frac).ceil() as usize;
        let stride = if base > overlap { base - overlap } else { 1 };
        (0..n)
            .map(|i| {
                let start = (i * stride) % total;
                (0..base.max(1))
                    .map(|j| self.cpus[(start + j) % total])
                    .collect()
            })
            .collect()
    }

    pub fn cpuset_string(cpus: &BTreeSet<usize>) -> String {
        if cpus.is_empty() {
            return String::new();
        }
        let sorted: Vec<usize> = cpus.iter().copied().collect();
        let mut ranges = Vec::new();
        let (mut start, mut end) = (sorted[0], sorted[0]);
        for &cpu in &sorted[1..] {
            if cpu == end + 1 {
                end = cpu;
            } else {
                ranges.push(if start == end {
                    format!("{start}")
                } else {
                    format!("{start}-{end}")
                });
                start = cpu;
                end = cpu;
            }
        }
        ranges.push(if start == end {
            format!("{start}")
        } else {
            format!("{start}-{end}")
        });
        ranges.join(",")
    }

    #[cfg(test)]
    pub fn synthetic(num_cpus: usize, num_llcs: usize) -> Self {
        let cpus: Vec<usize> = (0..num_cpus).collect();
        let per_llc = num_cpus / num_llcs;
        let llcs: Vec<LlcInfo> = (0..num_llcs)
            .map(|i| {
                let start = i * per_llc;
                let end = if i == num_llcs - 1 {
                    num_cpus
                } else {
                    (i + 1) * per_llc
                };
                LlcInfo {
                    cpus: (start..end).collect(),
                    numa_node: i,
                }
            })
            .collect();
        let numa_nodes = (0..num_llcs).collect();
        Self {
            cpus,
            llcs,
            numa_nodes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuset_string_empty() {
        assert_eq!(TestTopology::cpuset_string(&BTreeSet::new()), "");
    }

    #[test]
    fn cpuset_string_single() {
        assert_eq!(TestTopology::cpuset_string(&[3].into_iter().collect()), "3");
    }

    #[test]
    fn cpuset_string_range() {
        assert_eq!(
            TestTopology::cpuset_string(&[0, 1, 2, 3].into_iter().collect()),
            "0-3"
        );
    }

    #[test]
    fn cpuset_string_gaps() {
        assert_eq!(
            TestTopology::cpuset_string(&[0, 1, 3, 5, 6, 7].into_iter().collect()),
            "0-1,3,5-7"
        );
    }

    #[test]
    fn synthetic_topology() {
        let t = TestTopology::synthetic(8, 2);
        assert_eq!(t.total_cpus(), 8);
        assert_eq!(t.num_llcs(), 2);
        assert_eq!(t.cpus_in_llc(0), &[0, 1, 2, 3]);
        assert_eq!(t.cpus_in_llc(1), &[4, 5, 6, 7]);
    }

    #[test]
    fn overlapping_cpusets_basic() {
        let t = TestTopology::synthetic(8, 1);
        let sets = t.overlapping_cpusets(2, 0.5);
        assert_eq!(sets.len(), 2);
        for s in &sets {
            assert_eq!(s.len(), 4);
        }
        let overlap: BTreeSet<usize> = sets[0].intersection(&sets[1]).copied().collect();
        assert!(!overlap.is_empty());
    }

    #[test]
    fn overlapping_cpusets_no_overlap() {
        let t = TestTopology::synthetic(8, 1);
        let sets = t.overlapping_cpusets(2, 0.0);
        assert_eq!(sets.len(), 2);
        let overlap: BTreeSet<usize> = sets[0].intersection(&sets[1]).copied().collect();
        assert!(overlap.is_empty());
    }

    #[test]
    fn split_by_llc() {
        let t = TestTopology::synthetic(8, 2);
        let splits = t.split_by_llc();
        assert_eq!(splits.len(), 2);
        assert_eq!(splits[0], [0, 1, 2, 3].into_iter().collect());
        assert_eq!(splits[1], [4, 5, 6, 7].into_iter().collect());
    }

    #[test]
    fn llc_aligned_cpuset() {
        let t = TestTopology::synthetic(8, 2);
        assert_eq!(t.llc_aligned_cpuset(0), [0, 1, 2, 3].into_iter().collect());
        assert_eq!(t.llc_aligned_cpuset(1), [4, 5, 6, 7].into_iter().collect());
    }

    #[test]
    fn overlapping_cpusets_zero_n() {
        let t = TestTopology::synthetic(8, 1);
        assert!(t.overlapping_cpusets(0, 0.5).is_empty());
    }

    #[test]
    fn synthetic_single_llc() {
        let t = TestTopology::synthetic(4, 1);
        assert_eq!(t.num_llcs(), 1);
        assert_eq!(t.total_cpus(), 4);
        assert_eq!(t.num_numa_nodes(), 1);
        assert_eq!(t.all_cpus(), &[0, 1, 2, 3]);
    }

    #[test]
    fn synthetic_many_llcs() {
        let t = TestTopology::synthetic(16, 4);
        assert_eq!(t.num_llcs(), 4);
        for i in 0..4 {
            assert_eq!(t.cpus_in_llc(i).len(), 4);
        }
    }

    #[test]
    fn cpuset_string_two_ranges() {
        assert_eq!(
            TestTopology::cpuset_string(&[0, 1, 2, 5, 6, 7].into_iter().collect()),
            "0-2,5-7"
        );
    }

    #[test]
    fn cpuset_string_all_isolated() {
        assert_eq!(
            TestTopology::cpuset_string(&[1, 3, 5].into_iter().collect()),
            "1,3,5"
        );
    }

    #[test]
    fn cpuset_string_large_range() {
        let cpus: BTreeSet<usize> = (0..128).collect();
        assert_eq!(TestTopology::cpuset_string(&cpus), "0-127");
    }

    #[test]
    fn overlapping_cpusets_single_set() {
        let t = TestTopology::synthetic(8, 1);
        let sets = t.overlapping_cpusets(1, 0.5);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].len(), 8);
    }

    #[test]
    fn split_by_llc_single() {
        let t = TestTopology::synthetic(4, 1);
        let splits = t.split_by_llc();
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].len(), 4);
    }
}
