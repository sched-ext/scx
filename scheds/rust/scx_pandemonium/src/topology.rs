// PANDEMONIUM CPU CACHE TOPOLOGY
// PARSES SYSFS AT STARTUP, POPULATES BPF MAP FOR CACHE-AWARE DISPATCH
//
// BPF dispatch() USES THE CACHE DOMAIN MAP TO PREFER TASKS THAT LAST
// RAN ON THE SAME CPU OR AN L2 SIBLING. THIS PRESERVES CACHE WARMTH
// AND REDUCES THE THROUGHPUT GAP CAUSED BY BLIND NODE-DSQ CONSUMPTION.

use anyhow::Result;

use crate::scheduler::Scheduler;

pub struct CpuTopology {
    pub nr_cpus: usize,
    pub l2_domain: Vec<u32>,      // l2_domain[cpu] = group_id
    pub l2_groups: Vec<Vec<u32>>, // l2_groups[group_id] = [cpu, ...]
}

impl CpuTopology {
    pub fn detect(nr_cpus: usize) -> Result<Self> {
        let mut l2_domain = vec![0u32; nr_cpus];
        let mut seen_groups: Vec<Vec<u32>> = Vec::new();

        for cpu in 0..nr_cpus {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index2/shared_cpu_list",
                cpu
            );
            let content = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => {
                    // CPU MIGHT BE OFFLINE OR HAVE NO L2 INFO -- ASSIGN OWN GROUP
                    l2_domain[cpu] = cpu as u32;
                    continue;
                }
            };

            let members = parse_cpu_list(content.trim());

            // CHECK IF THIS GROUP ALREADY EXISTS
            let group_id = match seen_groups.iter().position(|g| *g == members) {
                Some(id) => id as u32,
                None => {
                    let id = seen_groups.len() as u32;
                    seen_groups.push(members.clone());
                    id
                }
            };

            l2_domain[cpu] = group_id;
        }

        Ok(Self {
            nr_cpus,
            l2_domain,
            l2_groups: seen_groups,
        })
    }

    // WRITE L2 DOMAIN MAP TO BPF ARRAY VIA SCHEDULER
    pub fn populate_bpf_map(&self, sched: &Scheduler) -> Result<()> {
        for cpu in 0..self.nr_cpus {
            sched.write_cache_domain(cpu as u32, self.l2_domain[cpu])?;
        }
        Ok(())
    }

    // WRITE L2 SIBLINGS FLAT ARRAY TO BPF MAP
    // l2_siblings[group_id * 8 + slot] = cpu_id, SENTINEL u32::MAX MARKS END
    pub fn populate_l2_siblings_map(&self, sched: &Scheduler) -> Result<()> {
        const MAX_L2_SIBLINGS: usize = 8;
        for (gid, members) in self.l2_groups.iter().enumerate() {
            for (slot, &cpu) in members.iter().enumerate().take(MAX_L2_SIBLINGS) {
                sched.write_l2_sibling(gid as u32, slot as u32, cpu)?;
            }
            if members.len() < MAX_L2_SIBLINGS {
                sched.write_l2_sibling(gid as u32, members.len() as u32, u32::MAX)?;
            }
        }
        Ok(())
    }

    pub fn log_summary(&self) {
        for (gid, members) in self.l2_groups.iter().enumerate() {
            let cpus: Vec<String> = members.iter().map(|c| c.to_string()).collect();
            log_info!("L2 GROUP {}: [{}]", gid, cpus.join(","));
        }
        log_info!(
            "L2 GROUPS: {} across {} CPUs",
            self.l2_groups.len(),
            self.nr_cpus
        );
    }
}

// PARSE KERNEL CPU LIST FORMAT: "0,6" or "0-2,6-8" or "3"
fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut result = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                for cpu in s..=e {
                    result.push(cpu);
                }
            }
        } else if let Ok(cpu) = part.parse::<u32>() {
            result.push(cpu);
        }
    }
    result.sort();
    result.dedup();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single() {
        assert_eq!(parse_cpu_list("3"), vec![3]);
    }

    #[test]
    fn parse_comma() {
        assert_eq!(parse_cpu_list("0,6"), vec![0, 6]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_cpu_list("0-2,6-8"), vec![0, 1, 2, 6, 7, 8]);
    }

    #[test]
    fn parse_mixed() {
        assert_eq!(parse_cpu_list("0-2,5,9-11"), vec![0, 1, 2, 5, 9, 10, 11]);
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
    }

    #[test]
    fn detect_topology() {
        // RUNS ON ANY MACHINE -- VERIFIES SANE OUTPUT
        let nr_cpus = std::fs::read_dir("/sys/devices/system/cpu")
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .map(|e| {
                        e.file_name().to_string_lossy().starts_with("cpu")
                            && e.file_name().to_string_lossy()[3..].parse::<u32>().is_ok()
                    })
                    .unwrap_or(false)
            })
            .count();

        if nr_cpus == 0 {
            return; // NO CPUS VISIBLE (CONTAINER?)
        }

        let topo = CpuTopology::detect(nr_cpus).unwrap();
        assert_eq!(topo.nr_cpus, nr_cpus);
        assert_eq!(topo.l2_domain.len(), nr_cpus);

        // EVERY CPU MUST HAVE A VALID GROUP ID
        let max_group = topo.l2_groups.len() as u32;
        for cpu in 0..nr_cpus {
            assert!(
                topo.l2_domain[cpu] < max_group || topo.l2_domain[cpu] == cpu as u32,
                "CPU {} has invalid l2 group {}",
                cpu,
                topo.l2_domain[cpu]
            );
        }

        // AT LEAST ONE GROUP MUST EXIST
        assert!(!topo.l2_groups.is_empty());
    }
}
