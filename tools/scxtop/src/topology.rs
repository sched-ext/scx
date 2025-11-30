// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TopoKind {
    L1 = 0,
    L2 = 1,
    L3 = 2,
    Numa = 3,
    Common = 4, // Fake grouping of all CPUs
}

const NR_TOPO_KIND: usize = 5;

#[derive(Debug, Clone)]
struct CpuTopo {
    cpu: usize,
    group: i32,
    topo: [i64; NR_TOPO_KIND],
}

impl CpuTopo {
    fn new(cpu: usize) -> Self {
        Self {
            cpu,
            group: -1,
            topo: [-1; NR_TOPO_KIND],
        }
    }
}

/// Union-Find set for topology grouping
#[derive(Debug, Clone)]
struct UfSet {
    id: usize,
    cnt: usize,
}

impl UfSet {
    fn new(id: usize) -> Self {
        Self { id, cnt: 1 }
    }
}

#[derive(Clone)]
struct UnionFind {
    sets: Vec<UfSet>,
}

impl UnionFind {
    fn new(size: usize) -> Self {
        Self {
            sets: (0..size).map(UfSet::new).collect(),
        }
    }

    fn find(&mut self, id: usize) -> usize {
        if self.sets[id].id == id {
            return id;
        }
        self.sets[id].id = self.find(self.sets[id].id);
        self.sets[id].id
    }

    fn find_count(&mut self, id: usize) -> usize {
        let root = self.find(id);
        self.sets[root].cnt
    }

    /// Returns true if sets were disjoint
    fn union(&mut self, a: usize, b: usize) -> bool {
        let sa = self.find(a);
        let sb = self.find(b);

        if sa == sb {
            return false;
        }

        self.sets[sa].id = sb;
        self.sets[sb].cnt += self.sets[sa].cnt;
        true
    }
}

fn parse_cpu_list(path: &Path) -> Result<Vec<bool>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read CPU list from {}", path.display()))?;

    let content = content.trim();
    if content.is_empty() {
        return Ok(vec![]);
    }

    // Find max CPU to size the vector
    let mut max_cpu = 0;
    for range in content.split(',') {
        let range = range.trim();
        if let Some((_, end)) = range.split_once('-') {
            let end_cpu: usize = end.parse()?;
            max_cpu = max_cpu.max(end_cpu);
        } else {
            let cpu: usize = range.parse()?;
            max_cpu = max_cpu.max(cpu);
        }
    }

    let mut mask = vec![false; max_cpu + 1];

    for range in content.split(',') {
        let range = range.trim();
        if let Some((start, end)) = range.split_once('-') {
            let start_cpu: usize = start.parse()?;
            let end_cpu: usize = end.parse()?;
            for cpu in start_cpu..=end_cpu {
                if cpu < mask.len() {
                    mask[cpu] = true;
                }
            }
        } else {
            let cpu: usize = range.parse()?;
            if cpu < mask.len() {
                mask[cpu] = true;
            }
        }
    }

    Ok(mask)
}

fn determine_cpu_topology(cpu_cnt: usize) -> Result<Vec<CpuTopo>> {
    let mut topo: Vec<CpuTopo> = (0..cpu_cnt).map(CpuTopo::new).collect();

    // Set COMMON topology (all CPUs in one group)
    for cpu_topo in &mut topo {
        cpu_topo.topo[TopoKind::Common as usize] = 0;
    }

    // NUMA topology
    let mut node = 0;
    loop {
        let path = format!("/sys/devices/system/node/node{}/cpulist", node);
        if !Path::new(&path).exists() {
            break;
        }

        match parse_cpu_list(Path::new(&path)) {
            Ok(mask) => {
                for (cpu, &in_node) in mask.iter().enumerate() {
                    if in_node && cpu < cpu_cnt {
                        topo[cpu].topo[TopoKind::Numa as usize] = node as i64;
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to parse NUMA node {} CPU list: {}", node, e);
            }
        }
        node += 1;
    }

    // Cache hierarchy (L1, L2, L3)
    for (cpu, cpu_topo) in topo.iter_mut().enumerate().take(cpu_cnt) {
        let mut cache_idx = 0;
        loop {
            let type_path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index{}/type",
                cpu, cache_idx
            );

            if !Path::new(&type_path).exists() {
                break;
            }

            // Skip instruction caches
            if let Ok(cache_type) = fs::read_to_string(&type_path) {
                if cache_type.trim() == "Instruction" {
                    cache_idx += 1;
                    continue;
                }
            }

            // Get cache level
            let level_path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index{}/level",
                cpu, cache_idx
            );

            if let Ok(level_str) = fs::read_to_string(&level_path) {
                if let Ok(level) = level_str.trim().parse::<usize>() {
                    if (1..=3).contains(&level) {
                        // Get cache ID
                        let id_path = format!(
                            "/sys/devices/system/cpu/cpu{}/cache/index{}/id",
                            cpu, cache_idx
                        );

                        if let Ok(id_str) = fs::read_to_string(&id_path) {
                            if let Ok(id) = id_str.trim().parse::<i64>() {
                                let kind = match level {
                                    1 => TopoKind::L1,
                                    2 => TopoKind::L2,
                                    3 => TopoKind::L3,
                                    _ => unreachable!(),
                                };
                                cpu_topo.topo[kind as usize] = id;
                            }
                        }
                    }
                }
            }

            cache_idx += 1;
        }
    }

    Ok(topo)
}

fn topo_regroup(topo: &mut [CpuTopo], uf: &mut UnionFind) {
    // Renumber groups into 0, 1, 2, ...
    let mut next_group_id = 0;

    for i in 0..topo.len() {
        let si = uf.find(topo[i].cpu);
        topo[i].group = -1;

        for j in 0..i {
            if uf.find(topo[j].cpu) == si {
                topo[i].group = topo[j].group;
                break;
            }
        }

        if topo[i].group < 0 {
            topo[i].group = next_group_id;
            next_group_id += 1;
        }
    }
}

pub fn setup_cpu_to_ringbuf_mapping(rb_cnt: usize, cpu_cnt: usize) -> Result<Vec<u32>> {
    let mut rb_cpu_mapping = vec![0u32; cpu_cnt];

    // Determine topology
    let mut topo = match determine_cpu_topology(cpu_cnt) {
        Ok(t) => t,
        Err(e) => {
            log::warn!(
                "Failed to determine CPU topology: {}, falling back to modulo-based distribution",
                e
            );
            for (i, rb_mapping) in rb_cpu_mapping.iter_mut().enumerate().take(cpu_cnt) {
                *rb_mapping = (i % rb_cnt) as u32;
            }
            return Ok(rb_cpu_mapping);
        }
    };

    // Sort by topology (NUMA -> L3 -> L2 -> L1 -> CPU)
    topo.sort_by(|a, b| {
        for k in (0..NR_TOPO_KIND).rev() {
            if a.topo[k] != b.topo[k] {
                return a.topo[k].cmp(&b.topo[k]);
            }
        }
        a.cpu.cmp(&b.cpu)
    });

    let mut uf = UnionFind::new(cpu_cnt);
    let mut last_uf;
    let mut set_cnt = cpu_cnt;
    let mut last_set_cnt = set_cnt;

    // Try to group by topology level (L1 -> L2 -> L3 -> NUMA)
    for k in 0..NR_TOPO_KIND {
        // Save state before this step
        last_uf = uf.clone();

        // Combine CPUs that share the same topology domain
        for i in 1..cpu_cnt {
            if topo[i].topo[k] != topo[i - 1].topo[k] {
                continue;
            }

            if uf.union(topo[i - 1].cpu, topo[i].cpu) {
                set_cnt -= 1;
            }
        }

        topo_regroup(&mut topo, &mut uf);

        if set_cnt == rb_cnt {
            // Perfect match!
            break;
        }

        if set_cnt < rb_cnt {
            // Overshot, need to balance
            uf = last_uf;
            set_cnt = last_set_cnt;

            // Restore original CPU order for balancing
            topo.sort_by_key(|t| t.cpu);

            // Balance step: merge smallest groups randomly until we hit rb_cnt
            use rand::Rng;
            let mut rng = rand::thread_rng();

            while set_cnt > rb_cnt {
                let cpu = rng.gen_range(0..cpu_cnt);
                let mut best_cpu = None;
                let mut best_cnt = usize::MAX;

                for i in 0..cpu_cnt {
                    if uf.find(i) == uf.find(cpu) {
                        continue;
                    }
                    if topo[i].topo[k] != topo[cpu].topo[k] {
                        continue;
                    }

                    let cnt = uf.find_count(i);
                    if cnt < best_cnt {
                        best_cpu = Some(i);
                        best_cnt = cnt;
                    }
                }

                if let Some(best) = best_cpu {
                    if uf.union(cpu, best) {
                        set_cnt -= 1;
                    }
                } else {
                    // No valid merge found, break to avoid infinite loop
                    break;
                }
            }

            topo_regroup(&mut topo, &mut uf);
            break;
        }

        last_set_cnt = set_cnt;
    }

    // Restore original CPU order and assign mappings
    topo.sort_by_key(|t| t.cpu);
    for i in 0..cpu_cnt {
        rb_cpu_mapping[i] = topo[i].group as u32;
    }

    log::debug!(
        "CPU to ringbuf mapping created: {} CPUs -> {} ringbufs",
        cpu_cnt,
        rb_cnt
    );
    for (cpu, &rb) in rb_cpu_mapping.iter().enumerate() {
        log::trace!(
            "CPU #{:3} (NUMA={}, L3={}, L2={}, L1={}) -> ringbuf #{}",
            cpu,
            topo[cpu].topo[TopoKind::Numa as usize],
            topo[cpu].topo[TopoKind::L3 as usize],
            topo[cpu].topo[TopoKind::L2 as usize],
            topo[cpu].topo[TopoKind::L1 as usize],
            rb
        );
    }

    Ok(rb_cpu_mapping)
}

pub fn calculate_default_ringbuf_count(cpu_cnt: usize) -> usize {
    // Heuristic: 16 CPUs per ringbuf, but at least 4 ringbufs
    let count = std::cmp::max(4, cpu_cnt.div_ceil(16));
    std::cmp::min(count, cpu_cnt)
}
