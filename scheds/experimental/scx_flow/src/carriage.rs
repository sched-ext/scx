// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// Topology discovery: reads per-CPU max frequencies, LLC IDs, and SMT
// status from sysfs and writes them into BPF BSS arrays.

use std::path::Path;

use anyhow::{Context, Result};
use log::info;

use scx_utils::Topology;

pub fn init_topology(skel: &mut crate::BpfSkel<'_>) -> Result<()> {
    let topo = Topology::new().context("Failed to read CPU topology")?;
    let nr_cpus = topo.all_cpus.len();
    let bss = skel.maps.bss_data.as_mut()
        .context("bss_data missing — BPF object has no .bss section")?;

    info!(
        "Discovered {} CPUs — reading max frequencies, LLC topology, SMT",
        nr_cpus
    );

    let mut core_to_cpus: Vec<Vec<usize>> = vec![Vec::new(); 1024];
    let mut system_total_khz: u64 = 0;

    for (id, cpu) in &topo.all_cpus {
        let freq_khz = cpu.max_freq as u64;
        let llc_id = read_cpu_llc_id(*id);
        let core_id = read_cpu_core_id(*id);

        bss.per_cpu_max_freq_khz[*id] = freq_khz;
        bss.per_cpu_llc_id[*id] = llc_id;

        if core_id < 1024 {
            core_to_cpus[core_id].push(*id);
        }

        info!(
            "  CPU {:3}: max_freq = {:>6} MHz, LLC = {}, core_id = {}",
            id, freq_khz / 1000, llc_id, core_id,
        );
    }

    /* Set per_cpu_sibling_count for all CPUs and mark SMT secondaries.
     * The first CPU per core_id is primary; subsequent ones are secondary.
     * sibling_count is set for ALL CPUs (including non-SMT, where it's 1)
     * so the bandwidth model works correctly for every CPU. */
    for (core_id, cpus) in core_to_cpus.iter().enumerate() {
        let count = cpus.len();
        if count > 1 {
            for (j, &cpu_id) in cpus.iter().enumerate() {
                bss.per_cpu_sibling_count[cpu_id] = count as u64;
                if j == 0 {
                    info!("  CPU {:3}: primary (core {}: {} CPUs)",
                          cpu_id, core_id, count);
                } else {
                    bss.per_cpu_is_smt[cpu_id] = 1;
                    info!("  CPU {:3}: SMT sibling (core {})",
                          cpu_id, core_id);
                }
            }
        } else if count == 1 {
            bss.per_cpu_sibling_count[cpus[0]] = 1;
        }
    }

    for (id, cpu) in &topo.all_cpus {
        let freq_khz = cpu.max_freq as u64;
        let core_id = read_cpu_core_id(*id);
        let siblings = if core_id < 1024 { core_to_cpus[core_id].len() } else { 1 };
        let thread_bw = if siblings > 1 { freq_khz / siblings as u64 } else { freq_khz };
        system_total_khz += thread_bw;
    }
    bss.system_total_khz = system_total_khz;

    info!(
        "  System total effective bandwidth: {} MHz ({} cores, SMT halved)",
        system_total_khz / 1000, nr_cpus,
    );

    Ok(())
}

fn read_cpu_llc_id(cpu: usize) -> u64 {
    let p = format!("/sys/devices/system/cpu/cpu{}/cache/index3/id", cpu);
    let path = Path::new(&p);
    if path.exists() {
        return std::fs::read_to_string(path)
            .ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    }
    let fb = format!("/sys/devices/system/cpu/cpu{}/topology/llc_id", cpu);
    let fb_path = Path::new(&fb);
    if fb_path.exists() {
        return std::fs::read_to_string(fb_path)
            .ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    }
    0
}

fn read_cpu_core_id(cpu: usize) -> usize {
    let p = format!("/sys/devices/system/cpu/cpu{}/topology/core_id", cpu);
    let path = Path::new(&p);
    if !path.exists() {
        log::warn!("CPU {}: topology/core_id not found", cpu);
        return 0;
    }
    std::fs::read_to_string(path)
        .ok().and_then(|s| s.trim().parse::<usize>().ok()).unwrap_or(0)
}
