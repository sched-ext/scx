// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

fn detected_cache_domains() -> usize {
    if let Ok(forced) = env::var("SCX_CAKE_FORCE_NR_CCDS") {
        return forced
            .parse::<usize>()
            .ok()
            .filter(|nr| *nr > 0)
            .expect("SCX_CAKE_FORCE_NR_CCDS must be a positive integer");
    }

    let mut domains = BTreeSet::new();
    let Ok(cpus) = fs::read_dir(Path::new("/sys/devices/system/cpu")) else {
        return 1;
    };
    for cpu in cpus.flatten() {
        let name = cpu.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name
            .strip_prefix("cpu")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_digit()))
        {
            continue;
        }
        let Ok(indices) = fs::read_dir(cpu.path().join("cache")) else {
            continue;
        };
        for index in indices.flatten() {
            if fs::read_to_string(index.path().join("level"))
                .ok()
                .is_some_and(|level| level.trim() == "3")
            {
                if let Ok(shared) = fs::read_to_string(index.path().join("shared_cpu_list")) {
                    domains.insert(shared.trim().to_owned());
                }
            }
        }
    }
    domains.len().max(1)
}

fn detected_possible_cpus() -> usize {
    if let Ok(forced) = env::var("SCX_CAKE_FORCE_NR_CPUS") {
        return forced
            .parse::<usize>()
            .ok()
            .filter(|nr| *nr > 0)
            .expect("SCX_CAKE_FORCE_NR_CPUS must be a positive integer");
    }

    let Ok(cpus) = fs::read_dir("/sys/devices/system/cpu") else {
        return 1024;
    };
    cpus.flatten()
        .filter_map(|cpu| cpu.file_name().to_str().map(str::to_owned))
        .filter_map(|name| name.strip_prefix("cpu")?.parse::<usize>().ok())
        .max()
        .map_or(1024, |max_id| max_id + 1)
}

fn main() {
    let nr_ccds = detected_cache_domains();
    let nr_cpus = detected_possible_cpus();
    let mdbls_stage = env::var("SCX_CAKE_MDBLS_STAGE")
        .unwrap_or_else(|_| "0".to_owned())
        .parse::<u8>()
        .ok()
        .filter(|stage| *stage <= 3)
        .expect("SCX_CAKE_MDBLS_STAGE must be 0, 1, 2, or 3");
    let mdbls_preempt = env::var("SCX_CAKE_MDBLS_PREEMPT")
        .unwrap_or_else(|_| "1".to_owned())
        .parse::<u8>()
        .ok()
        .filter(|mode| *mode <= 2)
        .expect("SCX_CAKE_MDBLS_PREEMPT must be 0 (off), 1 (act), or 2 (shadow)");
    let mdbls_slice = env::var("SCX_CAKE_MDBLS_SLICE")
        .unwrap_or_else(|_| "1".to_owned())
        .parse::<u8>()
        .ok()
        .filter(|mode| *mode <= 2)
        .expect("SCX_CAKE_MDBLS_SLICE must be 0 (off), 1 (act), or 2 (shadow)");
    let mdbls_telemetry = env::var("SCX_CAKE_MDBLS_TELEMETRY")
        .unwrap_or_else(|_| "0".to_owned())
        .parse::<u8>()
        .ok()
        .filter(|enabled| *enabled <= 1)
        .expect("SCX_CAKE_MDBLS_TELEMETRY must be 0 or 1");
    let irq_shadow_mode = env::var("SCX_CAKE_IRQ_SHADOW_MODE")
        .unwrap_or_else(|_| "0".to_owned())
        .parse::<u8>()
        .ok()
        .filter(|mode| *mode <= 2)
        .expect("SCX_CAKE_IRQ_SHADOW_MODE must be 0 (off), 1 (cost control), or 2 (observer)");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_FORCE_NR_CCDS");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_FORCE_NR_CPUS");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_MDBLS_STAGE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_MDBLS_PREEMPT");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_MDBLS_SLICE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_MDBLS_TELEMETRY");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_IRQ_SHADOW_MODE");
    println!("cargo:rustc-check-cfg=cfg(cake_multi_ccd)");
    println!("cargo:rustc-check-cfg=cfg(cake_mdbls_telemetry)");
    println!("cargo:rustc-check-cfg=cfg(cake_irq_shadow)");
    println!("cargo:rustc-check-cfg=cfg(cake_irq_shadow_observer)");
    if nr_ccds > 1 {
        println!("cargo:rustc-cfg=cake_multi_ccd");
    }
    if mdbls_telemetry == 1 {
        println!("cargo:rustc-cfg=cake_mdbls_telemetry");
    }
    if irq_shadow_mode > 0 {
        println!("cargo:rustc-cfg=cake_irq_shadow");
    }
    if irq_shadow_mode == 2 {
        println!("cargo:rustc-cfg=cake_irq_shadow_observer");
    }

    let mut post = env::var("BPF_EXTRA_CFLAGS_POST_INCL").unwrap_or_default();
    if !post.is_empty() {
        post.push(' ');
    }
    post.push_str(&format!(
        "-DCAKE_NR_CCDS={nr_ccds} -DCAKE_NR_CPUS={nr_cpus} -DCAKE_MDBLS_STAGE={mdbls_stage} -DCAKE_MDBLS_PREEMPT={mdbls_preempt} -DCAKE_MDBLS_SLICE={mdbls_slice} -DCAKE_MDBLS_TELEMETRY={mdbls_telemetry} -DCAKE_IRQ_SHADOW_MODE={irq_shadow_mode}"
    ));
    env::set_var("BPF_EXTRA_CFLAGS_POST_INCL", post);

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/cake.bpf.c", "bpf")
        .build()
        .unwrap();
}
