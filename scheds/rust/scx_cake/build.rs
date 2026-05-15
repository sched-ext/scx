// SPDX-License-Identifier: GPL-2.0
// Build script for scx_cake - compiles BPF code and generates bindings
//
// Compile-time hardware scaling (Rule 54): detect the build host's CPU and
// LLC topology from sysfs and pass -DCAKE_MAX_CPUS=N -DCAKE_MAX_LLCS=N to
// BPF Clang.  All BPF arrays, loops, and masks compile to the exact hardware
// size — zero wasted BSS, zero dead loop iterations.

/// Detect online logical CPU count from /sys/devices/system/cpu/online.
/// Returns next power-of-2, clamped [16, 512].
///
/// Parses range format: "0-15" → 16, "0-7,16-23" → 24 → next_pow2 = 32.
fn detect_max_cpus() -> u32 {
    let online =
        std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_else(|_| "0-7".into());
    let max_id = online
        .trim()
        .split(',')
        .filter_map(|range| range.split('-').next_back()?.parse::<u32>().ok())
        .max()
        .unwrap_or(7);
    (max_id + 1).next_power_of_two().clamp(16, 512)
}

/// Detect unique LLC (L3 cache) count from sysfs.
/// Returns next power-of-2, clamped [1, 16].
///
/// Reads /sys/devices/system/cpu/cpu*/cache/index3/id for each online CPU,
/// collects unique LLC IDs.  Falls back to 1 if sysfs unavailable.
fn detect_max_llcs() -> u32 {
    let mut ids = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("cpu") && name[3..].chars().all(|c| c.is_ascii_digit()) {
                let path = entry.path().join("cache/index3/id");
                if let Ok(id) = std::fs::read_to_string(&path) {
                    if let Ok(n) = id.trim().parse::<u32>() {
                        ids.insert(n);
                    }
                }
            }
        }
    }
    (ids.len() as u32).max(1).next_power_of_two().clamp(1, 16)
}

/// Detect if the system has heterogeneous (P/E) cores.
/// Reads cpu_capacity from sysfs — if any CPU has a different capacity,
/// the system has hybrid cores (Intel big.LITTLE or similar).
/// AMD SMP: all CPUs report 1024 → returns false → zero overhead.
fn detect_hybrid() -> bool {
    let mut first_cap: Option<u32> = None;
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("cpu") && name[3..].chars().all(|c| c.is_ascii_digit()) {
                let path = entry.path().join("cpu_capacity");
                if let Ok(cap_str) = std::fs::read_to_string(&path) {
                    if let Ok(cap) = cap_str.trim().parse::<u32>() {
                        match first_cap {
                            None => first_cap = Some(cap),
                            Some(first) if cap != first => return true,
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    false
}

fn profile_quantum_us(profile: &str) -> Option<u64> {
    match profile {
        "esports" => Some(750),
        "gaming" => Some(1000),
        "balanced" => Some(2000),
        "legacy" => Some(4000),
        _ => None,
    }
}

fn baked_profile() -> (String, u64) {
    let profile = std::env::var("SCX_CAKE_PROFILE")
        .unwrap_or_else(|_| "gaming".into())
        .to_ascii_lowercase()
        .replace('_', "-");
    let profile_quantum = profile_quantum_us(&profile).unwrap_or_else(|| {
        panic!("SCX_CAKE_PROFILE must be one of esports, gaming, balanced, legacy (got {profile})")
    });
    let quantum = std::env::var("SCX_CAKE_QUANTUM_US")
        .ok()
        .map(|value| {
            value.parse::<u64>().unwrap_or_else(|_| {
                panic!("SCX_CAKE_QUANTUM_US must be an integer microsecond value (got {value})")
            })
        })
        .unwrap_or(profile_quantum);
    assert!(quantum > 0, "SCX_CAKE_QUANTUM_US must be greater than 0");

    (profile, quantum)
}

fn baked_queue_policy() -> (&'static str, u32) {
    let policy = std::env::var("SCX_CAKE_QUEUE_POLICY")
        .unwrap_or_else(|_| "local".into())
        .to_ascii_lowercase()
        .replace('_', "-");
    match policy.as_str() {
        "local" => ("local", 0),
        "llc" | "llc-vtime" => ("llc-vtime", 1),
        _ => panic!("SCX_CAKE_QUEUE_POLICY must be one of local, llc-vtime (got {policy})"),
    }
}

fn baked_storm_guard() -> (&'static str, u32) {
    let mode = std::env::var("SCX_CAKE_STORM_GUARD")
        .unwrap_or_else(|_| "shield".into())
        .to_ascii_lowercase()
        .replace('_', "-");
    match mode.as_str() {
        "off" => ("off", 0),
        "shadow" => ("shadow", 1),
        "shield" => ("shield", 2),
        "full" => ("full", 3),
        _ => panic!("SCX_CAKE_STORM_GUARD must be one of off, shadow, shield, full (got {mode})"),
    }
}

fn baked_busy_wake_kick() -> (&'static str, u32) {
    let mode = std::env::var("SCX_CAKE_BUSY_WAKE_KICK")
        .unwrap_or_else(|_| "policy".into())
        .to_ascii_lowercase()
        .replace('_', "-");
    match mode.as_str() {
        "policy" => ("policy", 0),
        "preempt" => ("preempt", 1),
        "idle" => ("idle", 2),
        _ => {
            panic!("SCX_CAKE_BUSY_WAKE_KICK must be one of policy, preempt, idle (got {mode})")
        }
    }
}

fn baked_bool(name: &str, default: bool) -> (&'static str, u32, bool) {
    let value = std::env::var(name)
        .unwrap_or_else(|_| if default { "on" } else { "off" }.into())
        .to_ascii_lowercase()
        .replace('_', "-");

    match value.as_str() {
        "1" | "true" | "yes" | "on" | "enabled" => ("on", 1, true),
        "0" | "false" | "no" | "off" | "disabled" => ("off", 0, false),
        _ => panic!("{name} must be one of on/off, true/false, 1/0 (got {value})"),
    }
}

fn main() {
    // Detect build profile: release builds pass CAKE_RELEASE=1 to BPF Clang,
    // which eliminates ALL stats/telemetry code at compile time (zero overhead).
    // Debug builds retain full --verbose/TUI support via volatile RODATA toggle.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let base_flags = "-O2 -mcpu=v4 -fno-stack-protector -fno-asynchronous-unwind-tables -Wno-missing-declarations";

    // Compile-time hardware scaling: detect CPU/LLC topology and pass to BPF.
    let max_cpus = detect_max_cpus();
    let max_llcs = detect_max_llcs();
    let is_single_llc = max_llcs == 1;
    let has_hybrid = detect_hybrid();
    let enable_locality_experiments = profile != "release";
    let enable_hot_telemetry = profile != "release";
    let (baked_profile, baked_quantum_us) = baked_profile();
    let (baked_queue_policy, baked_queue_policy_value) = baked_queue_policy();
    let (baked_storm_guard, baked_storm_guard_value) = baked_storm_guard();
    let (baked_busy_wake_kick, baked_busy_wake_kick_value) = baked_busy_wake_kick();
    let (baked_learned_locality, baked_learned_locality_value, release_learned_locality) =
        baked_bool("SCX_CAKE_LEARNED_LOCALITY", false);
    let (baked_wake_chain_locality, baked_wake_chain_locality_value, release_wake_chain_locality) =
        baked_bool("SCX_CAKE_WAKE_CHAIN_LOCALITY", false);
    let needs_arena = if profile == "release" {
        release_learned_locality || release_wake_chain_locality
    } else {
        enable_hot_telemetry || enable_locality_experiments
    };

    // Generate Rust constants file — avoids unstable option_env! str matching.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let constants_path = std::path::Path::new(&out_dir).join("cake_constants.rs");
    std::fs::write(
        &constants_path,
        format!(
            "// Auto-generated by build.rs — compile-time hardware scaling\n\
             pub const MAX_CPUS: usize = {};\n\
             pub const MAX_LLCS: usize = {};\n\
             pub const MASK_WORDS: usize = {}usize.div_ceil(64);\n\
             pub const MAX_CORES: usize = {} / 2;\n\
             pub const BAKED_PROFILE: &str = {:?};\n\
             pub const BAKED_QUANTUM_US: u64 = {};\n\
             pub const BAKED_QUEUE_POLICY: &str = {:?};\n\
             pub const BAKED_QUEUE_POLICY_VALUE: u32 = {};\n\
             pub const BAKED_STORM_GUARD: &str = {:?};\n\
             pub const BAKED_STORM_GUARD_VALUE: u32 = {};\n\
             pub const BAKED_BUSY_WAKE_KICK: &str = {:?};\n\
             pub const BAKED_BUSY_WAKE_KICK_VALUE: u32 = {};\n\
             pub const BAKED_LEARNED_LOCALITY: &str = {:?};\n\
             pub const BAKED_LEARNED_LOCALITY_VALUE: u32 = {};\n\
             pub const BAKED_WAKE_CHAIN_LOCALITY: &str = {:?};\n\
             pub const BAKED_WAKE_CHAIN_LOCALITY_VALUE: u32 = {};\n",
            max_cpus,
            max_llcs,
            max_cpus,
            max_cpus,
            baked_profile,
            baked_quantum_us,
            baked_queue_policy,
            baked_queue_policy_value,
            baked_storm_guard,
            baked_storm_guard_value,
            baked_busy_wake_kick,
            baked_busy_wake_kick_value,
            baked_learned_locality,
            baked_learned_locality_value,
            baked_wake_chain_locality,
            baked_wake_chain_locality_value
        ),
    )
    .expect("Failed to write cake_constants.rs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_PROFILE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_QUANTUM_US");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_QUEUE_POLICY");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_STORM_GUARD");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_BUSY_WAKE_KICK");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_LEARNED_LOCALITY");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_WAKE_CHAIN_LOCALITY");
    println!("cargo:rerun-if-changed=src/bpf/telemetry.bpf.h");
    println!("cargo:rerun-if-changed=src/bpf/debug_events.bpf.h");
    println!("cargo:rerun-if-changed=src/bpf/iter.bpf.h");

    // Register custom cfg names to suppress unexpected_cfgs warnings
    println!("cargo::rustc-check-cfg=cfg(cake_bpf_release)");
    println!("cargo::rustc-check-cfg=cfg(cake_has_hybrid)");
    println!("cargo::rustc-check-cfg=cfg(cake_single_llc)");
    println!("cargo::rustc-check-cfg=cfg(cake_locality_experiments)");
    println!("cargo::rustc-check-cfg=cfg(cake_hot_telemetry)");
    println!("cargo::rustc-check-cfg=cfg(cake_needs_arena)");

    // Emit rustc-cfg flags for true conditional compilation (Rust #[cfg] guards)
    if has_hybrid {
        println!("cargo:rustc-cfg=cake_has_hybrid");
    }
    if is_single_llc {
        println!("cargo:rustc-cfg=cake_single_llc");
    }

    // Build cflags with hardware gates
    let mut cflags = format!(
        "{} -DCAKE_MAX_CPUS={} -DCAKE_MAX_LLCS={} -DCAKE_QUANTUM_NS={} -DCAKE_QUEUE_POLICY_VALUE={} -DCAKE_STORM_GUARD_VALUE={} -DCAKE_BUSY_WAKE_KICK_VALUE={} -DCAKE_LEARNED_LOCALITY_VALUE={} -DCAKE_WAKE_CHAIN_LOCALITY_VALUE={}",
        base_flags,
        max_cpus,
        max_llcs,
        baked_quantum_us * 1000,
        baked_queue_policy_value,
        baked_storm_guard_value,
        baked_busy_wake_kick_value,
        baked_learned_locality_value,
        baked_wake_chain_locality_value
    );
    if profile == "release" {
        cflags.push_str(" -DCAKE_RELEASE=1");
        println!("cargo:rustc-cfg=cake_bpf_release");
    }
    if profile != "release" && enable_locality_experiments {
        cflags.push_str(" -DCAKE_LOCALITY_EXPERIMENTS=1");
        println!("cargo:rustc-cfg=cake_locality_experiments");
    } else {
        cflags.push_str(" -DCAKE_LOCALITY_EXPERIMENTS=0");
    }
    if profile != "release" && enable_hot_telemetry {
        cflags.push_str(" -DCAKE_HOT_TELEMETRY=1");
        println!("cargo:rustc-cfg=cake_hot_telemetry");
    } else {
        cflags.push_str(" -DCAKE_HOT_TELEMETRY=0");
    }
    if needs_arena {
        cflags.push_str(" -DCAKE_NEEDS_ARENA=1");
        println!("cargo:rustc-cfg=cake_needs_arena");
    } else {
        cflags.push_str(" -DCAKE_NEEDS_ARENA=0");
    }
    // Gate 1: Single-LLC — eliminates cake_tick body from verifier
    if is_single_llc {
        cflags.push_str(" -DCAKE_SINGLE_LLC=1");
    }
    // Gate 2: Hybrid cores — eliminates Gate 2 scan loop + RODATA arrays from verifier
    if has_hybrid {
        cflags.push_str(" -DCAKE_HAS_HYBRID=1");
    }

    // Log detected topology + gates during build
    println!(
        "scx_cake [info]: CAKE_MAX_CPUS={} CAKE_MAX_LLCS={} SINGLE_LLC={} HAS_HYBRID={} BAKED_PROFILE={} BAKED_QUANTUM_US={} BAKED_QUEUE_POLICY={} BAKED_STORM_GUARD={} BAKED_BUSY_WAKE_KICK={} BAKED_LEARNED_LOCALITY={} BAKED_WAKE_CHAIN_LOCALITY={} NEEDS_ARENA={}",
        max_cpus,
        max_llcs,
        is_single_llc,
        has_hybrid,
        baked_profile,
        baked_quantum_us,
        baked_queue_policy,
        baked_storm_guard,
        baked_busy_wake_kick,
        baked_learned_locality,
        baked_wake_chain_locality,
        needs_arena
    );

    std::env::set_var("BPF_EXTRA_CFLAGS_PRE_INCL", &cflags);
    let mut builder = scx_cargo::BpfBuilder::new().unwrap();
    builder
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/cake.bpf.c", "bpf");

    if needs_arena {
        builder
            .add_source("../../../lib/arena.bpf.c")
            .add_source("../../../lib/rbtree.bpf.c")
            .add_source("../../../lib/atq.bpf.c")
            .add_source("../../../lib/sdt_alloc.bpf.c")
            .add_source("../../../lib/sdt_task.bpf.c")
            .add_source("../../../lib/bitmap.bpf.c")
            .add_source("../../../lib/cpumask.bpf.c")
            .add_source("../../../lib/topology.bpf.c");
    }

    builder.compile_link_gen().unwrap();
}
