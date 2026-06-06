// SPDX-License-Identifier: GPL-2.0
// Build script for scx_cake - compiles BPF code and generates bindings
//
// Compile-time hardware scaling (Rule 54): detect the build host's CPU and
// LLC topology from sysfs and pass -DCAKE_MAX_CPUS=N -DCAKE_MAX_LLCS=N to
// BPF Clang.  All BPF arrays, loops, and masks compile to the exact hardware
// size — zero wasted BSS, zero dead loop iterations.

/// Detect online logical CPU count from /sys/devices/system/cpu/online.
///
/// Parses range format: "0-15" → 16, "0-7,16-23" → 24.
fn detect_online_cpu_count() -> u32 {
    let online =
        std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_else(|_| "0-7".into());
    let max_id = online
        .trim()
        .split(',')
        .filter_map(|range| range.split('-').next_back()?.parse::<u32>().ok())
        .max()
        .unwrap_or(7);
    max_id + 1
}

/// Detect online logical CPU count from /sys/devices/system/cpu/online.
/// Returns next power-of-2, clamped [16, 512].
fn detect_max_cpus() -> u32 {
    detect_online_cpu_count().next_power_of_two().clamp(16, 512)
}

/// Detect unique LLC (L3 cache) count from sysfs.
/// Reads /sys/devices/system/cpu/cpu*/cache/index3/id for each online CPU,
/// collects unique LLC IDs.  Falls back to 1 if sysfs unavailable.
fn detect_llc_count() -> u32 {
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
    (ids.len() as u32).max(1)
}

/// Detect unique LLC (L3 cache) count from sysfs.
/// Returns next power-of-2, clamped [1, 16].
fn detect_max_llcs() -> u32 {
    detect_llc_count().next_power_of_two().clamp(1, 16)
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
    let nr_cpus = detect_online_cpu_count();
    let nr_llcs = detect_llc_count();
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
    let (baked_release_route_pred, baked_release_route_pred_value, _release_route_pred) =
        baked_bool("SCX_CAKE_RELEASE_ROUTE_PRED", false);
    let (baked_release_confidence, baked_release_confidence_value, _release_confidence) =
        baked_bool("SCX_CAKE_RELEASE_CONFIDENCE", false);
    let (baked_release_llc_pending, baked_release_llc_pending_value, _release_llc_pending) =
        baked_bool("SCX_CAKE_RELEASE_LLC_PENDING", true);
    let (baked_release_local_waiter, baked_release_local_waiter_value, _release_local_waiter) =
        baked_bool("SCX_CAKE_RELEASE_LOCAL_WAITER", true);
    let (baked_release_domain_drr, baked_release_domain_drr_value, _release_domain_drr) =
        baked_bool("SCX_CAKE_RELEASE_DOMAIN_DRR", false);
    let (baked_release_planck_local, baked_release_planck_local_value, _release_planck_local) =
        baked_bool("SCX_CAKE_RELEASE_PLANCK_LOCAL", true);
    let (baked_core_steal_dhq, baked_core_steal_dhq_value, release_core_steal_dhq) =
        baked_bool("SCX_CAKE_CORE_STEAL_DHQ", false);
    let (_futex_trace_label, futex_trace_value, futex_trace_enabled) =
        baked_bool("SCX_CAKE_FUTEX_TRACE", false);
    let (_busy_wake_grace_label, busy_wake_grace_value, _busy_wake_grace) =
        baked_bool("SCX_CAKE_BUSY_WAKE_GRACE", true);
    let (_smt_clean_select_label, smt_clean_select_value, _smt_clean_select) =
        baked_bool("SCX_CAKE_SMT_CLEAN_SELECT", false);
    let (_frame_owner_shield_label, frame_owner_shield_value, _frame_owner_shield) =
        baked_bool("SCX_CAKE_FRAME_OWNER_SHIELD", false);
    let (_prev_idle_override_label, prev_idle_override_value, _prev_idle_override) =
        baked_bool("SCX_CAKE_PREV_IDLE_OVERRIDE", false);
    let (_lean_wake_kick_label, lean_wake_kick_value, _lean_wake_kick) =
        baked_bool("SCX_CAKE_LEAN_WAKE_KICK", false);
    let (_kthread_wake_preempt_label, kthread_wake_preempt_value, _kthread_wake_preempt) =
        baked_bool("SCX_CAKE_KTHREAD_WAKE_PREEMPT", false);
    let (_native_fast_wake_label, native_fast_wake_value, _native_fast_wake) =
        baked_bool("SCX_CAKE_NATIVE_FAST_WAKE", false);
    let (_native_fast_wake_wide_label, native_fast_wake_wide_value, _native_fast_wake_wide) =
        baked_bool("SCX_CAKE_NATIVE_FAST_WAKE_WIDE", false);
    let (_nfw_miss_tunnel_label, nfw_miss_tunnel_value, _nfw_miss_tunnel) =
        baked_bool("SCX_CAKE_NATIVE_FAST_WAKE_MISS_TUNNEL", false);
    let (_fast_enqueue_label, fast_enqueue_value, _fast_enqueue) =
        baked_bool("SCX_CAKE_FAST_ENQUEUE", false);
    let (_nfw_miss_shared_label, nfw_miss_shared_value, _nfw_miss_shared) =
        baked_bool("SCX_CAKE_NFW_MISS_SHARED", false);
    let (_lean_accounting_label, lean_accounting_value, _lean_accounting) =
        baked_bool("SCX_CAKE_LEAN_ACCOUNTING", false);
    let (_wake_preempt_elapsed_label, wake_preempt_elapsed_value, _wake_preempt_elapsed) =
        baked_bool("SCX_CAKE_WAKE_PREEMPT_ELAPSED", false);
    let (_wake_preempt_adaptive_label, wake_preempt_adaptive_value, _wake_preempt_adaptive) =
        baked_bool("SCX_CAKE_WAKE_PREEMPT_ADAPTIVE", false);
    let baked_release_trust_maps_value =
        baked_release_route_pred_value & baked_release_confidence_value;
    let baked_release_trust_maps = if baked_release_trust_maps_value != 0 {
        "on"
    } else {
        "off"
    };
    let has_trust_maps = profile != "release" || baked_release_trust_maps_value != 0;
    let needs_arena = if profile == "release" {
        release_learned_locality || release_wake_chain_locality || release_core_steal_dhq
    } else {
        enable_hot_telemetry || enable_locality_experiments || release_core_steal_dhq
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
             pub const BAKED_WAKE_CHAIN_LOCALITY_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_ROUTE_PRED: &str = {:?};\n\
             pub const BAKED_RELEASE_ROUTE_PRED_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_CONFIDENCE: &str = {:?};\n\
             pub const BAKED_RELEASE_CONFIDENCE_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_LLC_PENDING: &str = {:?};\n\
             pub const BAKED_RELEASE_LLC_PENDING_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_LOCAL_WAITER: &str = {:?};\n\
             pub const BAKED_RELEASE_LOCAL_WAITER_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_DOMAIN_DRR: &str = {:?};\n\
             pub const BAKED_RELEASE_DOMAIN_DRR_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_PLANCK_LOCAL: &str = {:?};\n\
             pub const BAKED_RELEASE_PLANCK_LOCAL_VALUE: u32 = {};\n\
             pub const BAKED_RELEASE_TRUST_MAPS: &str = {:?};\n\
             pub const BAKED_RELEASE_TRUST_MAPS_VALUE: u32 = {};\n\
             pub const BAKED_CORE_STEAL_DHQ: &str = {:?};\n\
             pub const BAKED_CORE_STEAL_DHQ_VALUE: u32 = {};\n",
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
            baked_wake_chain_locality_value,
            baked_release_route_pred,
            baked_release_route_pred_value,
            baked_release_confidence,
            baked_release_confidence_value,
            baked_release_llc_pending,
            baked_release_llc_pending_value,
            baked_release_local_waiter,
            baked_release_local_waiter_value,
            baked_release_domain_drr,
            baked_release_domain_drr_value,
            baked_release_planck_local,
            baked_release_planck_local_value,
            baked_release_trust_maps,
            baked_release_trust_maps_value,
            baked_core_steal_dhq,
            baked_core_steal_dhq_value
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
    println!("cargo:rerun-if-env-changed=SCX_CAKE_RELEASE_ROUTE_PRED");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_RELEASE_CONFIDENCE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_RELEASE_LLC_PENDING");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_RELEASE_LOCAL_WAITER");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_RELEASE_DOMAIN_DRR");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_RELEASE_PLANCK_LOCAL");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_CORE_STEAL_DHQ");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_FUTEX_TRACE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_BUSY_WAKE_GRACE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_SMT_CLEAN_SELECT");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_FRAME_OWNER_SHIELD");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_PREV_IDLE_OVERRIDE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_LEAN_WAKE_KICK");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_KTHREAD_WAKE_PREEMPT");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_NATIVE_FAST_WAKE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_NATIVE_FAST_WAKE_WIDE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_NATIVE_FAST_WAKE_MISS_TUNNEL");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_FAST_ENQUEUE");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_NFW_MISS_SHARED");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_LEAN_ACCOUNTING");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_WAKE_PREEMPT_ELAPSED");
    println!("cargo:rerun-if-env-changed=SCX_CAKE_WAKE_PREEMPT_ADAPTIVE");
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
    println!("cargo::rustc-check-cfg=cfg(cake_trust_maps)");
    println!("cargo::rustc-check-cfg=cfg(cake_futex_trace)");
    println!("cargo::rustc-check-cfg=cfg(cake_core_steal_dhq)");

    // Emit rustc-cfg flags for true conditional compilation (Rust #[cfg] guards)
    if has_hybrid {
        println!("cargo:rustc-cfg=cake_has_hybrid");
    }
    if is_single_llc {
        println!("cargo:rustc-cfg=cake_single_llc");
    }

    // Build cflags with hardware gates
    let mut cflags = format!(
        "{} -DCAKE_MAX_CPUS={} -DCAKE_MAX_LLCS={} -DCAKE_NR_CPUS={} -DCAKE_NR_LLCS={} -DCAKE_QUANTUM_NS={} -DCAKE_QUEUE_POLICY_VALUE={} -DCAKE_STORM_GUARD_VALUE={} -DCAKE_BUSY_WAKE_KICK_VALUE={} -DCAKE_LEARNED_LOCALITY_VALUE={} -DCAKE_WAKE_CHAIN_LOCALITY_VALUE={} -DCAKE_RELEASE_ROUTE_PRED={} -DCAKE_RELEASE_CONFIDENCE={} -DCAKE_RELEASE_LLC_PENDING={} -DCAKE_RELEASE_LOCAL_WAITER={} -DCAKE_RELEASE_DOMAIN_DRR={} -DCAKE_RELEASE_PLANCK_LOCAL={} -DCAKE_CORE_STEAL_DHQ_VALUE={}",
        base_flags,
        max_cpus,
        max_llcs,
        nr_cpus,
        nr_llcs,
        baked_quantum_us * 1000,
        baked_queue_policy_value,
        baked_storm_guard_value,
        baked_busy_wake_kick_value,
        baked_learned_locality_value,
        baked_wake_chain_locality_value,
        baked_release_route_pred_value,
        baked_release_confidence_value,
        baked_release_llc_pending_value,
        baked_release_local_waiter_value,
        baked_release_domain_drr_value,
        baked_release_planck_local_value,
        baked_core_steal_dhq_value
    );
    cflags.push_str(&format!(" -DCAKE_FUTEX_TRACE={}", futex_trace_value));
    cflags.push_str(&format!(
        " -DCAKE_BUSY_WAKE_GRACE_VALUE={}",
        busy_wake_grace_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_SMT_CLEAN_SELECT_VALUE={}",
        smt_clean_select_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_FRAME_OWNER_SHIELD_VALUE={}",
        frame_owner_shield_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_PREV_IDLE_OVERRIDE_VALUE={}",
        prev_idle_override_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_LEAN_WAKE_KICK_VALUE={}",
        lean_wake_kick_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_KTHREAD_WAKE_PREEMPT_VALUE={}",
        kthread_wake_preempt_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_NATIVE_FAST_WAKE_VALUE={}",
        native_fast_wake_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_NATIVE_FAST_WAKE_WIDE={}",
        native_fast_wake_wide_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_NATIVE_FAST_WAKE_MISS_TUNNEL={}",
        nfw_miss_tunnel_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_FAST_ENQUEUE_VALUE={}",
        fast_enqueue_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_NFW_MISS_SHARED={}",
        nfw_miss_shared_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_LEAN_ACCOUNTING_VALUE={}",
        lean_accounting_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_WAKE_PREEMPT_ELAPSED_VALUE={}",
        wake_preempt_elapsed_value
    ));
    cflags.push_str(&format!(
        " -DCAKE_WAKE_PREEMPT_ADAPTIVE={}",
        wake_preempt_adaptive_value
    ));
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
    if has_trust_maps {
        println!("cargo:rustc-cfg=cake_trust_maps");
    }
    if futex_trace_enabled {
        println!("cargo:rustc-cfg=cake_futex_trace");
    }
    if release_core_steal_dhq {
        println!("cargo:rustc-cfg=cake_core_steal_dhq");
    }
    cflags.push_str(&format!(
        " -DCAKE_RELEASE_TRUST_MAPS={}",
        baked_release_trust_maps_value
    ));
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
        "scx_cake [info]: CAKE_MAX_CPUS={} CAKE_MAX_LLCS={} CAKE_NR_CPUS={} CAKE_NR_LLCS={} SINGLE_LLC={} HAS_HYBRID={} BAKED_PROFILE={} BAKED_QUANTUM_US={} BAKED_QUEUE_POLICY={} BAKED_STORM_GUARD={} BAKED_BUSY_WAKE_KICK={} BAKED_LEARNED_LOCALITY={} BAKED_WAKE_CHAIN_LOCALITY={} BAKED_RELEASE_ROUTE_PRED={} BAKED_RELEASE_CONFIDENCE={} BAKED_RELEASE_LLC_PENDING={} BAKED_RELEASE_LOCAL_WAITER={} BAKED_RELEASE_DOMAIN_DRR={} BAKED_RELEASE_PLANCK_LOCAL={} BAKED_RELEASE_TRUST_MAPS={} NEEDS_ARENA={} FUTEX_TRACE={} CORE_STEAL_DHQ={}",
        max_cpus,
        max_llcs,
        nr_cpus,
        nr_llcs,
        is_single_llc,
        has_hybrid,
        baked_profile,
        baked_quantum_us,
        baked_queue_policy,
        baked_storm_guard,
        baked_busy_wake_kick,
        baked_learned_locality,
        baked_wake_chain_locality,
        baked_release_route_pred,
        baked_release_confidence,
        baked_release_llc_pending,
        baked_release_local_waiter,
        baked_release_domain_drr,
        baked_release_planck_local,
        baked_release_trust_maps,
        needs_arena,
        futex_trace_enabled,
        baked_core_steal_dhq
    );

    std::env::set_var("BPF_EXTRA_CFLAGS_PRE_INCL", &cflags);
    let mut builder = scx_cargo::BpfBuilder::new().unwrap();
    builder
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/cake.bpf.c", "bpf");

    if needs_arena {
        builder
            .add_source("src/bpf/lib/arena.bpf.c")
            .add_source("src/bpf/lib/rbtree.bpf.c")
            .add_source("src/bpf/lib/atq.bpf.c")
            .add_source("src/bpf/lib/sdt_alloc.bpf.c")
            .add_source("src/bpf/lib/sdt_task.bpf.c")
            .add_source("src/bpf/lib/bitmap.bpf.c")
            .add_source("src/bpf/lib/cpumask.bpf.c")
            .add_source("src/bpf/lib/topology.bpf.c")
            .add_source("src/bpf/lib/minheap.bpf.c")
            .add_source("src/bpf/lib/dhq.bpf.c");
    }

    builder.compile_link_gen().unwrap();
}
