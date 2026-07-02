#![cfg(feature = "ktstr-tests")]
//! scx_mitosis cell-isolation smoke test, and a showcase of the ktstr harness.
//!
//! Two tenants, each in its own cgroup → its own mitosis cell: a small
//! "sensitive" tenant and a CPU "hog". Phase 0 runs under scx_mitosis; phase 1
//! detaches it and reruns under the kernel default (EEVDF). Under mitosis the
//! sensitive tenant should do more work and wait less, and the hog should not be
//! starved. Passing also proves mitosis boots, schedules, and detaches cleanly.
//!
//! ktstr features used: `Scheduler`/`CgroupDef` builders, `#[ktstr_test]` inline
//! topology, `Op::detach_scheduler` for the phase-1 A/B, `VmResult::phase_cgroup`
//! for per-cgroup per-phase stats, and the `claim!`/`Verdict` assertion DSL.

use ktstr::prelude::*;

/// scx_mitosis in cell-manager mode: each child of `--cell-parent-cgroup` is a cell.
const MITOSIS: Scheduler = Scheduler::named("mitosis")
    .binary_discover("scx_mitosis")
    .sched_args(&[
        "--cell-parent-cgroup",
        "/test.slice",
        "--cpu-controller-disabled",
        "--enable-llc-awareness",
        "--exit-dump-len",
        "1048576",
    ]);

const SENSITIVE_WORKERS: usize = 2;
const HOG_WORKERS: usize = 30;
/// Sensitive does at least this much more work under mitosis than under EEVDF.
const MIN_ISOLATION_GAIN: f64 = 1.3;
/// Sensitive waits at most this fraction of its EEVDF runqueue wait under mitosis.
const MAX_DELAY_RATIO: f64 = 0.7;
/// Hog keeps at least this fraction of its EEVDF work under mitosis (not starved).
const HOG_KEEP_FRACTION: f64 = 0.5;

/// Two tenants → two cells. Declared fresh per phase so each phase has its own
/// stats window.
fn interference_workload() -> Step {
    Step::with_defs(
        vec![
            CgroupDef::named("sensitive")
                .workers(SENSITIVE_WORKERS)
                .work_type(WorkType::SpinWait),
            CgroupDef::named("hog")
                .workers(HOG_WORKERS)
                .work_type(WorkType::SpinWait),
        ],
        HoldSpec::frac(0.5),
    )
}

/// Per-cgroup per-phase stats come off the `VmResult`, so the comparison lives here.
fn assert_mitosis_isolates_sensitive(result: &VmResult) -> Result<()> {
    // step 0 = mitosis, step 1 = detached EEVDF.
    let cell = |name: &str, step: u16| result.phase_cgroup(Phase::step(step), name);
    let (Some(sm), Some(se)) = (cell("sensitive", 0), cell("sensitive", 1)) else {
        anyhow::bail!("no per-phase stats for `sensitive`");
    };
    let (Some(hm), Some(he)) = (cell("hog", 0), cell("hog", 1)) else {
        anyhow::bail!("no per-phase stats for `hog`");
    };
    let (Some((sensitive_run_delay_us, _)), Some((eevdf_run_delay_us, _))) =
        (sm.run_delay_summary(), se.run_delay_summary())
    else {
        anyhow::bail!("no run-delay samples for `sensitive`");
    };

    eprintln!(
        "sensitive iters:        mitosis={} eevdf={}",
        sm.total_iterations, se.total_iterations
    );
    eprintln!(
        "sensitive run_delay_us: mitosis={sensitive_run_delay_us:.0} eevdf={eevdf_run_delay_us:.0}"
    );
    eprintln!(
        "hog iters:              mitosis={} eevdf={}",
        hm.total_iterations, he.total_iterations
    );

    // `claim!` labels each value by its name; `into_anyhow_or_log` bails on any
    // failed claim. Sensitive does more work and waits less; the hog is not starved.
    let sensitive_iters = sm.total_iterations as f64;
    let hog_iters = hm.total_iterations as f64;
    let mut verdict = Verdict::new();
    claim!(verdict, sensitive_iters).at_least(se.total_iterations as f64 * MIN_ISOLATION_GAIN);
    claim!(verdict, sensitive_run_delay_us).at_most(eevdf_run_delay_us * MAX_DELAY_RATIO);
    claim!(verdict, hog_iters).at_least(he.total_iterations as f64 * HOG_KEEP_FRACTION);
    verdict.into_anyhow_or_log()
}

#[ktstr_test(
    scheduler = MITOSIS,
    // Workload cgroups land here = the cell-parent, so each becomes a cell.
    workload_root_cgroup = "/test.slice",
    // 16 vCPUs; sensitive(2) + hog(30) = 32 threads oversubscribe them.
    llcs = 4,
    cores = 4,
    threads = 1,
    memory_mib = 512,
    // Two equal phases (frac(0.5) each).
    duration_s = 20,
    watchdog_timeout_s = 10,
    num_snapshots = 12,
    auto_repro = false,
    post_vm = assert_mitosis_isolates_sensitive,
)]
fn mitosis_isolates_sensitive_tenant(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![
        // Phase 0: both tenants under scx_mitosis.
        interference_workload(),
        // Phase 1: detach → EEVDF. The op runs before this phase's cgroups spawn.
        interference_workload().set_ops(vec![Op::detach_scheduler()]),
    ];
    execute_steps(ctx, steps)
}
