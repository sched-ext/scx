#![cfg(feature = "ktstr-tests")]

use ktstr::prelude::*;

declare_scheduler!(MITOSIS, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 2, 4, 2),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--cpu-controller-disabled",
        "--cell-parent-cgroup", "/ktstr",
        "--enable-borrowing",
        "--cell-no-cpus-fix",
    ],
});

/// Reproduces the mitosis "Cell 0 has no CPUs assigned" bail.
///
/// In --cell-parent-cgroup mode, cell 0 is the catch-all that
/// receives any CPUs not explicitly claimed by a child cgroup's
/// cpuset. compute_cpu_assignments (cell_manager.rs Phase 5)
/// bails when any cell — including cell 0 — would end up with
/// zero CPUs.
///
/// When child cgroups' cpusets collectively cover every CPU on
/// the host, cell 0 gets nothing and the scheduler tears down
/// mid-recompute:
///
///   running scheduler main loop
///   Caused by:
///     0: checking cpuset changes
///     1: recomputing cell configuration after cpuset change
///     2: computing demand-weighted CPU assignments
///     3: Cell 0 has no CPUs assigned (nr_cpus=N, num_cells=M)
///
/// alpha + beta with disjoint cpusets covering all 16 topology
/// CPUs reproduces the bail. The bug also fires dynamically when
/// cells gradually acquire cpusets via
/// `Cell N cpuset changed: None -> Some(...)` until the union
/// covers every CPU.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 30,
    memory_mib = 256,
)]
fn mitosis_cell0_starved_by_full_coverage_cpusets(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![Step::with_defs(
        vec![
            CgroupDef::named("alpha")
                .cpuset(CpusetSpec::exact(0..8))
                .workers(1)
                .work_type(WorkType::SpinWait),
            CgroupDef::named("beta")
                .cpuset(CpusetSpec::exact(8..16))
                .workers(1)
                .work_type(WorkType::SpinWait),
        ],
        HoldSpec::FULL,
    )];
    execute_steps(ctx, steps)
}
