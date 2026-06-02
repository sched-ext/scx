#![cfg(feature = "ktstr-tests")]

use std::collections::BTreeSet;

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
        "--vtime-borrow-fixes",
    ],
});

/// Reproduces mitosis.bpf.c's "vtime too far ahead" scx_bpf_error on
/// the UNPINNED cell-DSQ path. Tasks running on borrowed CPUs grow
/// dsq_vtime that never advances their home cell's vtime_now (the
/// stopping gate fails on `!borrowed`). Eventually the cell-DSQ
/// enqueue basis check sees vtime > basis + 8192 * slice_ns and
/// errors. Fixed by --vtime-borrow-fixes, which advances the
/// home cell's vtime regardless of borrow.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 180,
    memory_mib = 256,
)]
fn mitosis_vtime_too_far_ahead_via_borrowing(ctx: &Ctx) -> Result<AssertResult> {
    let bursty = WorkType::Bursty {
        burst_duration: std::time::Duration::from_millis(1),
        sleep_duration: std::time::Duration::from_millis(10),
    };
    let steps = vec![Step::with_defs(
        vec![
            CgroupDef::named("alpha").workers(64).work_type(bursty),
            CgroupDef::named("beta")
                .workers(8)
                .work_type(WorkType::SpinWait)
                .sched_policy(SchedPolicy::Idle),
        ],
        HoldSpec::FULL,
    )];
    execute_steps(ctx, steps)
}

/// Reproduces mitosis.bpf.c's "vtime too far ahead" scx_bpf_error on
/// the PINNED per-CPU-DSQ path. A task with single-CPU pinning
/// outside its home cell never advances the cross-cell CPU's
/// vtime_now (the stopping gate fails on
/// `vtime_charge_cell != cidx`). The pinned enqueue path uses
/// cctx->vtime_now as its basis, so dsq_vtime drifts past it
/// without bound. Fixed by --vtime-borrow-fixes, which both
/// advances home cell vtime in stopping and uses home cell vtime
/// as basis for cross-cell pinned tasks in enqueue.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 30,
    memory_mib = 256,
)]
fn mitosis_vtime_too_far_ahead_via_cross_cell_pin(ctx: &Ctx) -> Result<AssertResult> {
    let bursty = WorkType::Bursty {
        burst_duration: std::time::Duration::from_millis(1),
        sleep_duration: std::time::Duration::from_millis(10),
    };
    let steps = vec![Step::with_defs(
        vec![
            CgroupDef::named("alpha")
                .cpuset(CpusetSpec::exact([1, 2, 3, 4, 5, 6, 7]))
                .workers(1)
                .work_type(bursty),
            CgroupDef::named("beta").work(
                WorkSpec::default()
                    .workers(1)
                    .work_type(WorkType::SpinWait)
                    .sched_policy(SchedPolicy::Idle)
                    .affinity(AffinityIntent::Exact(BTreeSet::from([1usize]))),
            ),
        ],
        HoldSpec::FULL,
    )];
    execute_steps(ctx, steps)
}
