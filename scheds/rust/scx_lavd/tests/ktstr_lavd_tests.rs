//! ktstr reproduction for an scx_lavd runtime error.
#![cfg(feature = "ktstr-tests")]

use ktstr::prelude::*;

const SCRATCH: DiskConfig = DiskConfig::DEFAULT;

declare_scheduler!(LAVD, {
    name = "lavd",
    binary = "scx_lavd",
    sched_args = [
        "--performance",
        "--slice-min-us", "3000",
        "--slice-max-us", "10000",
        "--pinned-slice-us", "3000",
    ],
});

/// Reproduce the scx_lavd runtime error:
///   runtime error (SCX_DSQ_LOCAL[_ON] target CPU N not allowed for <task>)
///   scx_exit <- task_can_run_on_remote_rq <- dispatch_to_local_dsq
#[ktstr_test(
    scheduler = LAVD,
    disk = SCRATCH,
    llcs = 1,
    cores = 16,
    threads = 2,
    duration_s = 30,
)]
fn lavd_misplaced_local_on(ctx: &Ctx) -> Result<AssertResult> {
    execute_defs(
        ctx,
        vec![CgroupDef::named("race")
            .cpuset(CpusetSpec::range(0.0, 0.5))
            .work(
                WorkSpec::default()
                    .workers(32)
                    .work_type(WorkType::FutexPingPong { spin_iters: 0 }),
            )
            .work(
                WorkSpec::default()
                    .workers(4)
                    .work_type(WorkType::CrossAffinityChurn { spin_iters: 0 }),
            )],
    )
}
