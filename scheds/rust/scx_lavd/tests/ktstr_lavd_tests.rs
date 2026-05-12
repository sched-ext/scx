#![cfg(feature = "ktstr-tests")]

use anyhow::Result;
use ktstr::prelude::*;
use std::time::Duration;

#[derive(ktstr::Scheduler)]
#[scheduler(name = "lavd", binary = "scx_lavd", topology(1, 2, 4, 2))]
#[allow(dead_code)]
enum LavdFlags {
    #[flag(args = [
        "--performance",
        "--slice-min-us", "3000",
        "--slice-max-us", "10000",
        "--pinned-slice-us", "3000",
        "--enable-cpu-bw",
    ])]
    Alpha,
}

// stall when cpus.max set.
#[ktstr_test(
    scheduler = LAVD_PAYLOAD, duration_s = 30, watchdog_timeout_s = 10,
    required_flags = ["alpha"],
)]
fn lavd_cpus_max_stall(ctx: &Ctx) -> Result<AssertResult> {
    execute_defs(
        ctx,
        vec![CgroupDef::named("bw_stall")
            .cpu_quota_pct(5)
            .workers(4)
            .work_type(WorkType::SpinWait)
            .work(WorkSpec {
                work_type: WorkType::Bursty {
                    burst_duration: Duration::from_millis(10),
                    sleep_duration: Duration::from_millis(1),
                },
                num_workers: Some(16),
                ..Default::default()
            })],
    )
}

#[ktstr_test(
    scheduler = LAVD_PAYLOAD, duration_s = 30, watchdog_timeout_s = 10,
    required_flags = ["alpha"],
)]
fn lavd_reclaim_stall(ctx: &Ctx) -> Result<AssertResult> {
    execute_defs(
        ctx,
        vec![CgroupDef::named("reclaim_stall")
            .workers(8)
            .work_type(WorkType::PageFaultChurn {
                region_kb: 65536,
                touches_per_cycle: 4096,
                spin_iters: 0,
            })
            .work(
                WorkSpec::default()
                    .workers(32)
                    .work_type(WorkType::FutexPingPong { spin_iters: 1024 })
                    .nice(19),
            )],
    )
}
