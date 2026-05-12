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
