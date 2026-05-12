#![cfg(feature = "ktstr-tests")]

use ktstr::prelude::*;

#[derive(ktstr::Scheduler)]
#[scheduler(
    name = "mitosis",
    binary = "scx_mitosis",
    topology(1, 4, 4, 1),
    cgroup_parent = "/ktstr",
    sched_args = [
        "--exit-dump-len", "1048576",
        "--reject-multicpu-pinning",
        "--cpu-controller-disabled",
        "--enable-borrowing",
        "--enable-rebalancing",
        "--dynamic-affinity-cpu-selection",
        "--enable-slice-shrinking",
    ],
)]
#[allow(dead_code)]
enum MitosisFlags {}

#[ktstr_test(
    scheduler = MITOSIS_PAYLOAD,
    duration_s = 30, watchdog_timeout_s = 5,
    llcs = 1, cores = 16, threads = 2,
    extra_sched_args = ["--rebalance-cooldown-s", "1", "--rebalance-threshold", "0.1"],
    memory_mb = 96, workers_per_cgroup = 256,
)]
fn mitosis_root_cell_starvation(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![Step {
        setup: vec![CgroupDef::named("workload")
            .workers(ctx.workers_per_cgroup)
            .with_cpuset(CpusetSpec::range(0.0625, 1.0))]
        .into(),
        ops: vec![
            Op::SpawnHost {
                work: WorkSpec::default()
                    .workers(1)
                    .work_type(WorkType::SpinWait)
                    .sched_policy(SchedPolicy::Idle),
            },
            Op::SpawnHost {
                work: WorkSpec::default()
                    .workers(200)
                    .work_type(WorkType::Bursty {
                        burst_duration: std::time::Duration::from_millis(2),
                        sleep_duration: std::time::Duration::from_millis(20),
                    }),
            },
        ],
        hold: HoldSpec::FULL,
    }];
    execute_steps(ctx, steps)
}
