/// Reproducer for "EXIT: runtime error (invalid CPU N)" -- cell 0
/// starvation in BPF auto-mode.
///
/// In auto-mode (no --cell-parent-cgroup), update_timer_cb
/// (mitosis.bpf.c:1115) clears each child cgroup's cpuset CPUs from
/// root cell 0 (L1268). When children cover ALL CPUs, cell 0's
/// published cpumask is empty (L1324, no guard).
///
/// For cell 0 tasks: bpf_cpumask_subset(empty, p->cpus_ptr) = TRUE
/// (vacuous), so all_cell_cpus_allowed = TRUE, skipping the pinned
/// path (L705). On -EBUSY, bpf_cpumask_any_distribute(empty) at
/// L739-740 returns nr_cpu_ids -> ops_cpu_valid rejects it.
use ktstr::prelude::*;

#[derive(Scheduler)]
#[scheduler(
    name = "mitosis",
    binary = "scx_mitosis",
    topology(1, 1, 4, 1),
    sched_args = [
        "--cpu-controller-disabled",
        "--enable-borrowing",
        "--enable-rebalancing",
        "--exit-dump-len", "1048576",
    ]
)]
#[allow(dead_code)]
enum Mitosis {}

#[ktstr_test(
    scheduler = MITOSIS,
    duration_s = 10,
    workers_per_cgroup = 2,
    watchdog_timeout_s = 15,
    expect_err = false,
)]
fn mitosis_cell0_cpuset_starvation(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![
        // Warmup: let scheduler stabilize before triggering the bug.
        // Auto-repro probes need time to attach.
        Step::with_defs(
            vec![CgroupDef::named("cg_warmup").workers(2)],
            HoldSpec::Fixed(std::time::Duration::from_secs(3)),
        ),
        // Trigger: cpusets covering all CPUs starve cell 0.
        Step::with_defs(
            vec![
                CgroupDef::named("cg_0")
                    .with_cpuset(CpusetSpec::exact(0..2))
                    .workers(2),
                CgroupDef::named("cg_1")
                    .with_cpuset(CpusetSpec::exact(2..4))
                    .workers(2),
            ],
            HoldSpec::FULL,
        )
        .with_ops(vec![Op::spawn_host(Work::default().workers(8))]),
    ];
    execute_steps(ctx, steps)
}
