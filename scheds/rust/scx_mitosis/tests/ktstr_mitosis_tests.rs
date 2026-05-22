#![cfg(feature = "ktstr-tests")]

use ktstr::prelude::*;

declare_scheduler!(MITOSIS, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 4, 4, 1),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--reject-multicpu-pinning",
        "--cpu-controller-disabled",
        "--enable-borrowing",
        "--enable-rebalancing",
        "--dynamic-affinity-cpu-selection",
        "--enable-slice-shrinking",
        "--cell-parent-cgroup", "/ktstr",
    ],
});

/// Triggers cell 0 CPU under-provisioning.
///
/// Workload cgroup's cpuset claims 7 of 8 CPUs; mitosis's
/// exclusive-cpuset assignment honors that claim verbatim, so cell 0
/// ends up with only the 1 unclaimed CPU even though compute_targets
/// would emit a much larger share under equal-weight inputs (~4 of 8).
///
/// Cell assignment (verified from ktstr DualFailureDump, both early
/// and late snapshots identical, applied_configuration_seq=4):
///   - Cell 0 (root)                         primary {CPU 7}, borrowable {0-6}
///   - Cell 1 (workload cgroup, cell_owner)  primary {0-6},   borrowable empty
///   - cpuset range(0.0625, 1.0) on 8 CPUs → CPUs 0-6 claimed; cell 0
///     gets CPU 7.
///
/// Stall mechanism:
///   - All host tasks (200 bursty + 1 nice=19 SpinWait + init
///     + kthreads) land in cell 0 → must dispatch via CPU 7.
///   - 256 workload-cgroup workers land in cell 1 → saturate CPUs 0-6.
///   - enable_borrowing would let cell 0 borrow cell 1's CPUs, but
///     cell 1 never goes idle → no borrow opportunity.
///   - The nice=19 SpinWait is the always-runnable cell-0 background task
///     (analog of kworker / khugepaged on for-realsies hosts) that
///     creates the "runnable behind a saturated dispatcher" pattern.
///     A cell 0 kthread (init[117] in the captured dump) eventually
///     stays runnable past the 5s SCX watchdog and the scheduler
///     exits with kind 1026.
///
/// Key facts in the failure dump:
///   - cell_cpumasks:                cell 0 primary {7}, borrowable {0-6}
///   - bpf.bss cell_config.cpumasks: [0]=0x80 (CPU 7), [1]=0x7f (CPUs 0-6)
///   - cgrp_ctxs:                    cell_owner cgroup → cell=1
///   - rodata:                       enable_borrowing=true,
///                                   userspace_managed_cell_mode=true (LLC-aware OFF)
///
/// TL;DR: when cpuset forces too much divergence from compute_targets,
/// host tasks get starved.
///
/// Uses default rebalance cooldown (60s) like for-realsies; only the
/// initial equal-weight pass runs in the 30s window. The fix's
/// reclamation kicks in at that pass and gives cell 0 its
/// compute_targets share.
///
/// Workload shape: bursty (2ms/20ms) is the empirically-verified host
/// worker mix; SpinWait alone doesn't reproduce, AluHot reproduces 1026
/// via a different (preempt-disabled) mechanism that real workloads
/// don't exhibit.
///
/// https://github.com/sched-ext/scx/pull/3571 should fix the initial 
/// occurrence of this issue, but this pattern sounds common enough 
/// this should stick around.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 30,
    watchdog_timeout_s = 5,
    llcs = 2,
    cores = 2,
    threads = 2,
    memory_mib = 96,
)]
fn mitosis_root_cell_starvation(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![Step::with_defs(
        vec![CgroupDef::named("workload")
            .workers(256)
            .cpuset(CpusetSpec::range(0.0625, 1.0))],
        HoldSpec::FULL,
    )
    .set_ops(vec![
        Op::spawn_host(
            WorkSpec::default()
                .workers(1)
                .work_type(WorkType::SpinWait)
                .nice(19),
        ),
        Op::spawn_host(
            WorkSpec::default()
                .workers(100)
                .work_type(WorkType::Bursty {
                    burst_duration: std::time::Duration::from_millis(2),
                    sleep_duration: std::time::Duration::from_millis(20),
                }),
        ),
    ])];
    execute_steps(ctx, steps)
}
