#![cfg(feature = "ktstr-tests")]

use std::collections::BTreeSet;
use std::time::Duration;

use ktstr::prelude::*;

// Regression tests for runnable-task stalls (watchdog SCX_EXIT_ERROR_STALL,
// exit_kind 1026) from the scx_mitosis vtime drift bugs. Each sets up a
// SCHED_IDLE drifter (weight 1 -> p->scx.dsq_vtime charged at 100x,
// mitosis.bpf.c:1424) that, WITHOUT --vtime-borrow-fixes, drifts until it
// loses every vtime-ordered dispatch and the watchdog kills the scheduler.
// The flag is enabled here, so the drift is charged to the right vtime domain
// and both tests pass; drop --vtime-borrow-fixes to reproduce the stalls.
// They use the default scx watchdog (no override).
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

/// Bug 1 (borrowing) runnable-task stall — guarded by --vtime-borrow-fixes.
///
/// Without the flag, mitosis_stopping's gate
/// `!borrowed && vtime_charge_cell == cidx` (mitosis.bpf.c:1432) withholds a
/// task's BORROWED runtime from its home cell's vtime_now. A SCHED_IDLE
/// worker riding borrowed foreign CPUs charges p->scx.dsq_vtime at 100x while
/// its home cell never catches up, so once borrowing is cut it can no longer
/// be dispatched in its home cell and the watchdog fires. The flag charges
/// the borrowed runtime to the home cell (mitosis.bpf.c:1437), the runaway
/// cannot form, and this test passes.
///
/// Setup (16 CPUs): alpha owns [4..15] (cpuset), bursty in phase 1 so those
/// CPUs are idle and beta — which has no cpuset, so its borrowable set is
/// every CPU it does not own (cell_manager.rs:779) — borrows them. beta's
/// weight-100 SpinWait holders outcompete the SCHED_IDLE drifter onto
/// borrowed CPUs. Borrowing requires the drifter's mask to cover beta's
/// borrowable set (mitosis.bpf.c:349), which includes cell 0's CPUs, so a
/// cell-0 occupier (Op::spawn_host runs in the guest root cgroup, which
/// mitosis assigns to cell 0, mitosis.bpf.c:1508) pinned to cell 0's CPUs
/// [0,1] keeps its idle floor CPU busy. Phase 2 saturates alpha, cutting
/// borrowing.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 35,
    memory_mib = 256,
)]
fn mitosis_vtime_stall_via_borrowing(ctx: &Ctx) -> Result<AssertResult> {
    let bursty = WorkType::Bursty {
        burst_duration: Duration::from_millis(1),
        sleep_duration: Duration::from_millis(10),
    };

    let backdrop = Backdrop::new()
        // alpha owns [4..15]; bursty leaves them idle/borrowable in phase 1.
        .push_cgroup(
            CgroupDef::named("alpha")
                .cpuset(CpusetSpec::exact([
                    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]))
                .workers(2)
                .work_type(bursty),
        )
        .push_cgroup(
            CgroupDef::named("beta")
                // Unpinned weight-100 holders share beta's cell DSQ at low
                // vtime, so the SCHED_IDLE drifter is outcompeted for beta's
                // CPUs and forced to borrow alpha instead of running home.
                .work(WorkSpec::default().workers(5).work_type(WorkType::SpinWait))
                // The drifter: SCHED_IDLE, unpinned (its mask must cover beta's
                // borrowable set to be eligible to borrow). It borrows alpha's
                // idle [4..15] and drifts at 100x.
                .work(
                    WorkSpec::default()
                        .workers(1)
                        .work_type(WorkType::SpinWait)
                        .sched_policy(SchedPolicy::Idle),
                ),
        );

    let steps = vec![
        // Occupy cell 0's CPUs so the drifter cannot dodge by borrowing cell
        // 0's idle floor CPU. RunnerCgroup placement (Op::spawn_host) puts
        // these workers in the guest root cgroup = mitosis cell 0; pinned to
        // cell 0's mask [0,1], they keep those CPUs busy WITHOUT borrowing
        // (pinned -> not all_cell_cpus_allowed) and WITHOUT displacing cell 0
        // (they are in it). Phase 1 runs concurrently: the drifter borrows
        // alpha's idle [4..15] and drifts.
        Step::with_op(
            Op::spawn_host(
                WorkSpec::default()
                    .workers(4)
                    .work_type(WorkType::SpinWait)
                    .affinity(AffinityIntent::Exact(BTreeSet::from([0usize, 1]))),
            ),
            HoldSpec::fixed(Duration::from_millis(3000)),
        ),
        // Phase 2: saturate alpha so the drifter can borrow nowhere. Without
        // --vtime-borrow-fixes its runaway dsq_vtime has poisoned beta's
        // domain and a beta task stalls; with the flag beta's vtime_now
        // tracked the borrowed runtime, so all tasks keep running.
        Step::with_op(
            Op::spawn_workers(
                "alpha",
                WorkSpec::default()
                    .workers(24)
                    .work_type(WorkType::SpinWait),
            ),
            HoldSpec::fixed(Duration::from_secs(30)),
        ),
    ];

    execute_scenario(ctx, backdrop, steps)
}

/// Bug 2 (cross-cell pin) runnable-task stall — guarded by --vtime-borrow-fixes.
///
/// Without the flag, a SCHED_IDLE task pinned to a single CPU OUTSIDE its home
/// cell charges p->scx.dsq_vtime at 100x (mitosis.bpf.c:1424) but is charged to
/// its home cell, so its runs never advance the cell it actually runs in:
/// mitosis_stopping's gate fails on vtime_charge_cell != cidx
/// (mitosis.bpf.c:1432). On the saturated foreign CPU, mitosis_dispatch
/// raw-compares its drifted dsq_vtime against the foreign cell's tasks
/// (mitosis.bpf.c:951) and it loses every dispatch until the watchdog fires.
/// The flag charges the pinned task to the cell of the CPU it runs on
/// (vtime_charge_cell = that cell, mitosis.bpf.c:881), so that cell and that
/// CPU's vtime_now track it and its dsq_vtime stays comparable to the foreign
/// cell's tasks at dispatch; it stays dispatchable and this test passes.
///
/// Phase 1: alpha owns [1..7] (cpuset) with 1 bursty worker, so CPU 1 is
/// mostly idle and the pinned drifter runs there and drifts. Phase 2: SpinWait
/// saturates [1..7].
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 35,
    memory_mib = 256,
)]
fn mitosis_vtime_stall_via_cross_cell_pin(ctx: &Ctx) -> Result<AssertResult> {
    let bursty = WorkType::Bursty {
        burst_duration: Duration::from_millis(1),
        sleep_duration: Duration::from_millis(10),
    };

    let backdrop = Backdrop::new()
        .push_cgroup(
            CgroupDef::named("alpha")
                .cpuset(CpusetSpec::exact([1, 2, 3, 4, 5, 6, 7]))
                .workers(1)
                .work_type(bursty),
        )
        .push_cgroup(
            CgroupDef::named("beta").work(
                // SCHED_IDLE drifter pinned to CPU 1 (in alpha's cpuset),
                // outside beta's home cell -> cross-cell pin.
                WorkSpec::default()
                    .workers(1)
                    .work_type(WorkType::SpinWait)
                    .sched_policy(SchedPolicy::Idle)
                    .affinity(AffinityIntent::Exact(BTreeSet::from([1usize]))),
            ),
        );

    let steps = vec![
        // Phase 1: pinned drifter runs on idle CPU 1 and drifts. Kept short so
        // the gap stays below 8192*slice_ns (163.84s) and the scx_bpf_error
        // ("vtime too far ahead") path is not taken — this targets a stall.
        Step::hold(HoldSpec::fixed(Duration::from_millis(1500))),
        // Phase 2: saturate alpha's [1..7] so CPU 1 is busy with lower-vtime
        // cell-1 tasks. Without --vtime-borrow-fixes the pinned drifter loses
        // every dispatch and stalls; with the flag the cell it ran in tracks
        // its runtime, so it stays dispatchable.
        Step::with_op(
            Op::spawn_workers(
                "alpha",
                WorkSpec::default()
                    .workers(14)
                    .work_type(WorkType::SpinWait),
            ),
            HoldSpec::fixed(Duration::from_secs(30)),
        ),
    ];

    execute_scenario(ctx, backdrop, steps)
}
