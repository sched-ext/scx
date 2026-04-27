use std::time::Duration;

use anyhow::Result;
use ktstr::prelude::*;

#[derive(ktstr::Scheduler)]
#[scheduler(
    name = "mitosis",
    binary = "scx_mitosis",
    topology(1, 1, 4, 1),
    cgroup_parent = "/mitosis"
)]
#[allow(dead_code)]
enum MitosisFlags {
    #[flag(args = ["--cpu-controller-disabled"])]
    CpuControllerDisabled,
    #[flag(args = ["--enable-llc-awareness"])]
    Llc,
    #[flag(args = ["--enable-work-stealing"], requires = [Llc])]
    Steal,
    #[flag(args = ["--enable-borrowing"])]
    Borrowing,
    #[flag(args = ["--enable-rebalancing", "--rebalance-cooldown-s", "2", "--rebalance-threshold", "10"])]
    Rebalancing,
}

// ---------------------------------------------------------------------------
// Canned scenarios
// ---------------------------------------------------------------------------

#[ktstr_test(scheduler = MITOSIS_PAYLOAD, llcs = 1, cores = 4, duration_s = 15, watchdog_timeout_s = 5, required_flags = ["cpu-controller-disabled"])]
fn mitosis_steady(ctx: &Ctx) -> Result<AssertResult> {
    scenarios::steady(ctx)
}

#[ktstr_test(scheduler = MITOSIS_PAYLOAD, llcs = 2, cores = 2, duration_s = 15, watchdog_timeout_s = 5, required_flags = ["cpu-controller-disabled"])]
fn mitosis_cpuset_apply(ctx: &Ctx) -> Result<AssertResult> {
    scenarios::cpuset_apply(ctx)
}

#[ktstr_test(scheduler = MITOSIS_PAYLOAD, llcs = 1, cores = 4, duration_s = 15, watchdog_timeout_s = 5, required_flags = ["cpu-controller-disabled"])]
fn mitosis_cgroup_add(ctx: &Ctx) -> Result<AssertResult> {
    scenarios::cgroup_add(ctx)
}

#[ktstr_test(scheduler = MITOSIS_PAYLOAD, llcs = 1, cores = 4, duration_s = 15, watchdog_timeout_s = 5, required_flags = ["cpu-controller-disabled"])]
fn mitosis_oversubscribed(ctx: &Ctx) -> Result<AssertResult> {
    scenarios::oversubscribed(ctx)
}

// ---------------------------------------------------------------------------
// Custom: vtime contamination
//
// A heavily loaded cell must not pollute vtime accounting for other
// cells sharing the same CPU pool.  Three cells with wildly different
// worker counts and work patterns compete for 4 CPUs.  The scheduler
// must keep every cell alive (not_starved) despite the asymmetry.
// ---------------------------------------------------------------------------

#[ktstr_test(
    scheduler = MITOSIS_PAYLOAD,
    llcs = 1,
    cores = 4,
    duration_s = 20,
    watchdog_timeout_s = 8,
    required_flags = ["cpu-controller-disabled"],
    not_starved = true,
)]
fn mitosis_vtime_contamination(ctx: &Ctx) -> Result<AssertResult> {
    execute_defs(
        ctx,
        vec![
            CgroupDef::named("heavy")
                .workers(8)
                .work_type(WorkType::CpuSpin),
            CgroupDef::named("light")
                .workers(2)
                .work_type(WorkType::CpuSpin),
            CgroupDef::named("bursty")
                .workers(2)
                .work_type(WorkType::Bursty {
                    burst_ms: 10,
                    sleep_ms: 5,
                }),
        ],
    )
}

// ---------------------------------------------------------------------------
// Custom: cpuset swap between cells
//
// Two cells start on disjoint CPU sets, then swap mid-run.  The
// scheduler must detect the cpuset change, migrate tasks, and
// continue scheduling without starvation or prolonged gaps.
// ---------------------------------------------------------------------------

#[ktstr_test(
    scheduler = MITOSIS_PAYLOAD,
    llcs = 2,
    cores = 2,
    duration_s = 20,
    watchdog_timeout_s = 8,
    required_flags = ["cpu-controller-disabled"],
)]
fn mitosis_cpuset_swap(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![
        Step {
            setup: vec![
                CgroupDef::named("cell_a").with_cpuset(CpusetSpec::disjoint(0, 2)),
                CgroupDef::named("cell_b").with_cpuset(CpusetSpec::disjoint(1, 2)),
            ]
            .into(),
            ops: vec![],
            hold: HoldSpec::Frac(0.4),
        },
        Step {
            setup: vec![].into(),
            ops: vec![Op::swap_cpusets("cell_a", "cell_b")],
            hold: HoldSpec::Frac(0.6),
        },
    ];
    execute_steps(ctx, steps)
}

// ---------------------------------------------------------------------------
// Custom: borrowing fairness
//
// Two cells on disjoint cpusets: `lender` has light load (1 worker on
// 2 CPUs), `borrower` has heavy load (6 workers on 2 CPUs).  With
// borrowing enabled, the borrower should use lender's idle CPUs
// without starving the lender's single worker.
// ---------------------------------------------------------------------------

#[ktstr_test(
    scheduler = MITOSIS_PAYLOAD,
    llcs = 2,
    cores = 2,
    duration_s = 20,
    watchdog_timeout_s = 8,
    required_flags = ["cpu-controller-disabled", "borrowing"],
    not_starved = true,
)]
fn mitosis_borrowing_fairness(ctx: &Ctx) -> Result<AssertResult> {
    execute_defs(
        ctx,
        vec![
            CgroupDef::named("lender")
                .with_cpuset(CpusetSpec::disjoint(0, 2))
                .workers(1),
            CgroupDef::named("borrower")
                .with_cpuset(CpusetSpec::disjoint(1, 2))
                .workers(6),
        ],
    )
}

// ---------------------------------------------------------------------------
// Custom: bad args
//
// make a nice error stall to show auto-repro tracing
// ---------------------------------------------------------------------------

#[ktstr_test(
    scheduler = MITOSIS_PAYLOAD,
    llcs = 1,
    cores = 4,
    duration_s = 60,
    watchdog_timeout_s = 30,
    excluded_flags = [MitosisFlags::CPU_CONTROLLER_DISABLED],
    expect_err = false,
)]
fn mitosis_bad_args(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![
        Step {
            setup: vec![
                CgroupDef::named("cell_a").with_cpuset(CpusetSpec::disjoint(0, 2)),
                CgroupDef::named("cell_b").with_cpuset(CpusetSpec::disjoint(1, 2)),
            ]
            .into(),
            ops: vec![],
            hold: HoldSpec::Frac(0.4),
        },
        Step {
            setup: vec![].into(),
            ops: vec![Op::swap_cpusets("cell_a", "cell_b")],
            hold: HoldSpec::Frac(0.3),
        },
        Step {
            setup: vec![].into(),
            ops: vec![Op::remove_cgroup("cell_a")],
            hold: HoldSpec::Frac(0.3),
        },
    ];
    execute_steps(ctx, steps)
}
// ---------------------------------------------------------------------------
// Custom: rebalancing convergence
//
// Three cells start with equal load, then one goes idle while another
// ramps up.  With rebalancing enabled, CPUs should migrate toward the
// busy cell.  Not-starved on the remaining active cells confirms
// rebalancing did not break scheduling.
// ---------------------------------------------------------------------------

fn scenario_rebalancing_convergence(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![
        Step {
            setup: vec![
                CgroupDef::named("stable"),
                CgroupDef::named("ramp"),
                CgroupDef::named("idle"),
            ]
            .into(),
            ops: vec![],
            hold: HoldSpec::Frac(0.3),
        },
        Step {
            setup: vec![].into(),
            ops: vec![
                Op::stop_cgroup("idle"),
                Op::spawn(
                    "ramp",
                    Work::default().workers(6).work_type(WorkType::CpuSpin),
                ),
            ],
            hold: HoldSpec::Frac(0.7),
        },
    ];
    execute_steps(ctx, steps)
}

#[ktstr::__private::linkme::distributed_slice(ktstr::test_support::KTSTR_TESTS)]
#[linkme(crate = ktstr::__private::linkme)]
static __KTSTR_ENTRY_REBALANCE: ktstr::test_support::KtstrTestEntry =
    ktstr::test_support::KtstrTestEntry {
        name: "mitosis_rebalancing_convergence",
        func: scenario_rebalancing_convergence,
        scheduler: &MITOSIS_PAYLOAD,
        required_flags: &[
            MitosisFlags::CPU_CONTROLLER_DISABLED,
            MitosisFlags::REBALANCING,
        ],
        duration: Duration::from_secs(25),
        watchdog_timeout: Duration::from_secs(10),
        ..ktstr::test_support::KtstrTestEntry::DEFAULT
    };
