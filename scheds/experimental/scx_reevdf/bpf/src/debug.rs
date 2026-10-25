// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! What the scheduler adds to the kernel's debug dump, ops.dump_task(). The
//! exit record is uei.rs.
//!
//! Counterpart in scx_eevdf: main.bpf.c.

use scx_rustsched::{dump::DumpCtx, task::Task};

use crate::{config, pack, taskctx};
use scx_rustsched::dsq::{self, Edq};

/// Whether a stalled task is still in its CID's queue and how its virtual
/// time compares with the queue's: the kernel's dump shows BPF custody,
/// but cannot tell a queued task from one whose queue node was lost. Only
/// tasks runnable for at least a second, the ones the watchdog is about.
#[inline(always)]
pub fn dump_task(dump: &DumpCtx, task: &Task) {
    let now = dump.at_jiffies();
    let runnable_at = task.runnable_at();
    if now < runnable_at || (now - runnable_at) * config::get(config::TICK_NS) < 1_000_000_000 {
        return;
    }
    let Some(state) = taskctx::lookup(task) else {
        return;
    };
    let pid = task.pid();
    let cid = task.cid();
    let Some(queued) = dsq::inspect(task, Edq::Cid(cid)) else {
        return;
    };
    // Opaque, so that LLVM does not fold zeroed slots into a memset.
    let zero = core::hint::black_box(0_u64);
    if !pack::valid(cid) {
        scx_rustsched::dump!(
            "reevdf pid=%lld cid=%lld state=%llu linked=%llu hold=%lld nr=%llu",
            pid,
            cid.raw(),
            queued.state,
            zero,
            queued.holds,
            zero
        );
        return;
    }
    scx_rustsched::dump!(
        "reevdf pid=%lld cid=%lld state=%llu linked=%llu hold=%lld nr=%llu",
        pid,
        cid.raw(),
        queued.state,
        u64::from(queued.linked),
        queued.holds,
        cid.nr_queued()
    );
    let (key, eligibility) = (queued.deadline, queued.vtime);
    scx_rustsched::dump!(
        "reevdf v=%llu d=%llu key=%llu elig=%llu V=%llu w=%llu",
        state.vtime().get(),
        state.deadline().get(),
        key,
        eligibility,
        pack::reference_at(cid, dump.at_ns()),
        state.joined_weight().get()
    );
    scx_rustsched::dump!(
        "reevdf head=%llu W=%llu request=%llu lag=%lld",
        dsq::peek(Edq::Cid(cid), None).deadline.unwrap_or(0),
        pack::weight(cid),
        state.request().slice,
        state.lag().get()
    );
}
