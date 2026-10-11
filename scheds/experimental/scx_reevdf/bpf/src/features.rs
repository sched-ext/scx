// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Switches for turning one rule of fair.c off at a time, for comparing it
//! against the rule that replaces it. Each is the tunable of a --no-*
//! option of the loader, which says what it does.

use crate::{
    NO_DELAY_DEQUEUE, NO_DELAY_REQUEUE, NO_ELIGIBILITY, NO_ELIGIBLE_SCAN, NO_HRTICK, NO_PLACE_LAG,
    NO_PLACE_REL_DEADLINE, NO_PREEMPT_SHORT, NO_RUN_TO_PARITY, NO_VREF_UPDATE, NO_WAKE_SYNC,
    NO_WAKEUP_PREEMPT,
};

/// Wakeup preemption.
#[inline(always)]
pub fn wakeup_preempt() -> bool {
    !NO_WAKEUP_PREEMPT.get()
}

/// Asking who is owed service, entity_eligible(), rather than deciding on
/// deadlines alone.
#[inline(always)]
pub fn eligibility() -> bool {
    !NO_ELIGIBILITY.get()
}

/// Dispatch takes the first eligible task rather than the head. Implied
/// off by --no-eligibility.
#[inline(always)]
pub fn eligible_scan() -> bool {
    !NO_ELIGIBLE_SCAN.get() && !NO_ELIGIBILITY.get()
}

/// RUN_TO_PARITY: a running task owed service keeps the CPU until it has
/// had it. --no-eligibility drops it too.
#[inline(always)]
pub fn run_to_parity() -> bool {
    !NO_RUN_TO_PARITY.get() && !NO_ELIGIBILITY.get()
}

/// PREEMPT_SHORT.
#[inline(always)]
pub fn preempt_short() -> bool {
    !NO_PREEMPT_SHORT.get()
}

/// PLACE_LAG's compensation for the reference moving as the task joins.
#[inline(always)]
pub fn place_lag() -> bool {
    !NO_PLACE_LAG.get()
}

/// PLACE_REL_DEADLINE.
#[inline(always)]
pub fn place_rel_deadline() -> bool {
    !NO_PLACE_REL_DEADLINE.get()
}

/// DELAY_DEQUEUE and DELAY_ZERO.
#[inline(always)]
pub fn delay_dequeue() -> bool {
    !NO_DELAY_DEQUEUE.get()
}

/// ttwu_runnable()'s requeue of a delayed task. Implied off by
/// --no-delay-dequeue.
#[inline(always)]
pub fn delay_requeue() -> bool {
    !NO_DELAY_REQUEUE.get() && !NO_DELAY_DEQUEUE.get()
}

/// HRTICK.
#[inline(always)]
pub fn hrtick() -> bool {
    !NO_HRTICK.get()
}

/// update_curr() before every placement and eligibility test.
#[inline(always)]
pub fn vref_update() -> bool {
    !NO_VREF_UPDATE.get()
}

/// The sync wakeup path of wake_affine().
#[inline(always)]
pub fn wake_sync() -> bool {
    !NO_WAKE_SYNC.get()
}
