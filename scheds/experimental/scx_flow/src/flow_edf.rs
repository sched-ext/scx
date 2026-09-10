/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Deadline and queue helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 * The slice is fixed at 1ms with no knob.
 */

/* Bound of moved tasks in one pass. */
pub const DISPATCH_BATCH: u32 = 32;
/* Base id of the per CPU ordered queues. */
#[cfg(test)]
pub const DSQ_BASE: u64 = 0x4000;
/* Park id for tasks with no allowed CPU. */
#[cfg(test)]
pub const DSQ_PARK: u64 = 0x5000;

/*
 * True when the first time is before the second with
 * wrap safety. The signed diff keeps order across the
 * u64 wrap with no extra branch.
 */
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/*
 * Clamp virtual time to a bounded lag behind the
 * frontier. The floor is the frontier minus one slice
 * with wrap. A lagging value moves forward to the
 * floor with a clamp count. A fresh value stays.
 */
#[cfg(test)]
pub fn clamp_vruntime(v: u64, frontier: u64, slice: u64) -> u64 {
    let floor = frontier.wrapping_sub(slice);
    if time_before(v, floor) { floor } else { v }
}

/*
 * True when virtual time was clamped forward. Needs a
 * lag beyond one slice, so only sleepers count.
 */
#[cfg(test)]
pub fn was_clamped(v: u64, frontier: u64, slice: u64) -> bool {
    clamp_vruntime(v, frontier, slice) != v
}

/*
 * Clamp virtual time with a weight scaled cap. The floor
 * is the frontier minus the cap with wrap, same as the
 * fixed clamp with slice at 1024. Heavy tasks keep a
 * short cap, light tasks keep a long cap, both held in
 * slice over 8 to slice times 8.
 */
#[cfg(test)]
pub fn clamp_vruntime_w(v: u64, frontier: u64, slice: u64, weight: u32) -> u64 {
    let cap = crate::flow_slice::cap_for_weight(weight, slice);
    let floor = frontier.wrapping_sub(cap);
    if time_before(v, floor) { floor } else { v }
}

/*
 * True when weight scaled time was clamped forward.
 * Needs a lag beyond the cap, so only sleepers count.
 */
#[cfg(test)]
pub fn was_clamped_w(v: u64, frontier: u64, slice: u64, weight: u32) -> bool {
    clamp_vruntime_w(v, frontier, slice, weight) != v
}

/*
 * Deadline from clamped virtual time and scaled
 * estimate. The sum wraps with the clock with no
 * extra check, so order stays correct across wrap.
 */
#[cfg(test)]
pub fn deadline(clamped_v: u64, scaled: u64) -> u64 {
    clamped_v.wrapping_add(scaled)
}

/*
 * Advance virtual time by scaled runtime. The sum
 * wraps with the clock, so long runs stay ordered
 * across wrap with no extra check.
 */
#[cfg(test)]
pub fn vruntime_add(v: u64, delta: u64) -> u64 {
    v.wrapping_add(delta)
}

/*
 * Max of two virtual times with wrap safety. The later
 * time wins, so the frontier never moves backward
 * while work stays queued.
 */
#[cfg(test)]
pub fn frontier_max(old: u64, next: u64) -> u64 {
    if time_before(old, next) { next } else { old }
}

/*
 * Frontier for an idle CPU from the waking virtual
 * time. The waking value bounds the reset with no
 * zero use, so a new arrival never inherits stale
 * time while queued work never moves backward. The
 * caller keeps the old frontier when the waking value
 * is zero, so zero never disorders the frontier.
 */
#[cfg(test)]
pub fn frontier_idle(waking_v: u64) -> u64 {
    waking_v
}

/*
 * Guarded idle frontier. Keeps the old frontier when
 * the waking value is zero, so zero never disorders
 * the frontier. Otherwise resets to the waking value.
 */
#[cfg(test)]
pub fn frontier_idle_guarded(old: u64, waking_v: u64) -> u64 {
    if waking_v == 0 {
        old
    } else {
        frontier_idle(waking_v)
    }
}

/*
 * Full EDF insert model. Clamps the virtual time with the
 * weight scaled cap, scales the estimate, and adds the
 * deadline with wrap. Returns the clamped time, the
 * deadline, and the clamp flag for counts. Matches the
 * BPF enqueue paths that clamp with the weight cap.
 */
#[cfg(test)]
pub fn edf_insert(v: u64, frontier: u64, slice: u64, est: u64, weight: u32) -> (u64, u64, bool) {
    let clamped = clamp_vruntime_w(v, frontier, slice, weight);
    let flag = clamped != v;
    let est_c = crate::flow_slice::clamp_est(est);
    let scaled = crate::flow_slice::scale_by_weight(est_c, weight);
    let dl = deadline(clamped, scaled);
    (clamped, dl, flag)
}

/*
 * Frontier step for a stop. A runnable stop or queued
 * work keeps the max, so time never moves backward
 * while work stays queued. An idle block resets to the
 * waking virtual time with no zero use. A zero waking
 * value keeps the old frontier, so zero never
 * disorders the frontier.
 */
#[cfg(test)]
pub fn frontier_step(old: u64, new_v: u64, runnable: bool, queued: u64) -> u64 {
    if !runnable && queued == 0 {
        frontier_idle_guarded(old, new_v)
    } else {
        frontier_max(old, new_v)
    }
}

/*
 * Sentinel for a consumed completion. The deadline
 * holds max when no grant is outstanding, so a block
 * plus a disable plus an exit count one task once.
 * Enable starts consumed. Each insert regrants with a
 * real deadline. Each completion consumes once.
 */
#[cfg(test)]
pub const COMPLETED_SENTINEL: u64 = u64::MAX;

/*
 * Take one completion when a grant is outstanding.
 * Returns true once per grant and consumes the grant,
 * so a later block, disable, or exit sees consumed and
 * counts nothing. Returns false when already consumed.
 */
#[cfg(test)]
pub fn completion_take(deadline: &mut u64) -> bool {
    if *deadline == COMPLETED_SENTINEL {
        return false;
    }
    *deadline = COMPLETED_SENTINEL;
    true
}

/*
 * Grant one completion slot from a fresh deadline. A
 * computed max maps to max minus one, so the grant
 * never collides with the consumed sentinel.
 */
#[cfg(test)]
pub fn completion_grant(deadline: &mut u64, dl: u64) {
    if dl == COMPLETED_SENTINEL {
        *deadline = COMPLETED_SENTINEL - 1;
    } else {
        *deadline = dl;
    }
}

/*
 * Combined insert plus frontier step for tests. Runs
 * the insert model then advances virtual time by the
 * scaled estimate and steps the frontier, so callers
 * see the clamped time plus the deadline plus the next
 * frontier at once with no extra path.
 */
#[cfg(test)]
pub fn edf_insert_and_step(
    v: u64,
    frontier: u64,
    slice: u64,
    est: u64,
    weight: u32,
    runnable: bool,
    queued: u64,
) -> (u64, u64, u64, bool) {
    let (clamped, dl, flag) = edf_insert(v, frontier, slice, est, weight);
    let est_c = crate::flow_slice::clamp_est(est);
    let scaled = crate::flow_slice::scale_by_weight(est_c, weight);
    let next_v = vruntime_add(clamped, scaled);
    let next = frontier_step(frontier, next_v, runnable, queued);
    (clamped, dl, next, flag)
}

/*
 * Ordered entry for tests. The deadline orders the
 * queue. The sequence keeps arrival order when
 * deadlines match.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedEntry {
    /* Clamped virtual time plus scaled estimate. */
    pub deadline: u64,
    /* Arrival sequence used for ties. Lower is older. */
    pub seq: u64,
    /* Task id used only to name the entry. */
    pub id: u64,
}

#[cfg(test)]
impl OrderedEntry {
    /*
     * True when this entry sorts before the other. The
     * smaller deadline wins. Equal deadlines keep
     * arrival order with the older sequence first.
     */
    pub fn before(&self, other: &Self) -> bool {
        if self.deadline != other.deadline {
            return time_before(self.deadline, other.deadline);
        }
        self.seq < other.seq
    }
}

/*
 * Insert one entry into an ordered queue. The queue
 * stays sorted by deadline with arrival order for
 * ties. Returns the position of the new entry.
 */
#[cfg(test)]
pub fn ordered_insert(queue: &mut Vec<OrderedEntry>, entry: OrderedEntry) -> usize {
    let mut pos = queue.len();
    for (i, cur) in queue.iter().enumerate() {
        if entry.before(cur) {
            pos = i;
            break;
        }
    }
    queue.insert(pos, entry);
    pos
}

/*
 * Drain up to budget tasks for one CPU. The scan
 * visits every queued task in order and moves each
 * live task with the CPU in the mask and with no
 * move failure. Dead, foreign, and failed heads are
 * skipped, so one head never blocks later work.
 * Returns the count moved. A zero return means no
 * movable work was present.
 */
#[cfg(test)]
pub fn drain_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    budget: u32,
) -> u32 {
    let mut moved = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let ok = moved < budget
            && task.live
            && !task.fail
            && crate::flow_select::may_run_on(cpu, &task.allowed);
        if ok {
            moved += 1;
        } else {
            kept.push_back(task);
        }
    }
    *queue = kept;
    moved
}

/*
 * Dispatch own then park in fixed order. Drains own
 * with the full budget, returns early when saturated,
 * then drains park with the rest when park holds work.
 * The total never exceeds budget. A saturated own
 * leaves park waiting, which matches the BPF dispatch
 * order with no reserve and no new path.
 */
#[cfg(test)]
pub fn dispatch_own_park_model(
    own: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    park: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    budget: u32,
) -> (u32, u32) {
    let moved_own = drain_model(own, cpu, budget);
    if moved_own >= budget {
        return (moved_own, 0);
    }
    if park.is_empty() {
        return (moved_own, 0);
    }
    let moved_park = drain_model(park, cpu, budget - moved_own);
    (moved_own, moved_park)
}

/*
 * Running view of one CPU for tests. Mirrors the BPF
 * CPU state fields used by the dashboard. Zero pid
 * means idle. Nice plus weight stay display only with
 * no placement use.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningView {
    /* Estimate of the task now on the CPU. */
    pub est: u64,
    /* Pid now on the CPU. Zero when idle. */
    pub pid: u32,
    /* Nice now on the CPU. Zero when idle. */
    pub nice: i32,
    /* Weight now on the CPU. 1024 when idle. */
    pub weight: u32,
}

#[cfg(test)]
impl RunningView {
    /*
     * Idle view with neutral weight. Matches the
     * cleared BPF state after stopping.
     */
    pub fn idle() -> Self {
        Self {
            est: 0,
            pid: 0,
            nice: 0,
            weight: 1024,
        }
    }

    /*
     * True when no task runs on the CPU. The dashboard
     * uses the pid for this check.
     */
    pub fn is_idle(&self) -> bool {
        self.pid == 0
    }

    /*
     * Clear the view to idle. Mirrors the stopping path
     * that clears the BPF running fields at once.
     */
    pub fn clear(&mut self) {
        self.est = 0;
        self.pid = 0;
        self.nice = 0;
        self.weight = 1024;
    }

    /*
     * Clear the view only when the pid owns it. Mirrors
     * the disable plus exit path that clears the BPF
     * running fields only on owner match, so a stale
     * exit never clears a new owner after a switch.
     */
    pub fn clear_if_owner(&mut self, pid: u32) {
        if self.pid == pid {
            self.est = 0;
            self.pid = 0;
            self.nice = 0;
            self.weight = 1024;
        }
    }
}
