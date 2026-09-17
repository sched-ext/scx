// SPDX-License-Identifier: GPL-2.0
/*
 * Slot store helpers
 *
 * Holds the per CPU bounded LIFO slot helpers that mirror the BPF header so
 * behavior stays the same on both sides of the boundary. Each CPU holds two
 * queues plus 2 overflow tails with bounded LIFO at K 8 and no knob. The
 * probe maps one deadline to near or overflow, pinned tasks rest in
 * overflow, dispatch drains own plus overflow plus peer steal with same
 * group first and perf only cross second, defer counts capped drains with
 * work left, and the kick chain keeps idle owners moving.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/* Tasks moved by one slot trip at most. Fixed at 4 with no knob. */
pub const SLOT_D: u32 = 4;
/* Tasks moved by one dispatch pass at most. Fixed at 32 with no knob. */
pub const SLOT_BUDGET: u32 = 32;
/* Own queue cap at budget minus one. Fixed at 31 with no knob. */
#[cfg(test)]
pub const SLOT_OWN_CAP: u32 = 31;
/* Zero-move sweep bound. Fixed at 256 with no knob. */
#[cfg(test)]
pub const SWEEP_MAX: u16 = 256;
/* Base id of the per CPU queues. */
#[cfg(test)]
pub const SLOT_BASE: u64 = 0x6000;
/* Base id of the group overflow tails. Relocated to 0x6800 with no share. */
#[cfg(test)]
pub const SLOT_OVERFLOW_BASE: u64 = 0x6800;
/* Overflow tails, one per group. */
#[cfg(test)]
pub const SLOT_OVERFLOW_N: u64 = 2;
/* Queues per CPU. One light plus one hog with no share. */
#[cfg(test)]
pub const SLOT_PER_CPU: u64 = 2;
/* Max DSQs at 1024 CPUs. Holds 2 times 1024 plus 2 with no share. */
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 2050;
/* Slot width in nanos near 64us. */
#[cfg(test)]
pub const WHEEL_SLOT_NS: u64 = 64_000;
/* Near slots covered by per CPU insert. */
#[cfg(test)]
pub const WHEEL_DIM: u64 = 256;
/* Slots covered by the probe. */
#[cfg(test)]
pub const WHEEL_TOTAL: u64 = 65536;
/* Horizon in nanos near 4.19s in vruntime. */
#[cfg(test)]
pub const WHEEL_HORIZON_NS: u64 = 64_000 * 65536;
/* Low 16 bits cleared by the quantise step. */
#[cfg(test)]
pub const WHEEL_QUANT_LO: u64 = 0xFFFF;
/* Tokens held per CPU for the sleeper boost. */
#[cfg(test)]
pub const TOKEN_MAX: u32 = 255;
/* Head inserts in one LIFO period at 8 with one tail. */
#[cfg(test)]
pub const LIFO_K: u64 = 8;
/* Inserts in one LIFO period at 9 with 8 heads. */
#[cfg(test)]
pub const LIFO_PERIOD: u64 = 9;
/* LIFO sequences at 2050 with per CPU plus overflow. */
#[cfg(test)]
pub const LIFO_NSEQ: u64 = 2050;

/*
 * Deadline with the low 16 bits cleared near 64us
 * down. Clearing moves early only, so order never
 * moves late with at most 65535ns of earliness.
 */
#[cfg(test)]
pub fn qdl_round_down(dl: u64) -> u64 {
    dl & !WHEEL_QUANT_LO
}

/*
 * Probe of one deadline into quantised deadline,
 * slot, error, and overflow. Overdue keeps the
 * rounded deadline with slot zero and no overflow.
 * Inside keeps the rounded deadline with the slot
 * from the rounded distance shifted by 16. Outside
 * pins to the tail with the last slot and overflow
 * set. Error holds deadline minus rounded deadline
 * in 0 to 65535. Mirrors the BPF probe with one
 * horizon test and no double read.
 */
#[cfg(test)]
pub fn wheel_probe(dl: u64, frontier: u64) -> (u64, u64, u64, bool) {
    let err = dl & WHEEL_QUANT_LO;
    let overdue = crate::flow_edf::time_before(dl, frontier);
    let inside = overdue || dl.wrapping_sub(frontier) < WHEEL_HORIZON_NS;
    if !inside {
        let tail = frontier.wrapping_add(WHEEL_HORIZON_NS).wrapping_sub(1);
        return (qdl_round_down(tail), WHEEL_TOTAL - 1, err, true);
    }
    let qdl = qdl_round_down(dl);
    if crate::flow_edf::time_before(qdl, frontier) {
        return (qdl, 0, err, false);
    }
    let mut s = qdl.wrapping_sub(frontier) >> 16;
    if s >= WHEEL_TOTAL {
        s = WHEEL_TOTAL - 1;
    }
    (qdl, s, err, false)
}

/*
 * True when one sleeper may spend one token for a
 * boost. Needs a clamped lag with a live token, an
 * estimate at or below one slice, burn below 4ms,
 * and quant error at or below 64us, so the boost
 * stays bounded with no late move. Mirrors the BPF
 * conjunct in gate order.
 */
#[cfg(test)]
pub fn token_eligible(clamped: bool, tok: u32, est: u64, burn: u32, err: u64) -> bool {
    clamped
        && tok != 0
        && est <= crate::flow_slice::SLICE_NS
        && (burn as u64) < crate::flow_group::PROMOTE_BURN_NS
        && err <= WHEEL_SLOT_NS
}

/*
 * Slot id of one group overflow with light as
 * default. Holds overflow base plus group, so two
 * tails keep queue order per group with no share.
 * Bad group falls to light with no trap. Slot only,
 * never vtime.
 */
#[cfg(test)]
pub fn slot_overflow_dsq(group: u8) -> u64 {
    if group == crate::flow_group::GROUP_HOG {
        SLOT_OVERFLOW_BASE + 1
    } else {
        SLOT_OVERFLOW_BASE
    }
}

/*
 * Slot id of one CPU group with light as default.
 * Holds base plus CPU times two plus group, so two
 * per CPU keep light and hog apart with no share.
 * Bad group falls to light with no trap. Slot only,
 * never vtime. Mirrors the BPF per CPU helper.
 */
#[cfg(test)]
pub fn slot_cpu_dsq(cpu: u32, group: u8) -> u64 {
    let g = if group == crate::flow_group::GROUP_HOG {
        1
    } else {
        0
    };
    SLOT_BASE + cpu as u64 * 2 + g
}

/*
 * Count of DSQs for one host with per CPU plus
 * overflow. Holds two times nr plus two, so eight
 * CPUs need eighteen queues with 2050 max at 1024
 * CPUs and no share. Mirrors the BPF count helper.
 */
#[cfg(test)]
pub fn slot_nr_dsqs(nr: u64) -> u64 {
    nr * 2 + 2
}

/*
 * Least donor depth for one steal with idle empty
 * fast path. Holds one when idle empty, else two,
 * so idle owners collect the last task with no
 * strand. Mirrors the BPF steal need helper.
 */
#[cfg(test)]
pub fn steal_need(idle_empty: bool) -> u64 {
    if idle_empty {
        1
    } else {
        crate::flow_select::STEAL_MIN_DEPTH
    }
}

/*
 * DSQ id for one per CPU insert with pinned
 * overflow. Pinned tasks rest in the group overflow
 * tail with no per CPU use, so every owner dispatch
 * visits them in the window with mask wins. Migratable
 * tasks keep the per CPU queue or the horizon tail.
 * Dead CPUs rest in overflow with fail closed, so
 * negative plus past live plus past 1024 all pin
 * to the tail with no trap. Mirrors the BPF per
 * CPU branch with the same group fallback.
 */
#[cfg(test)]
pub fn insert_cpu_dsq(cpu: i32, group: u8, slot: u64, pinned: bool, nr: usize) -> u64 {
    if pinned {
        return slot_overflow_dsq(group);
    }
    if slot >= WHEEL_DIM {
        return slot_overflow_dsq(group);
    }
    if cpu < 0 {
        return slot_overflow_dsq(group);
    }
    if (cpu as usize) >= nr {
        return slot_overflow_dsq(group);
    }
    if (cpu as u64) >= 1024 {
        return slot_overflow_dsq(group);
    }
    slot_cpu_dsq(cpu as u32, group)
}

/*
 * Four local queue ids for one dispatch. Holds own
 * per CPU own group, own overflow, other per CPU,
 * and other overflow in drain order with no share.
 * Mirrors the BPF local trip ids with no drain use.
 */
#[cfg(test)]
pub fn local_trip_dsqs(cpu: u32, group: u8) -> [u64; 4] {
    let other = if group == crate::flow_group::GROUP_HOG {
        crate::flow_group::GROUP_LIGHT
    } else {
        crate::flow_group::GROUP_HOG
    };
    [
        slot_cpu_dsq(cpu, group),
        slot_overflow_dsq(group),
        slot_cpu_dsq(cpu, other),
        slot_overflow_dsq(other),
    ]
}

/*
 * Cap of one trip at D under the dispatch budget.
 * Returns the min of budget and 4, so one per CPU
 * queue or overflow moves at most 4 with the shared
 * loop and no K loop. Mirrors the BPF drain cap.
 */
#[cfg(test)]
pub fn slot_cap(budget: u32) -> u32 {
    budget.min(SLOT_D)
}

/*
 * Own queue cap at budget minus one. Holds 31 with
 * budget 32, so one slot stays for overflow, other
 * CPU, other overflow, plus steal with no strand on
 * a hot own queue. Zero stays zero. Mirrors the BPF
 * own cap reserve.
 */
#[cfg(test)]
pub fn slot_own_cap(budget: u32) -> u32 {
    budget.saturating_sub(1)
}

/*
 * Drain up to a cap from one slot queue for one CPU.
 * The scan visits every queued task in queue order
 * and moves each live task with the CPU in the mask
 * and with no move failure. Dead, foreign, and failed
 * tasks are skipped with progress, so one bad head
 * never blocks later work. Base carries moved so far
 * with the cap kept whole, so the stop reads one sum
 * like the BPF shared body. Returns the count moved.
 * A zero return means no movable work was present.
 */
#[cfg(test)]
pub fn slot_drain_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
) -> u32 {
    let mut moved = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let ok = moved + base < cap
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
 * True when one dispatch counts a defer. Needs moves
 * at or past D with work left in the window, so a
 * saturated queue reports back pressure with one
 * count. Mirrors the BPF defer gate with no drain
 * use.
 */
#[cfg(test)]
pub fn defer_ok(moved: u32, window_left: bool) -> bool {
    moved >= SLOT_D && window_left
}

/*
 * Kick step for one dispatch with the sweep count.
 * A zero-move dispatch with window work kicks until
 * the sweep bound at 256, so unmovable-only window
 * work stops polling with no infinite loop. Any move
 * resets the sweep with no extra pass. Moves with
 * window ride the next natural dispatch with no kick,
 * since the loop already visited every task and the
 * CPU runs the moved work before the next pass. Steady
 * state stays quiet with kicks per dispatch well below
 * one. Returns whether to kick and the next sweep
 * count. Mirrors the BPF safety net with zero-move
 * window only.
 */
#[cfg(test)]
pub fn kick_step(moved: u32, window_left: bool, sweep: u16) -> (bool, u16) {
    if moved == 0 && window_left && sweep < SWEEP_MAX {
        return (true, sweep + 1);
    }
    if moved > 0 {
        return (false, 0);
    }
    (false, sweep)
}

/*
 * True when one local window holds work. Window holds
 * own per CPU plus own overflow plus other per CPU
 * plus other overflow, so trips drain it with no peer
 * need. Mirrors the BPF window gate with four reads.
 */
#[cfg(test)]
pub fn window_has_work(own: bool, own_over: bool, other: bool, other_over: bool) -> bool {
    own || own_over || other || other_over
}

/*
 * Fold counts from one shared steal drain with post hoc mark.
 * Adds got to steal moves for all peer moves and got times
 * mark to steal x moves for the cross subset with two
 * unconditional adds, so zero keeps count still with no
 * branch on cross. Mirrors the BPF fold with LSB compare
 * after the drain and single move with lim at moved plus
 * one. Returns the pair of adds in steal moves order then
 * steal x moves order. See src/bpf/dispatch.bpf.c for the
 * drain use.
 */
#[cfg(test)]
pub fn steal_fold_counts(got: u32, steal_dsq: u64, sgroup: u8) -> (u64, u64) {
    let x = crate::flow_select::steal_cross_x(steal_dsq, sgroup);
    (got as u64, (got as u64) * x)
}

/*
 * First donor DSQ id from one scan window with keep first.
 * Visits bound peers from start with wrap and keeps the
 * first peer with queued at or past need, so shallow donors
 * skip early with no iterator. Mirrors the BPF keep first
 * scan with live check and need. Returns the DSQ id on hit
 * and none on miss with no drain use. See
 * src/bpf/dispatch.bpf.c for the scan use.
 */
#[cfg(test)]
pub fn steal_first_donor(
    start: u32,
    nr: usize,
    group: u8,
    need: u64,
    depths: &[u64],
) -> Option<u64> {
    if nr <= 1 {
        return None;
    }
    for off in 0..crate::flow_select::STEAL_BOUND as u32 {
        let peer = start.wrapping_add(off) % nr as u32;
        if (peer as usize) >= nr {
            continue;
        }
        if (peer as u64) >= 1024 {
            continue;
        }
        let q = depths.get(peer as usize).copied().unwrap_or(0);
        if q < need {
            continue;
        }
        return Some(slot_cpu_dsq(peer, group));
    }
    None
}

/*
 * Pick from two scan windows with strict and perf models.
 * Scans same group first and returns the same donor on hit
 * with no cross use, so strict stays same group only with
 * zero cross. Scans other group second from start plus 8
 * on same group miss when perf holds, so perf adds cross
 * cover with no extra drain. Single CPU hosts skip the
 * whole pass with one check. Mirrors the BPF fold with one
 * shared drain and single move. Returns the DSQ id with
 * cross flag on hit and none on miss. See
 * src/bpf/dispatch.bpf.c for the drain use.
 */
#[cfg(test)]
pub fn steal_pick_fold(
    start: u32,
    nr: usize,
    sgroup: u8,
    ogroup: u8,
    need: u64,
    same_depths: &[u64],
    cross_depths: &[u64],
    perf: bool,
) -> Option<(u64, bool)> {
    if nr <= 1 {
        return None;
    }
    if let Some(dsq) = steal_first_donor(start, nr, sgroup, need, same_depths) {
        return Some((dsq, false));
    }
    if !perf {
        return None;
    }
    let cross_start = start.wrapping_add(8);
    if let Some(dsq) = steal_first_donor(cross_start, nr, ogroup, need, cross_depths) {
        return Some((dsq, true));
    }
    None
}

/*
 * True when one insert takes head with bounded LIFO at K 8. Takes head for 8
 * of 9 with one tail plus one forced tail at MAX, so fresh work wins fast
 * with no starve or preempt use. Forced tails at period plus MAX keep
 * max gap 9 with 8 heads everywhere with wrap, so the bound stays exact
 * with one compare and no new state. Pure with no BSS use, so BPF and
 * tests share the period with no drift. Mirrors the BPF take head with
 * the same modulo plus MAX.
 */
#[cfg(test)]
pub fn lifo_take_head(seq: u32) -> bool {
    if seq == u32::MAX {
        return false;
    }
    (seq as u64 % LIFO_PERIOD) != LIFO_K
}

/*
 * Index of one LIFO sequence with per CPU plus overflow at 2050. Per CPU
 * holds CPU times 2 plus group, overflow holds 2048 plus group, so total
 * 2050 matches slot max with no share. Bad group falls to light with no
 * trap. Pure with no state. Mirrors the BPF index with the same map.
 */
#[cfg(test)]
pub fn lifo_idx(over: bool, cpu: u32, group: u8) -> u32 {
    let g = if group == crate::flow_group::GROUP_HOG {
        1
    } else {
        0
    };
    if over { 2048 + g } else { cpu * 2 + g }
}
