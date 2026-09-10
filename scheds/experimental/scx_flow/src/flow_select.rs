/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Placement and steal helpers for the flow scheduler.
 * The functions mirror the BPF side so behavior stays
 * the same on both sides of the boundary. Frequency
 * plus LLC plus CPU cards stay display only and never
 * shape placement.
 */

/* Compile time CPU bound. Mirrors the BPF header. */
#[cfg(test)]
pub const MAX_CPUS: u32 = 1024;
/* Bound of peers visited by one steal scan. */
#[cfg(test)]
pub const STEAL_BOUND: usize = 8;
/* Least donor depth that allows a steal. */
#[cfg(test)]
pub const STEAL_MIN_DEPTH: u64 = 2;
/* Coalesce window in nanos at 50us. */
#[cfg(test)]
pub const KICK_COALESCE_NS: u64 = 50_000;

/*
 * Queue id of one CPU. Returns none for an out of
 * range id, so callers fall back to the park queue.
 */
#[cfg(test)]
pub fn dsq_for_cpu(cpu: u32, max: usize) -> Option<u64> {
    if (cpu as usize) >= max {
        return None;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return None;
    }
    Some(crate::flow_edf::DSQ_BASE + cpu as u64)
}

/*
 * Next peer for a steal scan. Returns none with one
 * or no CPUs, so scans end at once with a single CPU
 * and no peers. Returns none for an out of range CPU.
 */
#[cfg(test)]
pub fn next_peer(cpu: u32, nr_cpus: usize) -> Option<u32> {
    if nr_cpus <= 1 {
        return None;
    }
    if (cpu as usize) >= nr_cpus {
        return None;
    }
    Some((cpu + 1) % nr_cpus as u32)
}

/*
 * Bound of a peer scan. Zero with one or no CPUs, so
 * steal scans and rotation end at once with a single
 * CPU. Otherwise capped by the steal bound and by one
 * less than the CPU count.
 */
#[cfg(test)]
pub fn scan_bound(nr_cpus: usize) -> usize {
    if nr_cpus <= 1 {
        return 0;
    }
    (nr_cpus - 1).min(STEAL_BOUND)
}

/*
 * Next steal cursor. The cursor rotates, so repeated
 * scans spread across peers.
 */
#[cfg(test)]
pub fn steal_next(cursor: u32, nr_cpus: usize) -> u32 {
    if nr_cpus == 0 {
        return 0;
    }
    (cursor + 1) % nr_cpus as u32
}

/*
 * Check that a CPU may run a task with the given
 * mask. Mirrors the BPF live plus range plus mask
 * check. A negative CPU fails closed. A CPU at or
 * past 1024 fails closed as test only bound. Live
 * CPUs are modelled by the mask length in tests, so
 * callers keep the mask sized to live CPUs. A missing
 * entry fails closed.
 */
#[cfg(test)]
pub fn may_run_on(cpu: i32, allowed: &[bool]) -> bool {
    if cpu < 0 {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    if let Some(&ok) = allowed.get(cpu as usize) {
        return ok;
    }
    false
}

/*
 * Check that a CPU is live for tests. Needs a CPU at
 * zero or past zero and below live count and below
 * 1024, so out of range CPUs fail closed with no
 * queue use. Mirrors the BPF live check with no mask.
 */
#[cfg(test)]
pub fn cpu_live(cpu: i32, nr_cpus: usize) -> bool {
    if cpu < 0 {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    (cpu as usize) < nr_cpus
}

/*
 * Check that a CPU is live and allowed for tests.
 * Needs a live CPU with the mask set, so dead CPUs
 * and foreign CPUs fail closed at once.
 */
#[cfg(test)]
pub fn may_run_on_live(cpu: i32, allowed: &[bool], nr_cpus: usize) -> bool {
    if !cpu_live(cpu, nr_cpus) {
        return false;
    }
    may_run_on(cpu, allowed)
}

/*
 * True when a donor queue may lose one task. Tier 0
 * model only. Needs at least two queued tasks, or one
 * queued task with a rescue when the thief is idle
 * with no moved plus no own left past unmovable park
 * leftovers or when the donor is asleep with no running
 * task. Busy thieves with a running donor keep the last
 * task. BPF ships thief idle only by construction due
 * to verifier jump at 1000001 on asleep check, with
 * donor asleep handled by idle kick.
 */
#[cfg(test)]
pub fn donor_ok(depth: u64, allow_single: bool, donor_idle: bool) -> bool {
    if depth >= STEAL_MIN_DEPTH {
        return true;
    }
    if depth == 1 && (allow_single || donor_idle) {
        return true;
    }
    false
}

/*
 * True when a thief may rescue a lone queued task.
 * Needs no moved work plus no own left past unmovable
 * park leftovers, so idle thieves rescue singletons
 * even when the park holds only unmovable entries.
 * Mirrors the BPF min depth gate with no park use.
 */
#[cfg(test)]
pub fn rescue_single_ok(moved: u32, own_left: u64) -> bool {
    moved == 0 && own_left == 0
}

/*
 * First idle CPU in the mask. Models the any idle
 * step. Returns none when no allowed CPU is idle.
 * Frequency plus LLC plus CPU cards stay display only
 * and never feed this choice.
 */
#[cfg(test)]
pub fn pick_any_idle(allowed: &[bool], idle: &[bool]) -> Option<u32> {
    for (cpu, &ok) in allowed.iter().enumerate() {
        if !ok {
            continue;
        }
        if let Some(true) = idle.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * Full select model. Mirrors the BPF order of any idle
 * plus previous plus current plus first. Returns none
 * for park use when no CPU allows. Frequency plus LLC
 * plus CPU cards stay display only and never feed this
 * choice.
 */
#[cfg(test)]
pub fn select_cpu_model(prev: i32, cur: i32, allowed: &[bool], idle: &[bool]) -> Option<u32> {
    if let Some(c) = pick_any_idle(allowed, idle) {
        return Some(c);
    }
    if may_run_on(prev, allowed) {
        return Some(prev as u32);
    }
    if may_run_on(cur, allowed) {
        return Some(cur as u32);
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * True when one CPU sits on a free core. Needs the CPU
 * plus no sibling with a running task. Singletons with
 * 0xffff read as free, so SMT off is a no-op with no
 * trap. Out of range CPUs fail closed with no
 * placement. Follows the partner table for up to 8
 * steps with no division. Mirrors the BPF walk with
 * the same table and the same bounds.
 */
#[cfg(test)]
pub fn core_free(cpu: i32, partner: &[u16], running: &[bool], nr: usize) -> bool {
    if cpu < 0 {
        return false;
    }
    let c = cpu as usize;
    if c >= nr {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    if running.get(c).copied().unwrap_or(false) {
        return false;
    }
    let Some(&nxt) = partner.get(c) else {
        return true;
    };
    if nxt == crate::flow_group::SIBLING_EMPTY {
        return true;
    }
    if (nxt as usize) >= MAX_CPUS as usize {
        return true;
    }
    if (nxt as usize) >= nr {
        return true;
    }
    if nxt as usize == c {
        return true;
    }
    let mut cur = nxt as usize;
    for _ in 0..8 {
        if cur >= nr {
            return true;
        }
        if (cur as u64) >= MAX_CPUS as u64 {
            return true;
        }
        if running.get(cur).copied().unwrap_or(false) {
            return false;
        }
        let Some(&after) = partner.get(cur) else {
            return true;
        };
        if after == crate::flow_group::SIBLING_EMPTY {
            return true;
        }
        if (after as usize) >= MAX_CPUS as usize {
            return true;
        }
        if (after as usize) >= nr {
            return true;
        }
        let v = after as usize;
        if v == c || v == cur {
            return true;
        }
        cur = v;
        if cur == c {
            return true;
        }
    }
    true
}

/*
 * First free CPU in one group. Tier A model only.
 * Scans in id order with the table when ready, else
 * halves. Needs allowed plus group plus free core by
 * running pid. No scx idle use and no claim, so a miss
 * wastes no idle claim. Returns none when no such CPU
 * lives. Strict iff ready is zero, best effort iff
 * ready is one with live table in placement.
 */
#[cfg(test)]
pub fn pick_free_idle(
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
    partner: &[u16],
    running: &[bool],
) -> Option<u32> {
    for cpu in 0..nr {
        if !may_run_on(cpu as i32, allowed) {
            continue;
        }
        if crate::flow_group::group_live(cpu as u32, nr, table, ready) != group {
            continue;
        }
        if !core_free(cpu as i32, partner, running, nr) {
            continue;
        }
        return Some(cpu as u32);
    }
    None
}

/*
 * First idle CPU in one group. Tier B model only.
 * Scans in id order with the table when ready, else
 * halves. Needs idle plus allowed in the group.
 * Returns none when no such CPU lives. Strict iff
 * ready is zero, best effort iff ready is one with
 * live table in placement.
 */
#[cfg(test)]
pub fn pick_idle_in_group(
    allowed: &[bool],
    idle: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
) -> Option<u32> {
    for cpu in 0..nr {
        if !may_run_on(cpu as i32, allowed) {
            continue;
        }
        if idle.get(cpu).copied().unwrap_or(false) != true {
            continue;
        }
        if crate::flow_group::group_live(cpu as u32, nr, table, ready) != group {
            continue;
        }
        return Some(cpu as u32);
    }
    None
}

/*
 * True when the waker CPU may keep the task. Needs idle
 * with no running task plus allowed plus in group.
 * An idle core cannot stack, so locality is free.
 * Every other case keeps current behavior.
 */
#[cfg(test)]
pub fn waker_first_ok(
    waker: i32,
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
    running: &[bool],
) -> bool {
    if waker < 0 {
        return false;
    }
    if (waker as usize) >= nr {
        return false;
    }
    if (waker as u64) >= MAX_CPUS as u64 {
        return false;
    }
    if !may_run_on(waker, allowed) {
        return false;
    }
    if crate::flow_group::group_live(waker as u32, nr, table, ready) != group {
        return false;
    }
    if running.get(waker as usize).copied().unwrap_or(true) {
        return false;
    }
    true
}

/*
 * Full tiered select model. Mirrors the BPF order of
 * waker CPU first plus free scan plus any idle in the
 * group plus previous plus current plus first in
 * the group plus first. Waker wins when idle with
 * no running task plus allowed plus in group. An
 * idle core cannot stack, so locality is free.
 * Every other case keeps current behavior. Tier A
 * scans for a free core with no claim, so a miss
 * wastes no idle claim. Tier B prefers any idle
 * in the group with claim only there. Placement
 * only with no dispatch use. Singletons treat all
 * running free as free, so Tier A equals Tier B
 * order with no trap. Strict iff ready is zero,
 * best effort iff ready is one with live table
 * in placement.
 */
#[cfg(test)]
pub fn select_cpu_tiered(
    prev: i32,
    cur: i32,
    allowed: &[bool],
    idle: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
    partner: &[u16],
    running: &[bool],
) -> Option<u32> {
    if waker_first_ok(cur, allowed, group, nr, table, ready, running) {
        return Some(cur as u32);
    }
    if let Some(c) = pick_free_idle(allowed, group, nr, table, ready, partner, running) {
        return Some(c);
    }
    if let Some(c) = pick_idle_in_group(allowed, idle, group, nr, table, ready) {
        return Some(c);
    }
    for &cpu in &[prev, cur] {
        if may_run_on(cpu, allowed)
            && crate::flow_group::group_live(cpu as u32, nr, table, ready) == group
            && (cpu as usize) < nr
            && cpu >= 0
        {
            return Some(cpu as u32);
        }
    }
    if let Some(c) = crate::flow_group::first_in_group_live(allowed, group, nr, table, ready) {
        return Some(c);
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * True when an exiting task may run at once on this CPU.
 * Needs an exiting task with this CPU allowed, so short
 * exits skip order wait with no queue stall. Falls back
 * when this CPU is not allowed.
 */
#[cfg(test)]
pub fn exiting_local_ok(exiting: bool, current_allowed: bool) -> bool {
    exiting && current_allowed
}

/*
 * True when an idle kick may run. Needs an idle target
 * with no running task and at most 2 queued, so a
 * missed empty to 1 kick is rescued on the next insert
 * while deep queues stay quiet with no storm. Busy
 * targets stay quiet. A missing state fails closed
 * with no kick.
 */
#[cfg(test)]
pub fn kick_idle_ok(queue_len: u64, running_pid: u32, has_state: bool) -> bool {
    if queue_len > STEAL_MIN_DEPTH {
        return false;
    }
    if !has_state {
        return false;
    }
    running_pid == 0
}

/*
 * True when one idle kick is recent in 50us. Zero last
 * never counts as recent with wrap. Diff wraps, so
 * order holds across the wrap with no extra check.
 */
#[cfg(test)]
pub fn kick_recent(now: u64, last: u64) -> bool {
    if last == 0 {
        return false;
    }
    now.wrapping_sub(last) < KICK_COALESCE_NS
}

/*
 * True when one idle kick coalesces with no kick. Needs
 * q2 plus idle plus recent plus not pinned, so q1 always
 * kicks and deep stays quiet with no count. Pinned never
 * skips. No slide on skip, the caller keeps the old last.
 * Park plus exiting stay out with no kick use.
 */
#[cfg(test)]
pub fn kick_coalesced(
    queue_len: u64,
    running_pid: u32,
    has_state: bool,
    pinned: bool,
    now: u64,
    last: u64,
) -> bool {
    if queue_len != STEAL_MIN_DEPTH {
        return false;
    }
    if running_pid != 0 {
        return false;
    }
    if !has_state {
        return false;
    }
    if pinned {
        return false;
    }
    kick_recent(now, last)
}

/*
 * False for park inserts with no kick. Park holds tasks
 * with no live allowed CPU after fallback, so no single
 * idle target can run them. The next dispatch pass on
 * any thief in the park group collects them when the
 * mask allows. A target scan would need a loop with
 * storm risk, so no kick is sent.
 */
#[cfg(test)]
pub fn park_kick_ok() -> bool {
    false
}

/*
 * Target CPU from the selected CPU. A valid allowed
 * selected CPU wins. Otherwise the first allowed CPU
 * wins. No allowed CPU yields no target for park use.
 * Pinned tasks resolve to the single allowed CPU here.
 */
#[cfg(test)]
pub fn pick_target_cpu(selected: i32, allowed: &[bool]) -> Option<u32> {
    if selected >= 0 {
        if let Some(&ok) = allowed.get(selected as usize) {
            if ok {
                return Some(selected as u32);
            }
        }
    }
    for (i, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(i as u32);
        }
    }
    None
}

/*
 * Target CPU for a task that cannot move. Mirrors
 * the BPF local path with a mask check. An out of
 * range CPU yields no target for park use. A CPU
 * outside the mask yields no target for park use.
 */
#[cfg(test)]
pub fn stay_target(here: i32, nr_cpus: usize, allowed: &[bool]) -> Option<u32> {
    if here < 0 {
        return None;
    }
    if (here as usize) >= nr_cpus {
        return None;
    }
    if !may_run_on(here, allowed) {
        return None;
    }
    Some(here as u32)
}

/*
 * True when a frequency value is known. Zero means
 * unknown, so callers use a plain fallback and never
 * divide by the value. Frequency stays display only
 * and never shapes placement.
 */
#[cfg(test)]
pub fn freq_known(freq_khz: u64) -> bool {
    freq_khz != 0
}

/*
 * Pending task for dispatch models. The mask names
 * allowed CPUs. The live flag marks tasks with a
 * trusted reference. A cleared live flag models a NULL
 * lookup from the pid table. The fail flag models a
 * failed move that must be skipped with progress.
 */
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTask {
    /* Allowed CPUs. Index is the CPU. */
    pub allowed: Vec<bool>,
    /* True when the task is exiting. */
    pub exiting: bool,
    /* False models a NULL pid lookup. */
    pub live: bool,
    /* True models a failed queue move. */
    pub fail: bool,
}

/*
 * True when one peer task may move to the thief.
 * Mirrors the BPF peer drain task check. A live and
 * allowed task with no move failure may move. Exiting
 * tasks may move when allowed, so they run to exit.
 * A dead, foreign, or failed task stays, so the scan
 * moves past it with progress. An empty queue yields
 * false.
 */
#[cfg(test)]
pub fn peer_head_ok(thief: i32, head: Option<&PendingTask>) -> bool {
    if let Some(t) = head {
        t.live && !t.fail && may_run_on(thief, &t.allowed)
    } else {
        false
    }
}

/*
 * Steal up to budget tasks from peers for an idle CPU.
 * Tier 0 model only. The scan visits at most bound
 * peers starting after the cursor with wrap. Only idle
 * callers steal. Each peer needs at least two queued
 * tasks, or one with a rescue when the thief is idle
 * with no moved plus no own left past unmovable park
 * leftovers or when the donor is asleep with no running
 * task, so thin running donors keep the last task while
 * idle thieves plus asleep donors rescue singletons.
 * BPF ships thief idle only by construction due to
 * verifier jump at 1000001 on asleep check, with donor
 * asleep handled by idle kick. Each peer is scanned in
 * order past dead, foreign, and failed heads, so movable
 * work behind a bad head is rescued. The cursor advances
 * by the peers visited. Returns the count moved and the
 * new cursor.
 */
#[cfg(test)]
pub fn steal_model(
    peers: &mut [std::collections::VecDeque<PendingTask>],
    thief: usize,
    cursor: u32,
    budget: u32,
    idle: bool,
    allow_single: bool,
    donor_idle: &[bool],
) -> (u32, u32) {
    if !idle {
        return (0, cursor);
    }
    if peers.len() <= 1 {
        return (0, cursor);
    }
    if budget == 0 {
        return (0, cursor);
    }
    let mut moved = 0;
    let mut cur = cursor;
    let mut visited = 0;
    let bound = scan_bound(peers.len());
    while visited < bound && moved < budget {
        let next = match next_peer(cur, peers.len()) {
            Some(v) => v,
            None => break,
        };
        cur = next;
        visited += 1;
        if next as usize == thief {
            continue;
        }
        if let Some(q) = peers.get_mut(next as usize) {
            let idle_donor = donor_idle.get(next as usize).copied().unwrap_or(false);
            if !donor_ok(q.len() as u64, allow_single, idle_donor) {
                continue;
            }
            let mut pos = None;
            for (idx, task) in q.iter().enumerate() {
                if peer_head_ok(thief as i32, Some(task)) {
                    pos = Some(idx);
                    break;
                }
            }
            if let Some(idx) = pos {
                q.remove(idx);
                moved += 1;
            }
            if moved >= budget {
                break;
            }
        }
    }
    (moved, cur)
}

/*
 * True when a CPU may steal after draining own and
 * park. An idle CPU with no moved work steals past
 * unmovable leftovers, so only unmovable work never
 * blocks a steal. A busy CPU with moved work steals
 * only when both queues are empty.
 */
#[cfg(test)]
pub fn may_steal(own_left: u64, park_left: u64, moved: u32) -> bool {
    if moved == 0 {
        return true;
    }
    own_left == 0 && park_left == 0
}
