// SPDX-License-Identifier: GPL-2.0
/*
 * Placement and steal helpers
 *
 * Holds the placement and steal helpers that mirror the BPF side so behavior
 * stays the same on both sides of the boundary. Frequency, LLC, and CPU cards
 * stay display only and never shape placement.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/* Compile time CPU bound. Mirrors the BPF header. */
#[cfg(test)]
pub const MAX_CPUS: u32 = 1024;
/* Bound of peers visited by one steal scan. */
#[cfg(test)]
pub const STEAL_BOUND: usize = 8;
/* Least donor depth that always allows a steal, depth 1 needs idle empty. */
#[cfg(test)]
pub const STEAL_MIN_DEPTH: u64 = 2;
/* Coalesce window in nanos at 50us. */
#[cfg(test)]
pub const KICK_COALESCE_NS: u64 = 50_000;

/*
 * Start peer for one dispatch from the cursor.
 * Masks rate plus stand then steps one with wrap,
 * so repeated passes spread across peers with no
 * hot spot. Mirrors the BPF start read once per
 * dispatch with mask. See src/bpf/dispatch.bpf.c
 * for the scan use.
 */
#[cfg(test)]
pub fn steal_start(cursor: u32, nr_cpus: usize) -> u32 {
    use crate::flow_preempt::CURSOR_MASK;
    if nr_cpus == 0 {
        return 0;
    }
    if nr_cpus == 1 {
        return 0;
    }
    ((cursor & CURSOR_MASK) + 1) % nr_cpus as u32
}

/*
 * Peers visited by two rotation windows from a start.
 * Steps 16 from start with wrap, so high CPUs
 * reach low peers with no dead read. First 8
 * feed one same group scan, next 8 preview the
 * next scan after the stride 8 step with 4 compare
 * and swap tries. BPF uses modulo with the same
 * order for the verifier. Returns 16 entries in
 * order. See src/bpf/dispatch.bpf.c for the scan use.
 */
#[cfg(test)]
pub fn steal_peers_from(start: u32, nr_cpus: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(16);
    if nr_cpus == 0 {
        return out;
    }
    for off in 0..16 {
        out.push((start.wrapping_add(off)) % nr_cpus as u32);
    }
    out
}

/*
 * Start step for one steal scan from a cursor.
 * Masks rate plus stand then steps one with wrap,
 * so this models the per dispatch start read with
 * no queue use. The cursor advance is separate at
 * stride 8 with 4 compare and swap tries that keep
 * rate plus stand, see cursor_store in flow_preempt
 * plus src/bpf/dispatch.bpf.c for the advance use.
 */
#[cfg(test)]
pub fn steal_next(cursor: u32, nr_cpus: usize) -> u32 {
    steal_start(cursor, nr_cpus)
}

/*
 * Peers visited by one steal scan from one CPU.
 * Takes bound peers from the start helper, so high
 * CPUs wrap to low peers with no dead read. BPF uses
 * modulo with the same order for the verifier.
 * Returns the visit order with bound entries.
 */
#[cfg(test)]
pub fn steal_peers(cpu: u32, nr_cpus: usize) -> Vec<u32> {
    let start = steal_start(cpu, nr_cpus);
    let full = steal_peers_from(start, nr_cpus);
    full.into_iter().take(STEAL_BOUND).collect()
}

/*
 * Peers visited by the perf only cross scan from a start.
 * Steps bound peers from start plus 8 with wrap, so high
 * CPUs reach low peers with no dead read. Feeds the other
 * group scan on same group miss with same need and keep
 * first. Mirrors the BPF second loop with modulo and the
 * same order for the verifier. Returns the visit order
 * with bound entries. See src/bpf/dispatch.bpf.c for the
 * scan use.
 */
#[cfg(test)]
pub fn steal_cross_peers(start: u32, nr_cpus: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(STEAL_BOUND);
    if nr_cpus == 0 {
        return out;
    }
    for off in 0..STEAL_BOUND as u32 {
        out.push(start.wrapping_add(8).wrapping_add(off) % nr_cpus as u32);
    }
    out
}

/*
 * Cross mark from one retained DSQ id and one owner group.
 * Compares the DSQ low bit against the owner group low bit
 * with xor, so same group maps to zero and cross maps to
 * one with no branch. Holds pure after the shared drain
 * with scalar-only live across the inline drain, no
 * map-pointer live, so the verifier keeps one state.
 * Mirrors the BPF post hoc xor with mask. Returns 0
 * for same and 1 for cross. See src/bpf/dispatch.bpf.c for
 * the fold use.
 */
#[cfg(test)]
pub fn steal_cross_x(steal_dsq: u64, sgroup: u8) -> u64 {
    ((steal_dsq & 1) ^ ((sgroup as u64) & 1)) & 1
}

/*
 * Check that a CPU may run a task with the given mask. Mirrors the BPF live,
 * range, and mask check. A negative CPU fails closed. A CPU at or past 1024
 * fails closed as test only bound. Live CPUs are modelled by the mask length in
 * tests, so callers keep the mask sized to live CPUs. A missing entry fails
 * closed.
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
 * First idle CPU in the mask. Models the any idle step. Returns none when no
 * allowed CPU is idle. Frequency, LLC, and CPU cards stay display only and
 * never feed this choice.
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
 * Full select model. Mirrors the BPF order of any idle, previous, current, and
 * first. Returns none for overflow use when no CPU allows. Frequency, LLC, and CPU
 * cards stay display only and never feed this choice.
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
 * True when one CPU sits on a free core. Needs the CPU and no sibling with a
 * running task. Singletons with 0xffff read as free, so SMT off is a no-op with
 * no trap. Out of range CPUs fail closed with no placement. Follows the partner
 * table for up to 8 steps with no division. Mirrors the BPF walk with the same
 * table and the same bounds.
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
 * First free CPU in one group. Tier A model only. Scans in id order with the
 * table when ready, else halves. Needs allowed, group, and free core by running
 * pid. No scx idle use and no claim, so a miss wastes no idle claim. Returns
 * none when no such CPU lives. Strict iff ready is zero, best effort iff ready
 * is one with live table in placement.
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
 * First idle CPU in one group. Tier B model only. Scans in id order with the
 * table when ready, else halves. Needs idle and allowed in the group. Returns
 * none when no such CPU lives. Strict iff ready is zero, best effort iff ready
 * is one with live table in placement.
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
 * True when the waker CPU may keep the task. Needs idle with no running task,
 * allowed, and in group. An idle core cannot stack, so locality is free. Every
 * other case keeps current behavior.
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
 * Full tiered select model with first fallback. Mirrors the BPF order of waker
 * CPU first, free scan, and any idle in the group. It then checks previous,
 * current, first in the group, and first. Waker wins when idle with no
 * running task, allowed, and in group. An idle core cannot stack, so locality
 * is free. Every other case keeps current behavior. Tier A scans for a free
 * core with no claim, so a miss wastes no idle claim. Tier B prefers any idle
 * in the group with claim only there. Placement only with no dispatch use.
 * Singletons treat all running free as free, so Tier A equals Tier B order with
 * no trap. Strict iff ready is zero, best effort iff ready is one with live
 * table in placement. First model only, see tiered least for the live least
 * used by select and enqueue.
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
 * Full tiered select model with least queued fallback. Mirrors the BPF order
 * of waker, free, and any idle. It then checks previous, current, least in
 * the group, and first. The least step scans 0 to nr in id order with live,
 * per CPU plus group overflow depth and picks the smallest depth with
 * lowest id on ties by strict less only, so equal depths keep the first
 * id. Missing entries read as zero with no trap. Placement keeps live,
 * dispatch keeps halves, constants frozen. Strict iff ready is zero, best
 * effort iff ready is one with live table use.
 */
#[cfg(test)]
pub fn select_cpu_tiered_least(
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
    overflow: &[u64],
    per_cpu: &[u64],
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
    if let Some(c) =
        crate::flow_group::least_in_group_live(allowed, group, nr, table, ready, overflow, per_cpu)
    {
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
 * Target CPU in one group from selected and least. Mirrors the BPF pick in
 * group used by enqueue. A valid allowed selected CPU in the group wins.
 * Otherwise the least queued allowed CPU in the group wins with lowest id on
 * ties. No allowed CPU in the group yields none for overflow use. Placement
 * keeps live, dispatch keeps halves, constants frozen.
 */
#[cfg(test)]
pub fn pick_in_group_least(
    selected: i32,
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
    overflow: &[u64],
    per_cpu: &[u64],
) -> Option<u32> {
    if selected >= 0
        && may_run_on(selected, allowed)
        && (selected as usize) < nr
        && crate::flow_group::group_live(selected as u32, nr, table, ready) == group
    {
        return Some(selected as u32);
    }
    crate::flow_group::least_in_group_live(allowed, group, nr, table, ready, overflow, per_cpu)
}

/*
 * Least queued allowed CPU in any group for S0 perf.
 * The per CPU FIFO store keeps backlog per CPU, so depth
 * reads each candidate per CPU queue plus its group
 * overflow tail. Picks the smallest depth with lowest
 * id on ties by strict less only, so equal depths keep
 * the first id. Missing entries read as zero with no
 * trap. Returns none when no allowed CPU lives. Mirrors
 * the BPF widened least over any allowed.
 */
#[cfg(test)]
pub fn least_any(
    allowed: &[bool],
    nr: usize,
    table: &[u8],
    ready: u8,
    overflow: &[u64],
    per_cpu: &[u64],
) -> Option<u32> {
    let mut best: Option<u32> = None;
    let mut best_q: u64 = 0;
    for cpu in 0..nr {
        if allowed.get(cpu).copied().unwrap_or(false) != true {
            continue;
        }
        if (cpu as u64) >= MAX_CPUS as u64 {
            continue;
        }
        let g = crate::flow_group::group_live(cpu as u32, nr, table, ready);
        let q = per_cpu
            .get(cpu)
            .copied()
            .unwrap_or(0)
            .wrapping_add(overflow.get(g as usize).copied().unwrap_or(0));
        match best {
            None => {
                best = Some(cpu as u32);
                best_q = q;
            }
            Some(_) if q < best_q => {
                best = Some(cpu as u32);
                best_q = q;
            }
            _ => {}
        }
    }
    best
}

/*
 * First free CPU in any group for S0 perf. Scans in id order with mask and free
 * core by running pid. No group check, so cross group idle cores win on in
 * group miss. Returns none when no such CPU lives. Mirrors the BPF widened free
 * scan with mask win.
 */
#[cfg(test)]
pub fn pick_free_any(
    allowed: &[bool],
    nr: usize,
    partner: &[u16],
    running: &[bool],
) -> Option<u32> {
    for cpu in 0..nr {
        if !may_run_on(cpu as i32, allowed) {
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
 * True when the waker CPU may keep the task in S0 perf. Needs idle with no
 * running task and allowed. Perf skips the group check, so any allowed idle
 * waker wins. Strict callers use waker_first_ok with group, see tiered perf
 * below. Mask always wins.
 */
#[cfg(test)]
pub fn waker_first_ok_perf(waker: i32, allowed: &[bool], nr: usize, running: &[bool]) -> bool {
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
    if running.get(waker as usize).copied().unwrap_or(true) {
        return false;
    }
    true
}

/*
 * Target CPU in one group with S0 perf widening. Mirrors the BPF pick in group
 * with the flag. A valid allowed selected CPU in the group wins. Perf takes any
 * allowed selected CPU on group miss. Then the least in group wins, then perf
 * takes the least any on miss with lowest depth and lowest id. No allowed CPU
 * yields none for overflow use. Mask wins.
 */
#[cfg(test)]
pub fn pick_in_group_widened(
    selected: i32,
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
    overflow: &[u64],
    per_cpu: &[u64],
    perf: bool,
) -> Option<u32> {
    if selected >= 0 && may_run_on(selected, allowed) && (selected as usize) < nr {
        if crate::flow_group::group_live(selected as u32, nr, table, ready) == group {
            return Some(selected as u32);
        }
        if perf {
            return Some(selected as u32);
        }
    }
    if let Some(c) =
        crate::flow_group::least_in_group_live(allowed, group, nr, table, ready, overflow, per_cpu)
    {
        return Some(c);
    }
    if perf {
        if let Some(c) = least_any(allowed, nr, table, ready, overflow, per_cpu) {
            return Some(c);
        }
    }
    None
}

/*
 * Full tiered select with S0 perf widening. Mirrors the BPF order of waker,
 * free, and any idle. It then checks previous, current, least, and first.
 * Strict keeps group checks, perf widens each miss to any allowed with same
 * Waker perf skips group. Free perf scans any free core on miss. Idle perf
 * takes any idle on miss. Previous and current perf take any allowed on group
 * miss. Least perf takes least any on miss with lowest depth and lowest id.
 * First stays any allowed. Mask always wins.
 */
#[cfg(test)]
pub fn select_cpu_tiered_perf(
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
    overflow: &[u64],
    per_cpu: &[u64],
    perf: bool,
) -> Option<u32> {
    if perf {
        if waker_first_ok_perf(cur, allowed, nr, running) {
            return Some(cur as u32);
        }
    } else if waker_first_ok(cur, allowed, group, nr, table, ready, running) {
        return Some(cur as u32);
    }
    if let Some(c) = pick_free_idle(allowed, group, nr, table, ready, partner, running) {
        return Some(c);
    }
    if perf {
        if let Some(c) = pick_free_any(allowed, nr, partner, running) {
            return Some(c);
        }
    }
    if let Some(c) = pick_idle_in_group(allowed, idle, group, nr, table, ready) {
        return Some(c);
    }
    if perf {
        if let Some(c) = pick_any_idle(allowed, idle) {
            return Some(c);
        }
    }
    for &cpu in &[prev, cur] {
        if may_run_on(cpu, allowed) && (cpu as usize) < nr && cpu >= 0 {
            if crate::flow_group::group_live(cpu as u32, nr, table, ready) == group {
                return Some(cpu as u32);
            }
            if perf {
                return Some(cpu as u32);
            }
        }
    }
    if let Some(c) =
        crate::flow_group::least_in_group_live(allowed, group, nr, table, ready, overflow, per_cpu)
    {
        return Some(c);
    }
    if perf {
        if let Some(c) = least_any(allowed, nr, table, ready, overflow, per_cpu) {
            return Some(c);
        }
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * True when an exiting task may run at once on the task CPU.
 * Needs an exiting task with the task CPU allowed, so short
 * exits skip order wait via LOCAL_ON with no queue stall.
 * The task CPU wins over the enqueuer, so an exit enqueued
 * elsewhere still runs where the task lives. Falls back
 * to the normal path exactly once when the task CPU is
 * not allowed with no double enqueue. Non-exiting tasks
 * never take this path.
 */
#[cfg(test)]
pub fn exiting_local_ok(exiting: bool, tgt_allowed: bool) -> bool {
    exiting && tgt_allowed
}

/*
 * True when an exiting fast path may kick the task CPU. Needs the target state
 * with no running task, so an idle task CPU wakes at once for the exit. No
 * queued depth, no coalesce, and no rate check, so q0, q1, and q2 all kick when
 * idle with no slide. Busy targets stay quiet. A missing state fails closed
 * with no kick. Callers gate on exiting_local_ok first, so non-exiting and
 * fallback paths never kick here.
 */
#[cfg(test)]
pub fn exiting_kick_ok(running_pid: u32, has_state: bool) -> bool {
    if !has_state {
        return false;
    }
    running_pid == 0
}

/*
 * True when an idle kick may run. Needs an idle target
 * with no running task. Always kicks the idle target
 * regardless of the shared queue depth, so no idle CPU
 * with queued work sleeps unkicked. Q2 still coalesces
 * in 50us, see below. Busy targets stay quiet. A
 * missing state fails closed with no kick. The queue
 * length stays for call compat and is ignored.
 */
#[cfg(test)]
pub fn kick_idle_ok(_queue_len: u64, running_pid: u32, has_state: bool) -> bool {
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
 * True when one idle kick coalesces with no kick. Needs q2, idle, recent, and
 * not pinned, so q1 always kicks and deep always kicks with no coalesce.
 * Pinned never skips. No slide on skip, the caller keeps the old last.
 * Overflow sends no kick on its own. Exiting uses its own idle kick with
 * no coalesce, see exiting_kick_ok.
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
 * False for overflow inserts with no kick. Overflow holds tasks with no live
 * allowed CPU after fallback, so no single idle target can run them. The next
 * rotation or rescue pass collects them when the mask allows. A target scan
 * would need a loop with storm risk, so no kick is sent.
 */
#[cfg(test)]
pub fn overflow_kick_ok() -> bool {
    false
}

/*
 * Target CPU from the selected CPU. A valid allowed
 * selected CPU wins. Otherwise the first allowed CPU
 * wins. No allowed CPU yields no target for overflow
 * use. Pinned tasks resolve to the single allowed CPU
 * here.
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
 * range CPU yields no target for overflow use. A CPU
 * outside the mask yields no target for overflow use.
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
