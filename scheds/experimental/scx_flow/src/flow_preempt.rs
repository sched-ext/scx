// SPDX-License-Identifier: GPL-2.0
/*
 * Delay, granule, slack, and rate helpers
 *
 * Holds the delay, granule, slack, and rate helpers that mirror the BPF header
 * so behavior stays the same on both sides of the boundary. Units stay in 32us
 * with integer math only and no float use.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/* One delay unit in nanos at 32us. */
#[cfg(test)]
pub const DELAY_UNIT_NS: u64 = 32_000;
/* Max delay in units at 250 near 8ms. */
#[cfg(test)]
pub const DELAY_MAX: u64 = 250;
/* Armed delay in units at 16 near 512us. */
pub const DELAY_ARM: u64 = 16;
/* Stand delay in units at 8 near 256us. */
pub const DELAY_STAND: u64 = 8;
/* Window length in updates at 8. */
#[cfg(test)]
pub const DELAY_WIN_LEN: u64 = 8;
/* Granule floor in nanos at 64us. */
#[cfg(test)]
pub const GRANULE_FLOOR_NS: u64 = 64_000;
/* Deserved slack in nanos at 32us. */
#[cfg(test)]
pub const DESERVED_SLACK_NS: u64 = 32_000;
/* Stand bit in cursor bit10 with peer in 0 to 9. */
pub const CURSOR_STAND_BIT: u32 = 0x0000_0400;
/* Cursor peer mask without stand, top stays masked. */
#[cfg(test)]
pub const CURSOR_MASK: u32 = 0x7fff_fbff;

/*
 * Sample in 32us units from queued count. One queued
 * is 31 units, 512us arms at 16. Cap is 250 at
 * 8ms with integer math only.
 */
#[cfg(test)]
pub fn delay_from_queued(queued: u64) -> u8 {
    if queued >= 8 {
        return 250;
    }
    let v = (queued * 125) / 4;
    if v > 250 { 250 } else { v as u8 }
}

/*
 * Decay one step by 1/8 with integer math only.
 * Holds peaks across windows for hysteresis.
 */
#[cfg(test)]
pub fn delay_decay(old: u8) -> u8 {
    let o = old as u32;
    (o - o / 8) as u8
}

/*
 * True when the delay window is armed at 16. 16 is
 * 512us in 32us units with absolute use. Display
 * only with no gate use, see dots.
 */
pub fn delay_armed(win: u8) -> bool {
    (win as u64) >= DELAY_ARM
}

/*
 * True when delay is armed with hysteresis. Arms
 * at 16, then holds while win stays at or past
 * stand at 8 with the latched flag. Persists
 * across idle with no decay sans traffic. Delay
 * shows stale when idle, see dashboard. Next
 * running decays at 1/8 per window. Display only
 * with no gate use, see dots.
 */
pub fn delay_armed_latched(win: u8, held: bool) -> bool {
    if delay_armed(win) {
        return true;
    }
    if held && (win as u64) >= DELAY_STAND {
        return true;
    }
    false
}

/*
 * True when the stand latch is held in bit10.
 * Bits 0 to 9 hold peer, bit10 holds stand, so
 * rotation masks the flag.
 */
pub fn stand_held(cursor: u32) -> bool {
    (cursor & CURSOR_STAND_BIT) != 0
}

/*
 * Max of two delay samples with cap at 250. Win and cur are dual writer max,
 * count is running only. Lost race drops at most one sample with no count skew,
 * decay intact.
 */
#[cfg(test)]
pub fn delay_max(a: u8, b: u8) -> u8 {
    let m = if a > b { a } else { b };
    if (m as u64) > DELAY_MAX { 250 } else { m }
}

/*
 * Close one window of 8 with decay and max. Decays the old max by 1/8 then
 * keeps the max with the current window max with cap at 250.
 */
#[cfg(test)]
pub fn delay_close(win: u8, cur: u8) -> u8 {
    let o = win as u32;
    let d = o - o / 8;
    let m = if d > cur as u32 { d } else { cur as u32 };
    if m > 250 { 250 } else { m as u8 }
}

/*
 * Push one sample through the window. Tracks the max
 * in the current window, then closes each 8 updates
 * with decay. Fast arm on a high sample, slow fall
 * by 1/8 per window for hysteresis. Integer only.
 * Running owns this path. Enqueue uses stamp only
 * with no count, so 8 means 8 runnings with no
 * double count. Persists across idle with no decay.
 */
#[cfg(test)]
pub fn delay_push(win: u8, cur: u8, cnt: u16, sample: u8) -> (u8, u8, u16) {
    let sample = if (sample as u64) > DELAY_MAX {
        250
    } else {
        sample
    };
    let nwin = delay_max(win, sample);
    let ncur = delay_max(cur, sample);
    let ncnt = cnt.wrapping_add(1);
    if (ncnt as u64) >= DELAY_WIN_LEN {
        let closed = delay_close(nwin, ncur);
        return (closed, 0, 0);
    }
    (nwin, ncur, ncnt)
}

/*
 * Granule in nanos quarter slice with 64us floor. Base is slice times 1024 over
 * weight quartered with floor at 64us, so heavy keeps short and light keeps
 * long with no trap on zero input. Short heavy is stricter, tempering deadline
 * lead. Net easiness is deadline math, not gran. Quarter bounds theft near 25%
 * of a slice. Floor covers IPI and switch cost, no thrash. Uses woken weight
 * only, see deserved.
 */
#[cfg(test)]
pub fn granule_for_weight(weight: u32, slice: u64) -> u64 {
    if weight == 0 {
        let gran = slice / 4;
        if gran < GRANULE_FLOOR_NS {
            return GRANULE_FLOOR_NS;
        }
        return gran;
    }
    if slice == 0 {
        return GRANULE_FLOOR_NS;
    }
    let base = ((slice as u128 * 1024) / weight as u128) as u64;
    let gran = base / 4;
    if gran < GRANULE_FLOOR_NS {
        return GRANULE_FLOOR_NS;
    }
    gran
}

/*
 * Cursor peer without stand, top stays masked.
 */
#[cfg(test)]
pub fn cursor_val(cursor: u32) -> u32 {
    cursor & CURSOR_MASK
}

/*
 * Store peer, keep stand. Masks the peer, so rotation keeps order
 * with no extra state. Dispatch CAS keeps the fresh flag, model
 * is sequential form, timing only.
 */
#[cfg(test)]
pub fn cursor_store(peer: u32, old: u32) -> u32 {
    (peer & CURSOR_MASK) | (old & CURSOR_STAND_BIT)
}

/*
 * Set the stand latch, keep peer.
 */
#[cfg(test)]
pub fn stand_set(cursor: u32) -> u32 {
    cursor | CURSOR_STAND_BIT
}

/*
 * Clear the stand latch, keep peer.
 */
#[cfg(test)]
pub fn stand_clear(cursor: u32) -> u32 {
    cursor & !CURSOR_STAND_BIT
}

/*
 * Stamp one sample with max only and no count. Enqueue stamps, running owns
 * count and close, so 8 means 8 runnings with no double count. Dual max drops
 * at most one sample, no skew, decay intact. See delay_max bound.
 */
#[cfg(test)]
pub fn delay_stamp(win: u8, cur: u8, sample: u8) -> (u8, u8) {
    let sample = if (sample as u64) > DELAY_MAX {
        250
    } else {
        sample
    };
    (delay_max(win, sample), delay_max(cur, sample))
}

/*
 * True when woken deadline beats frontier, gran, and slack. Frontier is the
 * service floor, so beating it by granule proves earliness with no occupant
 * state. Slack is 32us bounded at half the 64us floor, so near misses ease with
 * no storm. Wrap safe via wrapping add and signed compare with no branch.
 * Granule uses woken weight only, occupant weight stays out after the frontier
 * compare fix.
 */
#[cfg(test)]
pub fn deserved(woken_dl: u64, frontier: u64, granule: u64) -> bool {
    (woken_dl.wrapping_sub(
        frontier
            .wrapping_add(granule)
            .wrapping_add(DESERVED_SLACK_NS),
    ) as i64)
        < 0
}

/*
 * Effective same group under S1 perf bypass. Perf forces true with no recount,
 * strict keeps the live check. Mirrors the BPF busy-kick bypass in enqueue
 * where flow_perf_enabled forces same true before the branch checks, so
 * pskip_group stays flat in perf with no new counter. Callers apply this before
 * preempt_ok and skip_reason with no signature change.
 */
#[cfg(test)]
pub fn same_override(same_group: bool, perf: bool) -> bool {
    if perf { true } else { same_group }
}

/*
 * True when the bound preempt gate passes. Pinned
 * false, empty at most one queued, deserved or hog,
 * same group, mask allowed, and rate ok with kick
 * on all pass. Branch order is pinned, empty,
 * deserved or hog, same, mask, and rate, rate last
 * as the window check. Pinned plus deep count total
 * only at 272B with no reason. Armed retired frozen
 * with display only, see delay dots.
 */
#[cfg(test)]
pub fn preempt_ok(
    pinned: bool,
    empty_ok: bool,
    deserved_or_hog: bool,
    same_group: bool,
    mask_ok: bool,
    rate_ok: bool,
) -> bool {
    if pinned {
        return false;
    }
    if !empty_ok {
        return false;
    }
    if !deserved_or_hog {
        return false;
    }
    if !same_group {
        return false;
    }
    if !mask_ok {
        return false;
    }
    rate_ok
}

/*
 * Skip reason in bound order pinned, empty,
 * deserved or hog, same, mask, and rate. Returns
 * none on kick, else the first failing gate. Pinned
 * plus empty map to total only with no reason write
 * at 272B, deserved maps to 2, group to 3, mask to
 * 4, rate to 5 with armed 1 retired frozen. Mirrors
 * the BPF sequential checks in enqueue with rate
 * last as the window check.
 */
#[cfg(test)]
pub fn skip_reason(
    pinned: bool,
    empty_ok: bool,
    deserved_or_hog: bool,
    same_group: bool,
    mask_ok: bool,
    rate_ok: bool,
) -> Option<u8> {
    if pinned {
        return Some(6);
    }
    if !empty_ok {
        return Some(6);
    }
    if !deserved_or_hog {
        return Some(2);
    }
    if !same_group {
        return Some(3);
    }
    if !mask_ok {
        return Some(4);
    }
    if !rate_ok {
        return Some(5);
    }
    None
}

/*
 * Name of one skip reason for logs. Zero is kick
 * with no skip, one is armed retired frozen, two to
 * five follow bound order deserved, group, mask, and
 * rate, six is total only for pinned plus deep with
 * no reason write.
 */
#[cfg(test)]
pub fn skip_reason_name(reason: u8) -> &'static str {
    match reason {
        0 => "kick",
        1 => "armed",
        2 => "deserved",
        3 => "group",
        4 => "mask",
        5 => "rate",
        6 => "total-only",
        _ => "unknown",
    }
}

/*
 * True when one queue holds at most one task for empty
 * first. Holds when queued is zero or one, else false,
 * so deep queues stay quiet with no storm and no time
 * use. Minimal compare with no wrap. Mirrors the BPF
 * empty check for the bound gate.
 */
#[cfg(test)]
pub fn empty_ok(q: u64) -> bool {
    q <= 1
}

/*
 * True when one wake earns the CPU by earliness or hog.
 * Holds when deserved holds or occupant holds hog
 * regardless of waker class, so hog occupants preempt
 * with no time cap past empty first, still bounded by
 * empty plus same plus mask plus rate. Minimal OR
 * with no wrap. Mirrors the BPF hog OR for the bound
 * gate.
 */
#[cfg(test)]
pub fn deserved_or_hog(deserved: bool, occupant_hog: bool) -> bool {
    deserved || occupant_hog
}
