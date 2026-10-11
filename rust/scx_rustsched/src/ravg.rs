// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Running averages, a port of scx's lib/ravg.
//!
//! A running average accumulates values between 0 and 2^44 over arbitrary
//! intervals and halves the accumulated value every half-life, each period
//! starting where the time modulo the half-life is 0. A zeroed average is
//! initialized. Averages read with [`read`] are fixed point, with
//! [`FRAC_BITS`] fractional bits.
//!
//! The operations take a plain [`Ravg`], which the BPF side loads from the
//! arena word by word and stores back the same way, so the host tests run the
//! very same arithmetic.

/// Bits of an input value.
pub const VAL_BITS: u32 = 44;
/// Fractional bits of an average: 1 << 20 is 1.0.
pub const FRAC_BITS: u32 = 20;

/// Decayed sums of full periods, so that folding several needs no loop:
/// `[0]` is `decay(1 << FRAC_BITS, 1)` and each next one adds the next
/// halving, constant from the last on.
const FULL_SUM: [u64; 20] = [
    524288, 786432, 917504, 983040, 1015808, 1032192, 1040384, 1044480, 1046528, 1047552, 1048064,
    1048320, 1048448, 1048512, 1048544, 1048560, 1048568, 1048572, 1048574, 1048575,
];

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Ravg {
    /// The current value.
    pub val: u64,
    /// When `val` was set; the latest completed period is `val_at / half_life - 1`.
    pub val_at: u64,
    /// The average as of the latest completed period.
    pub old: u64,
    /// What the current period has accumulated.
    pub cur: u64,
}

#[inline(always)]
fn sat_add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

#[inline(always)]
fn decay(value: u64, shift: u32) -> u64 {
    if shift >= 64 { 0 } else { value >> shift }
}

/// `duration` as a fraction of `half_life`, rounded up, at most 1.0.
#[inline(always)]
pub fn normalize_dur(duration: u32, half_life: u32) -> u32 {
    if duration < half_life && half_life != 0 {
        (u64::from(duration) << FRAC_BITS).div_ceil(u64::from(half_life)) as u32
    } else {
        1 << FRAC_BITS
    }
}

/// `(a * b) >> rshift` without overflowing the intermediate, for results
/// that fit in 64 bits.
#[inline(always)]
pub fn u64_x_u32_rshift(a: u64, b: u32, rshift: u32) -> u64 {
    let low = (a & 0xffff_ffff) * u64::from(b);
    let high = (a >> 32) * u64::from(b);
    let low = low >> rshift;
    let high = if rshift <= 32 {
        high << (32 - rshift)
    } else {
        high >> (rshift - 32)
    };
    low + high
}

/// The value changes to `new_val` at `now`: fold in what the old one
/// accumulated since it was set.
#[inline(always)]
pub fn accumulate(rd: &mut Ravg, new_val: u64, now: u64, half_life: u32) {
    if half_life == 0 {
        return;
    }
    let half = u64::from(half_life);
    // Several CPUs may accumulate into one average without guaranteeing
    // monotonic time; a stamp in the past counts as now.
    let now = now.max(rd.val_at);
    if now != rd.val_at {
        let cur_seq = now / half;
        let val_seq = rd.val_at / half;
        let seq_delta = (cur_seq - val_seq) as u32;
        if seq_delta > 0 {
            // Decay the old average up to the period before now, and fold
            // in the current period, which must be val_seq's.
            rd.old = decay(rd.old, seq_delta);
            rd.old = sat_add(rd.old, decay(rd.cur, seq_delta));
            rd.cur = 0;
        }
        if rd.val != 0 {
            if seq_delta > 0 {
                // The oldest period, which may be partial.
                let duration = normalize_dur(half_life - (rd.val_at % half) as u32, half_life);
                rd.old = sat_add(rd.old, rd.val * decay(u64::from(duration), seq_delta));
                // The full periods in the middle.
                if seq_delta > 1 {
                    let index = ((seq_delta - 2) as usize).min(FULL_SUM.len() - 1);
                    rd.old = sat_add(rd.old, rd.val * FULL_SUM[index]);
                }
                // The current period so far.
                rd.cur += rd.val * u64::from(normalize_dur((now % half) as u32, half_life));
            } else {
                rd.cur += rd.val * u64::from(normalize_dur((now - rd.val_at) as u32, half_life));
            }
        }
    }
    rd.val = new_val.min((1 << VAL_BITS) - 1);
    rd.val_at = now;
}

/// The average as of `now`, fixed point.
///
/// At the start of a period the average is `old`; at the start of the next
/// it would be `old / 2 + current / 2`. In between the two blend linearly.
#[inline(always)]
pub fn read(rd: &Ravg, now: u64, half_life: u32) -> u64 {
    if half_life == 0 {
        return 0;
    }
    let now = now.max(rd.val_at);
    let elapsed = (now % u64::from(half_life)) as u32;
    let mut copy = *rd;
    accumulate(&mut copy, 0, now, half_life);
    if elapsed == 0 {
        return copy.old;
    }
    let progress = normalize_dur(elapsed, half_life);
    let old = u64_x_u32_rshift(copy.old, (1 << FRAC_BITS) - progress / 2, FRAC_BITS);
    old + copy.cur / 2
}

/// [`read`] when the last update and `now` are in the same period, which is
/// the common case: no period to fold, no copy to run through
/// [`accumulate`]. Falls back to [`read`] across a period boundary.
#[inline(always)]
pub fn read_fast(rd: &Ravg, now: u64, half_life: u32) -> u64 {
    if half_life == 0 {
        return 0;
    }
    let half = u64::from(half_life);
    if now < rd.val_at || now / half != rd.val_at / half {
        return read(rd, now, half_life);
    }
    let elapsed = (now % half) as u32;
    if elapsed == 0 {
        return rd.old;
    }
    let progress = normalize_dur(elapsed, half_life);
    let old = u64_x_u32_rshift(rd.old, (1 << FRAC_BITS) - progress / 2, FRAC_BITS);
    let mut cur = rd.cur;
    if rd.val != 0 && now > rd.val_at {
        let add = rd.val * u64::from(normalize_dur((now - rd.val_at) as u32, half_life));
        cur = sat_add(cur, add);
    }
    old + cur / 2
}
