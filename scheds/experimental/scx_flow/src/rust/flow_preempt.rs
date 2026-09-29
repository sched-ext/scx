// SPDX-License-Identifier: GPL-2.0
//! Preempt plus kick helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the kick rule shared by BPF and userspace tests. Idle targets
//! kick at once with no rate window, and busy targets kick only for a
//! strictly earlier deadline.

/// True when one arrival kicks the occupant of a busy CPU.
/// A strictly earlier deadline kicks at once, and equal or later
/// deadlines pace at slice expiry with no kick.
#[cfg(test)]
pub fn arrival_kicks(arrival: u64, occupant: u64) -> bool {
    if occupant == 0 {
        return false;
    }
    if arrival == 0 {
        return false;
    }
    arrival < occupant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earlier_kicks_later_paces() {
        assert!(arrival_kicks(10, 20));
        assert!(!arrival_kicks(20, 20));
        assert!(!arrival_kicks(30, 20));
    }

    #[test]
    fn zero_deadline_never_kicks() {
        assert!(!arrival_kicks(0, 20));
        assert!(!arrival_kicks(10, 0));
    }
}
