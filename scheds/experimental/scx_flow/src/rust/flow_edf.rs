// SPDX-License-Identifier: GPL-2.0
//! Deadline plus admission helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the release plus period plus deadline plus admission plus miss
//! models shared by BPF and userspace tests. The BPF deadline lives in
//! intf.h with the admission rows in main/deadline.bpf.c, and this file
//! mirrors the math with no map use.

/// Default period in nanos at 16ms. Holds eight slices.
pub const PERIOD_NS: u64 = 16_000_000;
/// Admission bound in per mille at 950. Holds use under ninety five percent.
pub const ADMIT_PERMILLE: u64 = 950;
/// Base capacity in units at 1024. Every symmetric CPU offers the same units.
pub const CAP_BASE: u32 = 1024;

/// Period for one task from hint micros else default.
/// A zero hint means no hint, so the default period applies. The hint
/// converts from micros to nanos with saturation, so a huge hint
/// clamps instead of wrapping to a short period.
#[cfg(test)]
pub fn task_period(hint_us: u32) -> u64 {
    if hint_us == 0 {
        return PERIOD_NS;
    }
    (hint_us as u64).saturating_mul(1000)
}

/// Absolute deadline from release plus relative period.
/// The add saturates, so a huge release clamps instead of wrapping
/// to the front.
#[cfg(test)]
pub fn deadline_at(release: u64, period: u64) -> u64 {
    release.saturating_add(period)
}

/// Per mille share of one slice in one period with saturation.
/// A zero period means no bound, so the share stays zero. A 2ms slice
/// in a 16ms period takes 125 per mille.
#[cfg(test)]
pub fn slice_permillle(period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    crate::flow_slice::QUANTUM_NS * 1000 / period
}

/// True when one CPU can admit one more per mille share.
/// The admitted sum plus the new share must stay under the bound, so
/// admitted work keeps idle time for late wakeups. Saturated sums
/// fail closed, so a wrapped sum never admits.
#[cfg(test)]
pub fn admit_ok(admitted: u64, share: u64) -> bool {
    let sum = admitted.saturating_add(share);
    if sum < admitted {
        return false;
    }
    sum <= ADMIT_PERMILLE
}

/// True when one task missed its deadline at the given time.
/// A zero deadline means no order yet, so the check skips. A zero
/// release means no release yet, so the check skips too.
#[cfg(test)]
pub fn missed(release: u64, deadline: u64, now: u64) -> bool {
    if release == 0 {
        return false;
    }
    if deadline == 0 {
        return false;
    }
    if now <= deadline {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_defaults_and_hints() {
        assert_eq!(task_period(0), 16_000_000);
        assert_eq!(task_period(8000), 8_000_000);
        assert_eq!(deadline_at(1_000, 16_000_000), 16_001_000);
        assert_eq!(deadline_at(u64::MAX, 16_000_000), u64::MAX);
    }

    #[test]
    fn admission_holds_bound() {
        assert_eq!(slice_permillle(16_000_000), 125);
        assert_eq!(slice_permillle(0), 0);
        assert!(admit_ok(825, 125));
        assert!(!admit_ok(826, 125));
        assert!(!admit_ok(u64::MAX, 125));
    }

    #[test]
    fn miss_checks() {
        assert!(!missed(0, 100, 200));
        assert!(!missed(10, 0, 200));
        assert!(!missed(10, 100, 100));
        assert!(missed(10, 100, 101));
    }
}
