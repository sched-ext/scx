// SPDX-License-Identifier: GPL-2.0
//! Served runtime helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the virtual runtime advance shared by tests. The BPF runtime
//! lives in intf.h, and this file mirrors the math with no map use.

/// Clamp one share into 1 to 16384.
/// Zero or oversize shares fail closed to the nearer bound.
#[cfg(test)]
pub fn clamp_share(w: u32) -> u32 {
    w.clamp(crate::flow_slice::WEIGHT_MIN, crate::flow_slice::WEIGHT_MAX)
}

/// Advanced runtime after one execution segment.
/// Scales raw time by base over weight with a split divide, so heavy
/// weights advance slowly and light weights advance fast. The split
/// keeps every intermediate small for real segments, a segment past
/// the scale bound saturates at once, and both adds saturate too, so
/// huge inputs clamp instead of wrapping.
#[cfg(test)]
pub fn runtime_advance(vruntime: u64, delta: u64, weight: u32) -> u64 {
    let w = clamp_share(weight) as u64;
    let base = crate::flow_slice::WEIGHT_BASE as u64;
    let q = delta / w;
    if q > u64::MAX / base {
        return u64::MAX;
    }
    let adv = (q * base).saturating_add(delta % w * base / w);
    vruntime.saturating_add(adv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_weight_advances_raw() {
        assert_eq!(runtime_advance(0, 2_000_000, 128), 2_000_000);
    }

    #[test]
    fn heavy_advances_slow_light_fast() {
        let heavy = runtime_advance(0, 2_000_000, 16_384);
        let light = runtime_advance(0, 2_000_000, 1);
        assert!(heavy < 2_000_000);
        assert!(light > 2_000_000);
    }

    #[test]
    fn huge_inputs_saturate() {
        assert_eq!(runtime_advance(u64::MAX, u64::MAX, 128), u64::MAX);
        assert_eq!(runtime_advance(0, u64::MAX, 1), u64::MAX);
    }
}
