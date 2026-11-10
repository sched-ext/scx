// SPDX-License-Identifier: GPL-2.0
//! Per LLC metric collection for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Sums counters in struct order with wrapping add.

use log::warn;

use crate::BpfSkel;
use crate::stats::Metrics;

/// Fold one LLC value into the aggregate.
/// Counters use wrapping add. Short reads keep prior state.
/// Thirteen counters cover queueing plus kicks plus forward.
pub fn fold_llc_val(out: &mut Metrics, val: &[u8]) {
    if val.len() < 32 {
        return;
    }
    let q = u64::from_ne_bytes(val[0..8].try_into().unwrap_or([0u8; 8]));
    let d = u64::from_ne_bytes(val[8..16].try_into().unwrap_or([0u8; 8]));
    let f = u64::from_ne_bytes(val[16..24].try_into().unwrap_or([0u8; 8]));
    let s = u64::from_ne_bytes(val[24..32].try_into().unwrap_or([0u8; 8]));
    out.queued = out.queued.wrapping_add(q);
    out.dispatched = out.dispatched.wrapping_add(d);
    out.fallback = out.fallback.wrapping_add(f);
    out.steal = out.steal.wrapping_add(s);
    if val.len() >= 40 {
        let v = u64::from_ne_bytes(val[32..40].try_into().unwrap_or([0u8; 8]));
        out.fb_duplicate = out.fb_duplicate.wrapping_add(v);
    }
    if val.len() >= 48 {
        let v = u64::from_ne_bytes(val[40..48].try_into().unwrap_or([0u8; 8]));
        out.steal_llc = out.steal_llc.wrapping_add(v);
    }
    if val.len() >= 56 {
        let v = u64::from_ne_bytes(val[48..56].try_into().unwrap_or([0u8; 8]));
        out.kick_preempt = out.kick_preempt.wrapping_add(v);
    }
    if val.len() >= 64 {
        let v = u64::from_ne_bytes(val[56..64].try_into().unwrap_or([0u8; 8]));
        out.kick_idle = out.kick_idle.wrapping_add(v);
    }
    if val.len() >= 72 {
        let v = u64::from_ne_bytes(val[64..72].try_into().unwrap_or([0u8; 8]));
        out.kick_skip = out.kick_skip.wrapping_add(v);
    }
    if val.len() >= 80 {
        let v = u64::from_ne_bytes(val[72..80].try_into().unwrap_or([0u8; 8]));
        out.overrun = out.overrun.wrapping_add(v);
    }
    if val.len() >= 88 {
        let v = u64::from_ne_bytes(val[80..88].try_into().unwrap_or([0u8; 8]));
        out.blocked = out.blocked.wrapping_add(v);
    }
    if val.len() >= 96 {
        let v = u64::from_ne_bytes(val[88..96].try_into().unwrap_or([0u8; 8]));
        out.orphan_kick = out.orphan_kick.wrapping_add(v);
    }
    if val.len() >= 104 {
        let v = u64::from_ne_bytes(val[96..104].try_into().unwrap_or([0u8; 8]));
        out.hol_forward = out.hol_forward.wrapping_add(v);
    }
}

/// Sum per LLC counters into one view.
/// A failed map read warns and keeps zeros for that LLC.
pub fn collect(skel: &BpfSkel<'_>) -> Metrics {
    use libbpf_rs::MapCore;
    let mut out = Metrics::default();
    for llc in 0..crate::bpf_intf::flow_consts_FLOW_MAX_LLCS {
        let key = llc.to_ne_bytes();
        let val = match skel
            .maps
            .llc_stats_stor
            .lookup(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => {
                warn!("stats read failed for llc {llc}: {e:#}");
                continue;
            }
        };
        fold_llc_val(&mut out, &val);
        if llc + 1 >= 64 {
            break;
        }
    }
    out
}

/// Collect each LLC row on its own.
/// Short reads keep zeros for that LLC through the same fold guards.
/// Order follows the LLC index.
pub fn collect_per_llc(skel: &BpfSkel<'_>) -> Vec<(u32, Metrics)> {
    use libbpf_rs::MapCore;
    let mut out: Vec<(u32, Metrics)> = Vec::new();
    for llc in 0..crate::bpf_intf::flow_consts_FLOW_MAX_LLCS {
        let key = llc.to_ne_bytes();
        let val = match skel
            .maps
            .llc_stats_stor
            .lookup(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => {
                warn!("stats read failed for llc {llc}: {e:#}");
                continue;
            }
        };
        let mut row = Metrics::default();
        fold_llc_val(&mut row, &val);
        out.push((llc, row));
        if llc + 1 >= 64 {
            break;
        }
    }
    out
}
