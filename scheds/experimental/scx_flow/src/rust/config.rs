// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults that match intf.h.

use anyhow::Result;
use anyhow::bail;

/// Fixed slice in nanos at 1ms. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 1_000_000;
/// Dynamic slice floor in nanos at 10us. Fresh waits clamp the
/// saturated remaining time to this floor with the quantum ceiling.
pub const SLICE_MIN_NS: u64 = 10_000;
/// Default period in nanos at 16ms. Holds sixteen slices.
pub const PERIOD_NS: u64 = 16_000_000;
/// Least predictor value in nanos at 1. Clamps short bursts.
pub const PRED_MIN_NS: u64 = 1;
/// Largest predictor value in nanos at 1s. Clamps long bursts.
pub const PRED_MAX_NS: u64 = 1_000_000_000;
/// Base capacity in units at 1024. Symmetric hosts share the base.
pub const CAP_BASE: u32 = 1024;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 16_384;
/// Max hint rows bound shared with the BPF header.
pub const HINT_MAX: u64 = 8192;
/// RED bound in nanos at 128us. Caps the maximum exceeding time.
pub const RED_EMAX_NS: u64 = 128_000;
/// RED tolerance in nanos at 64us. Holds hard task slack only.
pub const RED_TOL_NS: u64 = 64_000;
/// Adaptive grow step in nanos at 64us frozen for wire compat only.
/// Kept with no use after the proportional law.
pub const ADAPT_GROW_NS: u64 = 64_000;
/// Adaptive shrink step in nanos at 128us frozen for wire compat only.
/// Kept with no use after the proportional law.
pub const ADAPT_SHRINK_NS: u64 = 128_000;
/// Proportional adapt cap in nanos at 256us. Caps one shift step.
pub const ADAPT_PROP_MAX_NS: u64 = 256_000;
/// Proportional adapt shift at 3. Maps exceed plus slack to one eighth.
pub const ADAPT_PROP_SHIFT: u32 = 3;
/// Latency slice cap in nanos at 100us. Caps the dynamic slice plus
/// the carryover plus the adapt step for latency work, so urgent
/// wakeups rotate each tenth quantum with no extra hold. The cap
/// equals the preempt tail, so a latency head at the cap never passes
/// the tail gate and floors with no resume. Adapt steps cap at 256us
/// then re-clamp here, so one shift never holds past the cap. RED Emax
/// stays at 128us past the cap, so a capped latency slice never pays
/// as victim with no swap.
pub const SLICE_LAT_NS: u64 = 100_000;
/// Latency sleep floor in nanos at 20us. Vetoes only sleeps below this
/// floor toward batch with no knob, so the 100us slice cap stays
/// decoupled with no extra hold. Like fair.c, the floor paces service
/// with no fixed priority hold. Unknown sleep fails open with no stall.
pub const LAT_SLEEP_MIN_NS: u64 = 20_000;
/// Latency deadline bound in nanos at 4ms. Holds one quarter period.
pub const D_LAT_NS: u64 = 4_000_000;
/// Preempt margin in nanos at 100us. Leads the occupant key, so near
/// ties never bounce with no knob.
pub const PREEMPT_MARGIN_NS: u64 = 100_000;
/// Preempt tail in nanos at 100us. Holds the owner leftover, so nearly
/// done owners finish with no knob.
pub const PREEMPT_TAIL_NS: u64 = 100_000;

/// Default fixed slice in nanos.
const DEF_QUANTUM_NS: u64 = QUANTUM_NS;

/// Mirror of flow_adapt_prop in intf.h for host tests.
/// Shifts only with no divide, capped at 256us, clamped 10us to 1ms.
/// An exceed shrinks, a slack grows, both zero holds, exceed wins.
#[cfg(test)]
pub fn adapt_prop(cur: u32, exceed: u64, slack: u64) -> u32 {
    let base = if cur == 0 { QUANTUM_NS } else { cur as u64 };
    // Clamp helper keeps the same 10us plus 1ms bounds as BPF.
    let clamp = |v: u64| -> u32 {
        if v < SLICE_MIN_NS {
            return SLICE_MIN_NS as u32;
        }
        if v > QUANTUM_NS {
            return QUANTUM_NS as u32;
        }
        v as u32
    };
    if exceed != 0 {
        let mut step = exceed >> ADAPT_PROP_SHIFT;
        if step > ADAPT_PROP_MAX_NS {
            step = ADAPT_PROP_MAX_NS;
        }
        if step == 0 {
            return clamp(base);
        }
        if base <= step {
            return SLICE_MIN_NS as u32;
        }
        return clamp(base - step);
    }
    if slack != 0 {
        let mut step = slack >> ADAPT_PROP_SHIFT;
        if step > ADAPT_PROP_MAX_NS {
            step = ADAPT_PROP_MAX_NS;
        }
        if step == 0 {
            return clamp(base);
        }
        return clamp(base.saturating_add(step));
    }
    clamp(base)
}

/// Mirror of flow_slice_lat_clamp in intf.h for host tests.
/// Caps the slice at 100us for latency with no knob.
#[cfg(test)]
pub fn slice_lat_clamp(slice: u32, is_lat: bool) -> u32 {
    if is_lat && (slice as u64) > SLICE_LAT_NS {
        return SLICE_LAT_NS as u32;
    }
    slice
}

/// Mirror of flow_red_cost in intf.h for host tests.
/// Costs burst else slice else quantum clamped to 10us plus 1ms, so
/// the guarantee bounds with no share shaping.
#[cfg(test)]
pub fn red_cost(avg: u64, slice: u32) -> u64 {
    if avg != 0 {
        if avg < SLICE_MIN_NS {
            return SLICE_MIN_NS;
        }
        if avg > QUANTUM_NS {
            return QUANTUM_NS;
        }
        return avg;
    }
    if slice != 0 {
        let s = slice as u64;
        if s < SLICE_MIN_NS {
            return SLICE_MIN_NS;
        }
        if s > QUANTUM_NS {
            return QUANTUM_NS;
        }
        return s;
    }
    QUANTUM_NS
}

/// Mirror of flow_lat_deadline in intf.h for host tests.
/// Takes max 4ms else slice plus margin with saturation, then adds now
/// with saturation for ns accuracy with no divide.
#[cfg(test)]
pub fn lat_deadline(now: u64, slice: u32) -> u64 {
    let need = (slice as u64).saturating_add(PREEMPT_MARGIN_NS);
    let bound = if need > D_LAT_NS { need } else { D_LAT_NS };
    now.saturating_add(bound)
}

/// Mirror of flow_lat_crit_ext in intf.h for host tests.
/// Advisory veto toward batch with 20us sleep floor plus
/// quantum-relative bounds plus no divide, so unknown sleep plus clamp
/// plus share fail open with no stall. The sleep floor stays decoupled
/// from the 100us slice cap. Newcomers with no history stay batch with
/// probation.
#[cfg(test)]
pub fn lat_crit_ext(
    avg: u64,
    dev: u64,
    hint_us: u32,
    sleep_ns: u64,
    uclamp_min: u32,
    eff_w: u32,
) -> bool {
    if avg == 0 {
        return false;
    }
    {
        let pred = avg.saturating_add(dev);
        if pred == u64::MAX {
            return false;
        }
        if pred > QUANTUM_NS {
            return false;
        }
    }
    if hint_us != 0 {
        let h = hint_us as u64;
        if h > 18_446_744_073_709_551 {
            return false;
        }
        if h * 1000 > QUANTUM_NS {
            return false;
        }
    }
    if sleep_ns != 0 && sleep_ns < LAT_SLEEP_MIN_NS {
        return false;
    }
    if uclamp_min != 0 && uclamp_min < 512 {
        return false;
    }
    if eff_w != 0 && eff_w < WEIGHT_BASE {
        return false;
    }
    true
}

/// Mirror of flow_lat_crit in intf.h for host tests.
/// Newcomers with no history stay batch with probation.
#[cfg(test)]
pub fn lat_crit(avg: u64, dev: u64) -> bool {
    if avg == 0 {
        return false;
    }
    let pred = avg.saturating_add(dev);
    if pred == u64::MAX {
        return false;
    }
    pred <= QUANTUM_NS
}

/// Mirror of flow_is_lat in intf.h for host tests.
/// Unifies base plus ext, so RED and slice agree.
#[cfg(test)]
pub fn is_lat(
    avg: u64,
    dev: u64,
    hint_us: u32,
    sleep_ns: u64,
    uclamp_min: u32,
    eff_w: u32,
) -> bool {
    if !lat_crit(avg, dev) {
        return false;
    }
    lat_crit_ext(avg, dev, hint_us, sleep_ns, uclamp_min, eff_w)
}

/// Wrap-safe order for host tests mirroring flow_time_before.
/// Uses the signed diff, so the u64 wrap keeps order with no branch.
#[cfg(test)]
fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Mirror of flow_sleep_ns in intf.h for host tests.
/// Isolates now minus wait minus burst, so queue plus run never count
/// as sleep with wrap safety and probation.
#[cfg(test)]
pub fn sleep_ns(old_wait: u64, now: u64, avg: u64) -> u64 {
    if old_wait == 0 {
        return 0;
    }
    if !time_before(old_wait, now) {
        return 0;
    }
    let mut gap = now - old_wait;
    if avg != 0 {
        if gap > avg {
            gap -= avg;
        } else {
            gap = 0;
        }
    }
    gap
}

/// Mirror of flow_preempt_ok in preempt.bpf.c for host tests.
/// Needs lat arrival against batch owner with 100us margin lead plus
/// 100us tail left on start plus inherit cur, so near ties plus nearly
/// done owners never bounce with wrap safety.
#[cfg(test)]
pub fn preempt_ok(
    arr_key: u64,
    occ_key: u64,
    now: u64,
    occ_run_at: u64,
    occ_cur: u32,
    arr_lat: bool,
    occ_lat: bool,
) -> bool {
    if !arr_lat || occ_lat {
        return false;
    }
    if arr_key == 0 || arr_key == u64::MAX {
        return false;
    }
    if occ_key == 0 || occ_key == u64::MAX {
        return false;
    }
    if !time_before(arr_key, occ_key) {
        return false;
    }
    let margin = arr_key.saturating_add(PREEMPT_MARGIN_NS);
    if margin == u64::MAX {
        return false;
    }
    if !time_before(margin, occ_key) {
        return false;
    }
    if occ_run_at == 0 || occ_run_at == u64::MAX {
        return false;
    }
    let base = if occ_cur == 0 {
        QUANTUM_NS
    } else {
        occ_cur as u64
    };
    let occ_end = occ_run_at.saturating_add(base);
    if occ_end == u64::MAX {
        return false;
    }
    let tail = now.saturating_add(PREEMPT_TAIL_NS);
    if tail == u64::MAX {
        return false;
    }
    if !time_before(tail, occ_end) {
        return false;
    }
    true
}

/// Mirror of flow_slice_resume in intf.h for host tests.
/// Keeps start plus cur leftover clamped to 10us plus 100us else 1ms
/// with wrap-safe order, so a wrapped clock never reads as leftover.
/// Equality fails closed and floors, so a head at the 100us cap never
/// resumes past the equal tail.
#[cfg(test)]
pub fn slice_resume(start: u64, now: u64, is_lat: bool, cur: u32) -> u32 {
    let base = if cur == 0 { QUANTUM_NS } else { cur as u64 };
    if start == 0 || start == u64::MAX {
        return base as u32;
    }
    let end = start.saturating_add(base);
    if end == u64::MAX {
        return base as u32;
    }
    let rem = if !time_before(now, end) && now != end {
        0
    } else if time_before(now, end) {
        end.wrapping_sub(now)
    } else {
        0
    };
    let cap = if is_lat { SLICE_LAT_NS } else { QUANTUM_NS };
    if rem < SLICE_MIN_NS {
        return SLICE_MIN_NS as u32;
    }
    if rem > cap {
        return cap as u32;
    }
    rem as u32
}

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Fixed slice in nanos. Always 1ms with no knob.
    pub quantum_ns: u64,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            quantum_ns: DEF_QUANTUM_NS,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds the BPF side relies on.
    /// An invalid value is a programming fault, not a runtime state.
    /// The slice stays fixed at 1ms with base weight 128 in range
    /// 1 to 16384. The period stays at 16ms with predictor 1ns to 1s.
    /// Fresh waits clamp remaining time to the 10us floor plus the 1ms
    /// ceiling with misses holding else flooring only.
    /// Dispatch moves at most one hint threaded move per tier bounded
    /// by remaining slots with visits capped at 8 per pass shared across
    /// three PRIQ tiers plus steal plus reclaim window 4 to 8 with BSF
    /// four disjoint past SSF eight for twelve unique peers on hosts
    /// with at least twelve CPUs with node-local phases plus drain plus
    /// minimum plus id tiebreak, and RED admits with residual plus
    /// exceed plus tolerance used only for the guarantee with base
    /// capacity 1024. Queues hold 1024 local plus 16 node plus machine
    /// plus reject with ids in the 0x5100 region. Hints hold 8192 flat
    /// rows with period plus weight and no timer wait. Preempt needs
    /// 100us margin plus 100us tail strictly with a floor at 100us and
    /// one kick per wait gated on eligibility. Fairness bounds lag at
    /// 2ms with vruntime plus virtual deadline pacing queue order.
    /// Stats hold 17 counters at 136B with preempt kicks plus skipped
    /// plus RED rejects plus reclaims. Adaptive shrinks by exceed right 3
    /// capped 256us on late else grows by slack right 3 capped 256us on
    /// early with clamp to 10us plus 1ms and no virtual change. Latency
    /// caps the slice at 100us plus the key at now plus max 4ms else
    /// slice plus 100us with RED on the original deadline. Latency
    /// vetoes sleeps below 20us toward batch with unknown open, so the
    /// sleep floor stays decoupled from the slice cap.
    pub fn validate(&self) -> Result<()> {
        if self.quantum_ns != QUANTUM_NS {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if SLICE_MIN_NS != 10_000 {
            bail!("slice floor bad");
        }
        if SLICE_MIN_NS >= QUANTUM_NS {
            bail!("slice floor over ceiling bad");
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 128 || WEIGHT_MAX != 16_384 {
            bail!("weight bounds bad");
        }
        if PERIOD_NS != 16_000_000 {
            bail!("period bounds bad");
        }
        if PRED_MIN_NS != 1 || PRED_MAX_NS != 1_000_000_000 {
            bail!("predictor bounds bad");
        }
        if CAP_BASE != 1024 {
            bail!("capacity base bad");
        }
        if HINT_MAX != 8192 {
            bail!("hint bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64 != QUANTUM_NS {
            bail!("quantum header bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_SLICE_MIN_NS as u64 != SLICE_MIN_NS {
            bail!("slice floor header bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PERIOD_NS as u64 != PERIOD_NS {
            bail!("period header bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PRED_MIN_NS as u64 != PRED_MIN_NS {
            bail!("pred floor bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PRED_MAX_NS as u64 != PRED_MAX_NS {
            bail!("pred ceiling bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_WEIGHT_MIN as u64 != WEIGHT_MIN as u64 {
            bail!("weight floor bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_WEIGHT_BASE as u64 != WEIGHT_BASE as u64 {
            bail!("weight base bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_WEIGHT_MAX as u64 != WEIGHT_MAX as u64 {
            bail!("weight top bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_CAP_BASE as u64 != CAP_BASE as u64 {
            bail!("cap base bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64 != HINT_MAX {
            bail!("hint header bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64 != PREEMPT_MARGIN_NS {
            bail!("margin bad");
        }
        if PREEMPT_MARGIN_NS != 100_000 {
            bail!("margin bounds bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64 != PREEMPT_TAIL_NS {
            bail!("tail bad");
        }
        if PREEMPT_TAIL_NS != 100_000 {
            bail!("tail bounds bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_VLAG_MAX_NS as u64 != 2_000_000 {
            bail!("lag bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64 != 1042 {
            bail!("dsq count bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u64 != 8 {
            bail!("visit bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_STEAL_MIN_PEERS as u64 != 4
            || crate::bpf_intf::flow_consts_FLOW_STEAL_MAX_PEERS as u64 != 8
        {
            bail!("steal window bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u64 != 4 {
            bail!("bsf bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u64
            > crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u64
        {
            bail!("bsf over visit bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64 != 0x5A01 {
            bail!("overflow id bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_RED_EMAX_NS as u64 != RED_EMAX_NS {
            bail!("red emax bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_RED_TOL_NS as u64 != RED_TOL_NS {
            bail!("red tol bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_ADAPT_GROW_NS as u64 != ADAPT_GROW_NS {
            bail!("adapt grow bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_ADAPT_SHRINK_NS as u64 != ADAPT_SHRINK_NS {
            bail!("adapt shrink bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_ADAPT_PROP_MAX_NS as u64 != ADAPT_PROP_MAX_NS {
            bail!("adapt prop max bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_ADAPT_PROP_SHIFT as u64 != ADAPT_PROP_SHIFT as u64 {
            bail!("adapt prop shift bad");
        }
        if ADAPT_PROP_MAX_NS != 256_000 {
            bail!("prop max bounds bad");
        }
        if ADAPT_PROP_SHIFT != 3 {
            bail!("prop shift bounds bad");
        }
        if ADAPT_PROP_MAX_NS >= QUANTUM_NS {
            bail!("prop max over ceiling bad");
        }
        if SLICE_LAT_NS != 100_000 {
            bail!("slice lat bad");
        }
        if D_LAT_NS != 4_000_000 {
            bail!("d lat bad");
        }
        if SLICE_LAT_NS <= SLICE_MIN_NS {
            bail!("slice lat floor bad");
        }
        if SLICE_LAT_NS >= QUANTUM_NS {
            bail!("slice lat over ceiling bad");
        }
        if D_LAT_NS != PERIOD_NS / 4 {
            bail!("d lat period bad");
        }
        if D_LAT_NS >= PERIOD_NS {
            bail!("d lat over period bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_SLICE_LAT_NS as u64 != SLICE_LAT_NS {
            bail!("slice lat header bad");
        }
        if LAT_SLEEP_MIN_NS != 20_000 {
            bail!("lat sleep bad");
        }
        if LAT_SLEEP_MIN_NS < PRED_MIN_NS {
            bail!("lat sleep floor bad");
        }
        if LAT_SLEEP_MIN_NS >= SLICE_LAT_NS {
            bail!("lat sleep over slice bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_LAT_SLEEP_MIN_NS as u64 != LAT_SLEEP_MIN_NS {
            bail!("lat sleep header bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_D_LAT_NS as u64 != D_LAT_NS {
            bail!("d lat header bad");
        }
        if std::mem::size_of::<crate::bpf_intf::flow_sched_stats>() != 136 {
            bail!("stats size bad");
        }
        if std::mem::size_of::<crate::bpf_intf::flow_task_ctx>() != 72 {
            bail!("task size bad");
        }
        Ok(())
    }

    /// One line summary of the constants for the start log.
    /// Values print in microseconds for brevity.
    pub fn describe(&self) -> String {
        format!("quantum={}us", self.quantum_ns / 1000,)
    }
}

/// Builder for Config used only by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    quantum_ns: Option<u64>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the fixed slice.
    pub fn quantum_ns(mut self, v: u64) -> Self {
        self.quantum_ns = Some(v);
        self
    }
    /// Assemble and validate the result.
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let cfg = Config {
            quantum_ns: self.quantum_ns.unwrap_or(d.quantum_ns),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn builder_defaults_match_config() {
        let cfg = ConfigBuilder::default().build().unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn rejects_bad_quantum() {
        let a = ConfigBuilder::default().quantum_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_ns(2_000_000).build();
        assert!(b.is_err());
    }

    #[test]
    /// Summary holds the fixed slice with no knob.
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("quantum=1000us"));
        assert!(!s.contains("batch"));
    }

    #[test]
    /// Dynamic slice spans the 10us floor to the 1ms ceiling.
    fn slice_bounds_match_intf_h() {
        assert_eq!(SLICE_MIN_NS, 10_000);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_SLICE_MIN_NS as u64,
            SLICE_MIN_NS
        );
        const _: () = assert!(SLICE_MIN_NS < QUANTUM_NS);
    }

    #[test]
    /// Defaults match the shared header with local plus shared queues.
    fn defaults_match_intf_h() {
        assert_eq!(
            Config::default().quantum_ns,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(QUANTUM_NS, 1_000_000);
        assert_eq!(PERIOD_NS, 16_000_000);
        assert_eq!(PRED_MIN_NS, 1);
        assert_eq!(PRED_MAX_NS, 1_000_000_000);
        assert_eq!(CAP_BASE, 1024);
        assert_eq!(WEIGHT_MIN, 1);
        assert_eq!(WEIGHT_BASE, 128);
        assert_eq!(WEIGHT_MAX, 16_384);
        assert_eq!(HINT_MAX, 8192);
        assert_eq!(RED_EMAX_NS, 128_000);
        assert_eq!(RED_TOL_NS, 64_000);
        assert_eq!(ADAPT_GROW_NS, 64_000);
        assert_eq!(ADAPT_SHRINK_NS, 128_000);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 1042);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_VLAG_MAX_NS as u64,
            2_000_000
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MACHINE as u64, 0x5A00);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x5A01);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u64,
            8
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u64, 4);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_LOCAL_BASE as u64, 0x5100);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_NODE_BASE as u64, 0x5900);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64, HINT_MAX);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PRED_MIN_NS as u64,
            PRED_MIN_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PRED_MAX_NS as u64,
            PRED_MAX_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_CAP_BASE as u64,
            CAP_BASE as u64
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_WEIGHT_BASE as u64,
            WEIGHT_BASE as u64
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_WEIGHT_MAX as u64,
            WEIGHT_MAX as u64
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64,
            PREEMPT_MARGIN_NS
        );
        assert_eq!(PREEMPT_MARGIN_NS, 100_000);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64,
            PREEMPT_TAIL_NS
        );
        assert_eq!(PREEMPT_TAIL_NS, 100_000);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_RED_EMAX_NS as u64,
            RED_EMAX_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_RED_TOL_NS as u64,
            RED_TOL_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_ADAPT_GROW_NS as u64,
            ADAPT_GROW_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_ADAPT_SHRINK_NS as u64,
            ADAPT_SHRINK_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_ADAPT_PROP_MAX_NS as u64,
            ADAPT_PROP_MAX_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_ADAPT_PROP_SHIFT as u64,
            ADAPT_PROP_SHIFT as u64
        );
        assert_eq!(ADAPT_PROP_MAX_NS, 256_000);
        assert_eq!(ADAPT_PROP_SHIFT, 3);
        assert_eq!(SLICE_LAT_NS, 100_000);
        assert_eq!(LAT_SLEEP_MIN_NS, 20_000);
        assert_eq!(D_LAT_NS, 4_000_000);
        assert_eq!(D_LAT_NS, PERIOD_NS / 4);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_SLICE_LAT_NS as u64,
            SLICE_LAT_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_LAT_SLEEP_MIN_NS as u64,
            LAT_SLEEP_MIN_NS
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_D_LAT_NS as u64, D_LAT_NS);
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            136
        );
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 72);
    }

    #[test]
    /// Proportional adapt shrinks on exceed plus grows on slack.
    fn prop_shrink_grow_matches_intf_h() {
        // Exceed 8us shrinks 1us with shift 3 only.
        assert_eq!(adapt_prop(1_000_000, 8_000, 0), 999_000);
        // Slack 1.6us grows 200ns with shift 3 only.
        assert_eq!(adapt_prop(500_000, 0, 1_600), 500_200);
        // Huge exceed caps at 256us shrink.
        assert_eq!(adapt_prop(1_000_000, 10_000_000, 0), 744_000);
        // Huge slack caps at 256us grow clamped to 1ms.
        assert_eq!(adapt_prop(900_000, 0, 10_000_000), 1_000_000);
        // Small base shrinks to the 10us floor.
        assert_eq!(adapt_prop(10_000, 80_000, 0), 10_000);
        // On-time hold keeps the clamped slice.
        assert_eq!(adapt_prop(500_000, 0, 0), 500_000);
        // Zero slice inherits the quantum then shrinks.
        assert_eq!(adapt_prop(0, 8_000, 0), 999_000);
        // Tiny exceed below 8ns holds with no divide.
        assert_eq!(adapt_prop(500_000, 7, 0), 500_000);
        // Early 500 plus 700 slack 200 grows 25ns.
        assert_eq!(adapt_prop(500_000, 0, 200), 500_025);
        // Exceed wins when both hold.
        assert_eq!(
            adapt_prop(500_000, 8_000, 1_600),
            adapt_prop(500_000, 8_000, 0)
        );
    }

    #[test]
    /// RED costs the pre-clamp slice with no post-clamp underestimate.
    fn red_uses_pre_clamp_not_post() {
        // Fresh 1ms pre-clamp caps to 100us for latency slice.
        let pre = 1_000_000;
        let post = slice_lat_clamp(pre, true);
        assert_eq!(post, 100_000);
        // RED still costs the 1ms pre-clamp with no underestimate.
        assert_eq!(red_cost(0, pre), 1_000_000);
        assert_eq!(red_cost(0, post), 100_000);
        assert!(red_cost(0, pre) > red_cost(0, post));
        // Burst wins over slice with the same 10us plus 1ms clamp.
        assert_eq!(red_cost(900_000, 1_000_000), 900_000);
        assert_eq!(red_cost(0, 0), QUANTUM_NS);
        assert_eq!(red_cost(1, 1_000_000), SLICE_MIN_NS);
    }

    #[test]
    /// Latency slice clamps at 100us plus deadline at max 4ms.
    fn lat_bounds_match_intf_h() {
        const _: () = assert!(SLICE_LAT_NS > SLICE_MIN_NS);
        const _: () = assert!(SLICE_LAT_NS < QUANTUM_NS);
        const _: () = assert!(LAT_SLEEP_MIN_NS < SLICE_LAT_NS);
        const _: () = assert!(LAT_SLEEP_MIN_NS >= PRED_MIN_NS);
        assert_eq!(SLICE_LAT_NS, 100_000);
        assert_eq!(LAT_SLEEP_MIN_NS, 20_000);
        assert_eq!(D_LAT_NS, 4_000_000);
        assert_eq!(D_LAT_NS, PERIOD_NS / 4);
        // Non latency keeps the slice.
        assert_eq!(slice_lat_clamp(1_000_000, false), 1_000_000);
        // Latency caps at 100us.
        assert_eq!(slice_lat_clamp(1_000_000, true), 100_000);
        assert_eq!(slice_lat_clamp(100_000, true), 100_000);
        // Deadline floors at 4ms plus adds slice plus 100us.
        assert_eq!(lat_deadline(0, 100_000), 4_000_000);
        assert_eq!(lat_deadline(1_000, 1_000_000), 1_000 + 4_000_000);
        assert_eq!(lat_deadline(0, 5_000_000), 5_100_000);
        // Saturates on wrap with ns accuracy.
        assert_eq!(lat_deadline(u64::MAX - 1_000, 100_000), u64::MAX);
    }

    #[test]
    /// Extended latency vetoes batch hints with probation.
    fn lat_ext_veto_matches_intf_h() {
        // Newcomers with no history stay batch with probation.
        assert!(!lat_crit_ext(0, 0, 0, 0, 0, 0));
        assert!(!lat_crit(0, 0));
        assert!(!is_lat(0, 0, 0, 0, 0, 0));
        // Short burst with neutral signals keeps latency.
        assert!(lat_crit_ext(100_000, 10_000, 0, 1_000_000, 0, 128));
        assert!(lat_crit(100_000, 10_000));
        assert!(is_lat(100_000, 10_000, 0, 1_000_000, 0, 128));
        // Unified latency matches base plus ext, so RED agrees.
        assert!(!is_lat(900_000, 200_000, 0, 1_000_000, 0, 128));
        assert!(!is_lat(100_000, 10_000, 2000, 1_000_000, 0, 128));
        assert!(!is_lat(100_000, 10_000, 0, 10_000, 0, 128));
        assert!(is_lat(100_000, 10_000, 0, 30_000, 0, 128));
        assert!(is_lat(100_000, 10_000, 0, 50_000, 0, 128));
        assert!(is_lat(100_000, 10_000, 0, 150_000, 0, 128));
        assert!(is_lat(100_000, 10_000, 0, 0, 0, 128));
        // Long burst past quantum vetoes.
        assert!(!lat_crit_ext(900_000, 200_000, 0, 1_000_000, 0, 128));
        // Large hint past quantum vetoes.
        assert!(!lat_crit_ext(100_000, 10_000, 2000, 1_000_000, 0, 128));
        // Small hint keeps latency.
        assert!(lat_crit_ext(100_000, 10_000, 500, 1_000_000, 0, 128));
        // Short sleep below 20us vetoes, 30us plus 50us plus 150us keep,
        // unknown sleep fails open with no stall.
        assert!(!lat_crit_ext(100_000, 10_000, 0, 10_000, 0, 128));
        assert!(lat_crit_ext(100_000, 10_000, 0, 30_000, 0, 128));
        assert!(lat_crit_ext(100_000, 10_000, 0, 50_000, 0, 128));
        assert!(lat_crit_ext(100_000, 10_000, 0, 150_000, 0, 128));
        assert!(lat_crit_ext(100_000, 10_000, 0, 0, 0, 128));
        // Explicit low clamp vetoes, unknown passes.
        assert!(!lat_crit_ext(100_000, 10_000, 0, 1_000_000, 100, 128));
        assert!(lat_crit_ext(100_000, 10_000, 0, 1_000_000, 1024, 128));
        // Light share vetoes, heavy keeps.
        assert!(!lat_crit_ext(100_000, 10_000, 0, 1_000_000, 0, 32));
        assert!(lat_crit_ext(100_000, 10_000, 0, 1_000_000, 0, 1024));
    }

    #[test]
    /// Sleep isolates now minus wait minus burst with probation.
    fn sleep_isolates_gap_minus_burst() {
        // Gap 1ms minus 200us burst leaves 800us sleep.
        assert_eq!(sleep_ns(1_000, 1_001_000, 200_000), 800_000);
        // Burst-covered gap reads zero with no underflow.
        assert_eq!(sleep_ns(1_000, 1_001_000, 2_000_000), 0);
        // No history keeps the full gap.
        assert_eq!(sleep_ns(1_000, 1_001_000, 0), 1_000_000);
        // Unknown wait plus wait at now both read zero.
        assert_eq!(sleep_ns(0, 1_000, 100_000), 0);
        assert_eq!(sleep_ns(1_000, 1_000, 100_000), 0);
    }

    #[test]
    /// Resume keeps start plus cur leftover with clamp.
    fn resume_uses_cur_not_quantum() {
        // Start plus 500us cur with 400us left keeps 400us batch.
        assert_eq!(
            slice_resume(1_000, 1_000 + 100_000, false, 500_000),
            400_000
        );
        // Latency caps the same leftover at 100us.
        assert_eq!(slice_resume(1_000, 1_000 + 100_000, true, 500_000), 100_000);
        // Start plus 250us cur keeps 150us rem capped to 100us for latency.
        assert_eq!(slice_resume(1_000, 1_000 + 100_000, true, 250_000), 100_000);
        // Bad start inherits the stored slice.
        assert_eq!(slice_resume(0, 1_000, false, 500_000), 500_000);
        assert_eq!(slice_resume(0, 1_000, true, 500_000), 500_000);
        // Past end floors to the minimum with no zero slice.
        assert_eq!(slice_resume(1_000, 1_000 + 600_000, false, 500_000), 10_000);
        // Saturated end near wrap inherits with no wrap to front.
        assert_eq!(slice_resume(u64::MAX - 10, 100, false, 500_000), 500_000);
    }

    #[test]
    /// Preempt needs lat arrival against batch owner only.
    fn preempt_needs_lat_to_batch_only() {
        // Arrival 1ms leads occupant 2ms with margin plus tail held.
        assert!(preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 1_000_000, true, false
        ));
        // Lat to lat plus batch to batch plus batch to lat fail closed.
        assert!(!preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 1_000_000, true, true
        ));
        assert!(!preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 1_000_000, false, false
        ));
        assert!(!preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 1_000_000, false, true
        ));
        // Near tie within 100us margin never bounces.
        assert!(!preempt_ok(
            1_950_000, 2_000_000, 500_000, 500_000, 1_000_000, true, false
        ));
        // Nearly done owner with tail left fails closed.
        assert!(!preempt_ok(
            1_000_000, 2_000_000, 1_450_000, 500_000, 1_000_000, true, false
        ));
        // Zero cur inherits quantum, so the same lead still wins.
        assert!(preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 0, true, false
        ));
        // Short 50us cur leaves no tail, so the kick fails closed.
        assert!(!preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 50_000, true, false
        ));
    }

    #[test]
    /// Miss plus skip plus period stays intentional with no drift.
    fn miss_skip_period_are_intentional() {
        // Misses stay lifetime: newcomers with no history stay batch.
        assert!(!is_lat(0, 0, 0, 0, 0, 0));
        // Skips count every hold: lat to lat fails closed by design.
        assert!(!preempt_ok(
            1_000_000, 2_000_000, 500_000, 500_000, 1_000_000, true, true
        ));
        // Period caps in-tier keys at now plus one period by design.
        assert_eq!(D_LAT_NS, PERIOD_NS / 4);
        assert_eq!(PERIOD_NS, 16_000_000);
    }
}
