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
/// Adaptive grow step in nanos at 64us. Widens the slice on a miss.
pub const ADAPT_GROW_NS: u64 = 64_000;
/// Adaptive shrink step in nanos at 128us. Narrows the slice on a hit.
pub const ADAPT_SHRINK_NS: u64 = 128_000;

/// Default fixed slice in nanos.
const DEF_QUANTUM_NS: u64 = QUANTUM_NS;

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
    /// plus RED rejects plus reclaims. Adaptive grows 64us on a miss
    /// else shrinks 128us with clamp to 10us plus 1ms and no virtual
    /// change.
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
        if crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64 != 100_000 {
            bail!("margin bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64 != 100_000 {
            bail!("tail bad");
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
            100_000
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64,
            100_000
        );
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
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            136
        );
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 72);
    }
}
