// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Userspace configuration, validated scheduling constants written into
//! BPF rodata.
//!
//! `Config` is the single validated set of scheduling constants; the BPF side
//! reads them from `const volatile` rodata globals declared in
//! `src/bpf/main.bpf.c` (see `src/bpf/intf.h` for the compile-time
//! defaults, which are the source of truth for every value here).
//!
//! `ConfigBuilder` assembles a `Config` from optional setters. Every
//! setter is optional and `build()` validates the assembled values, so an
//! invalid intermediate state can never be constructed.

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

/// Time units matching `enum mlfq_consts` in `src/bpf/intf.h`.
const NSEC_PER_USEC: u64 = 1_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

/*
 * Defaults must match `enum mlfq_consts` in `src/bpf/intf.h`; the BPF
 * compile-time values are the contract. The defaults are therefore derived
 * from the bindgen-generated constants (the same source `topology.rs`
 * cross-checks its constants against), so an intf.h change propagates here
 * automatically and the `defaults_match_intf_h` test pins the binding.
 * SHORT_SLEEP_NS is the one explicit value and the test pins it to the
 * intf.h constant.
 */

/// Per-queue request sizes.
const Q1_SLICE_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_Q1_SLICE_NS as u64;
const Q2_SLICE_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_Q2_SLICE_NS as u64;
const Q3_SLICE_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_Q3_SLICE_NS as u64;

/// EMA gauge ceiling.
const BUDGET_MAX_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_BUDGET_MAX_NS as u64;

/// Climb aggressiveness, fixed.
const ALPHA: u64 = crate::bpf_intf::mlfq_consts_MLFQ_ALPHA as u64;

/// Classification thresholds.
const T_L_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_T_L_NS as u64;
const T_H_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_T_H_NS as u64;

/// EMA decay half-life.
const EMA_HALF_LIFE_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_EMA_HALF_LIFE_NS as u64;

/// Aging period.
const AGING_PERIOD_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_AGING_PERIOD_NS as u64;

/// Short-sleep boost window: periodic wakeup cadences such as the 60 Hz
/// frame interval stay interactive; the per-task boost rate limit bounds
/// the churn.
const SHORT_SLEEP_NS: u64 = 32 * NSEC_PER_MSEC;
const SHORT_SLEEP_RATE_LIMIT_NS: u64 =
    crate::bpf_intf::mlfq_consts_MLFQ_SHORT_SLEEP_RATE_LIMIT_NS as u64;
const HYSTERESIS_SLEEP_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_HYSTERESIS_SLEEP_NS as u64;

/// A sleep longer than this collapses the gauge.
const LONG_SLEEP_NS: u64 = crate::bpf_intf::mlfq_consts_MLFQ_LONG_SLEEP_NS as u64;

/// Dispatch quotas.
const Q1_QUOTA: u32 = crate::bpf_intf::mlfq_consts_MLFQ_Q1_QUOTA;
const Q2_QUOTA: u32 = crate::bpf_intf::mlfq_consts_MLFQ_Q2_QUOTA;
const DISPATCH_MAX_BATCH: u32 = crate::bpf_intf::mlfq_consts_MLFQ_DISPATCH_MAX_BATCH;

/// Validated scheduling constants.
///
/// Every field maps to a `const volatile` rodata global in
/// `src/bpf/main.bpf.c`; field names match the BPF globals 1:1 so
/// `Config::apply()` is a mechanical write-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Q1 request size (interactive), nsecs.
    pub q1_slice_ns: u64,
    /// Q2 request size (default), nsecs.
    pub q2_slice_ns: u64,
    /// Q3 request size (batch), nsecs.
    pub q3_slice_ns: u64,
    /// EMA gauge ceiling, nsecs.
    pub budget_max_ns: u64,
    /// EMA climb aggressiveness (fixed).
    pub alpha: u64,
    /// Interactive threshold T_L, nsecs.
    pub t_l_ns: u64,
    /// CPU-bound threshold T_H, nsecs.
    pub t_h_ns: u64,
    /// EMA decay half-life, nsecs.
    pub ema_half_life_ns: u64,
    /// Global aging period, nsecs.
    pub aging_period_ns: u64,
    /// Short-sleep boost window, nsecs.
    pub short_sleep_ns: u64,
    /// Per-task short-sleep boost rate limit, nsecs.
    pub short_sleep_rate_limit_ns: u64,
    /// Sleep counted as "short" for the wake_cnt hysteresis, nsecs.
    pub hysteresis_sleep_ns: u64,
    /// Sleep beyond which the gauge collapses, nsecs.
    pub long_sleep_ns: u64,
    /// Q1 dispatch quota per dispatch() call.
    pub q1_quota: u32,
    /// Q2 dispatch quota per dispatch() call.
    pub q2_quota: u32,
    /// Dispatch-loop bound.
    pub dispatch_max_batch: u32,
}

impl Default for Config {
    /// Compile-time defaults from `src/bpf/intf.h`.
    fn default() -> Self {
        Self {
            q1_slice_ns: Q1_SLICE_NS,
            q2_slice_ns: Q2_SLICE_NS,
            q3_slice_ns: Q3_SLICE_NS,
            budget_max_ns: BUDGET_MAX_NS,
            alpha: ALPHA,
            t_l_ns: T_L_NS,
            t_h_ns: T_H_NS,
            ema_half_life_ns: EMA_HALF_LIFE_NS,
            aging_period_ns: AGING_PERIOD_NS,
            short_sleep_ns: SHORT_SLEEP_NS,
            short_sleep_rate_limit_ns: SHORT_SLEEP_RATE_LIMIT_NS,
            hysteresis_sleep_ns: HYSTERESIS_SLEEP_NS,
            long_sleep_ns: LONG_SLEEP_NS,
            q1_quota: Q1_QUOTA,
            q2_quota: Q2_QUOTA,
            dispatch_max_batch: DISPATCH_MAX_BATCH,
        }
    }
}

impl Config {
    /// Validate the configuration against the invariants the BPF side
    /// relies on (`src/bpf/intf.h`).
    ///
    /// An invalid configuration is a programming error, not a runtime
    /// condition: `ConfigBuilder::build()` enforces it before any value is
    /// written into rodata.
    fn validate(&self) -> Result<()> {
        if self.q1_slice_ns == 0 || self.q2_slice_ns == 0 || self.q3_slice_ns == 0 {
            bail!(
                "queue slices must be non-zero (got Q1={} Q2={} Q3={})",
                self.q1_slice_ns,
                self.q2_slice_ns,
                self.q3_slice_ns
            );
        }
        if self.budget_max_ns == 0 {
            bail!("budget_max must be non-zero");
        }
        if self.alpha == 0 {
            bail!("alpha must be non-zero");
        }
        if self.t_l_ns == 0 {
            bail!("T_L must be non-zero");
        }
        if self.t_l_ns >= self.t_h_ns {
            bail!(
                "T_L ({}) must be strictly below T_H ({})",
                self.t_l_ns,
                self.t_h_ns
            );
        }
        if self.t_h_ns >= self.budget_max_ns {
            bail!(
                "T_H ({}) must be strictly below BUDGET_MAX ({})",
                self.t_h_ns,
                self.budget_max_ns
            );
        }
        if self.ema_half_life_ns == 0 {
            bail!("EMA half-life must be non-zero");
        }
        if self.aging_period_ns == 0 {
            bail!("aging period must be non-zero");
        }
        if self.short_sleep_ns == 0 {
            bail!("short-sleep window must be non-zero");
        }
        if self.short_sleep_rate_limit_ns == 0 {
            bail!("short-sleep rate limit must be non-zero");
        }
        if self.hysteresis_sleep_ns == 0 {
            bail!("hysteresis sleep window must be non-zero");
        }
        if self.long_sleep_ns == 0 {
            bail!("long-sleep window must be non-zero");
        }
        if self.q1_quota == 0 || self.q2_quota == 0 {
            bail!(
                "dispatch quotas must be non-zero (got Q1={} Q2={})",
                self.q1_quota,
                self.q2_quota
            );
        }
        if self.dispatch_max_batch == 0 {
            bail!("dispatch_max_batch must be non-zero");
        }
        /*
         * dispatch() serves Q1 up to its quota, then Q2 up to its quota,
         * then the Q3 remainder within dispatch_max_batch.
         * If the quotas consume the whole batch, Q3 never runs on a busy
         * system: the cross-queue starvation bound depends on this slack.
         */
        if u64::from(self.q1_quota) + u64::from(self.q2_quota) >= u64::from(self.dispatch_max_batch)
        {
            bail!(
                "Q1+Q2 quotas ({}+{}) must leave headroom for Q3 within the dispatch batch ({})",
                self.q1_quota,
                self.q2_quota,
                self.dispatch_max_batch
            );
        }
        /*
         * The kernel's per-dispatch() move budget is set from the ops table
         * (.dispatch_max_batch = MLFQ_DISPATCH_MAX_BATCH in main.bpf.c).
         * A userspace batch larger than that constant would make the BPF
         * dispatch loops try to move more tasks than the kernel allows per
         * call, so the rodata value must never exceed it.
         */
        if self.dispatch_max_batch > crate::bpf_intf::mlfq_consts_MLFQ_DISPATCH_MAX_BATCH {
            bail!(
                "dispatch_max_batch ({}) exceeds the ops-table bound ({})",
                self.dispatch_max_batch,
                crate::bpf_intf::mlfq_consts_MLFQ_DISPATCH_MAX_BATCH
            );
        }
        Ok(())
    }

    /// Write the validated constants into the BPF object's rodata section.
    ///
    /// Must be called on the opened, not-yet-loaded skeleton, before
    /// `scx_ops_load!()` - rodata becomes read-only after load.
    pub fn apply(&self, skel: &mut crate::bpf_skel::OpenBpfSkel<'_>) -> Result<()> {
        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("rodata missing, the BPF object has no .rodata section")?;
        rodata.mlfq_q1_slice_ns = self.q1_slice_ns;
        rodata.mlfq_q2_slice_ns = self.q2_slice_ns;
        rodata.mlfq_q3_slice_ns = self.q3_slice_ns;
        rodata.mlfq_budget_max_ns = self.budget_max_ns;
        rodata.mlfq_alpha = self.alpha;
        rodata.mlfq_t_l_ns = self.t_l_ns;
        rodata.mlfq_t_h_ns = self.t_h_ns;
        rodata.mlfq_ema_half_life_ns = self.ema_half_life_ns;
        rodata.mlfq_aging_period_ns = self.aging_period_ns;
        rodata.mlfq_short_sleep_ns = self.short_sleep_ns;
        rodata.mlfq_short_sleep_rate_limit_ns = self.short_sleep_rate_limit_ns;
        rodata.mlfq_hysteresis_sleep_ns = self.hysteresis_sleep_ns;
        rodata.mlfq_long_sleep_ns = self.long_sleep_ns;
        rodata.mlfq_q1_quota = self.q1_quota;
        rodata.mlfq_q2_quota = self.q2_quota;
        rodata.mlfq_dispatch_max_batch = self.dispatch_max_batch;
        Ok(())
    }

    /// One-line summary of the applied constants for the startup log.
    pub fn describe(&self) -> String {
        format!(
            "slices: Q1={}us Q2={}us Q3={}us, T_L={}us, T_H={}us, \
             budget_max={}us, alpha={}, ema_half_life={}us, aging_period={}s, \
             short_sleep={}us, ss_rate_limit={}us, hysteresis_sleep={}us, \
             long_sleep={}ms, quotas: Q1={} Q2={} max_batch={}",
            self.q1_slice_ns / NSEC_PER_USEC,
            self.q2_slice_ns / NSEC_PER_USEC,
            self.q3_slice_ns / NSEC_PER_USEC,
            self.t_l_ns / NSEC_PER_USEC,
            self.t_h_ns / NSEC_PER_USEC,
            self.budget_max_ns / NSEC_PER_USEC,
            self.alpha,
            self.ema_half_life_ns / NSEC_PER_USEC,
            self.aging_period_ns / NSEC_PER_SEC,
            self.short_sleep_ns / NSEC_PER_USEC,
            self.short_sleep_rate_limit_ns / NSEC_PER_USEC,
            self.hysteresis_sleep_ns / NSEC_PER_USEC,
            self.long_sleep_ns / NSEC_PER_MSEC,
            self.q1_quota,
            self.q2_quota,
            self.dispatch_max_batch,
        )
    }
}

/// Builder for `Config`, assembled from optional setters.
///
/// Every setter is optional; unset fields fall back to the `intf.h`
/// defaults. `build()` validates the result and returns an error for any
/// configuration that would break a BPF invariant.
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    q1_slice_ns: Option<u64>,
    q2_slice_ns: Option<u64>,
    q3_slice_ns: Option<u64>,
    budget_max_ns: Option<u64>,
    alpha: Option<u64>,
    t_l_ns: Option<u64>,
    t_h_ns: Option<u64>,
    ema_half_life_ns: Option<u64>,
    aging_period_ns: Option<u64>,
    short_sleep_ns: Option<u64>,
    short_sleep_rate_limit_ns: Option<u64>,
    hysteresis_sleep_ns: Option<u64>,
    long_sleep_ns: Option<u64>,
    q1_quota: Option<u32>,
    q2_quota: Option<u32>,
    dispatch_max_batch: Option<u32>,
}

/*
 * The setters assemble a Config from the intf.h defaults and run it
 * through build()'s validation. The scheduler is intentionally knob-free,
 * so the production path always uses the defaults. The setters are
 * exercised by the unit tests, which drive every field through the
 * validation contract.
 */
#[allow(dead_code)]
impl ConfigBuilder {
    /// Set the Q1 (interactive) request size in nsecs.
    pub fn q1_slice_ns(mut self, v: u64) -> Self {
        self.q1_slice_ns = Some(v);
        self
    }

    /// Set the Q2 (default) request size in nsecs.
    pub fn q2_slice_ns(mut self, v: u64) -> Self {
        self.q2_slice_ns = Some(v);
        self
    }

    /// Set the Q3 (batch) request size in nsecs.
    pub fn q3_slice_ns(mut self, v: u64) -> Self {
        self.q3_slice_ns = Some(v);
        self
    }

    /// Set the EMA gauge ceiling in nsecs.
    pub fn budget_max_ns(mut self, v: u64) -> Self {
        self.budget_max_ns = Some(v);
        self
    }

    /// Set the EMA climb aggressiveness.
    pub fn alpha(mut self, v: u64) -> Self {
        self.alpha = Some(v);
        self
    }

    /// Set the interactive threshold T_L in nsecs.
    pub fn t_l_ns(mut self, v: u64) -> Self {
        self.t_l_ns = Some(v);
        self
    }

    /// Set the CPU-bound threshold T_H in nsecs.
    pub fn t_h_ns(mut self, v: u64) -> Self {
        self.t_h_ns = Some(v);
        self
    }

    /// Set the EMA decay half-life in nsecs.
    pub fn ema_half_life_ns(mut self, v: u64) -> Self {
        self.ema_half_life_ns = Some(v);
        self
    }

    /// Set the global aging period in nsecs.
    pub fn aging_period_ns(mut self, v: u64) -> Self {
        self.aging_period_ns = Some(v);
        self
    }

    /// Set the short-sleep boost window in nsecs.
    pub fn short_sleep_ns(mut self, v: u64) -> Self {
        self.short_sleep_ns = Some(v);
        self
    }

    /// Set the per-task short-sleep boost rate limit in nsecs.
    pub fn short_sleep_rate_limit_ns(mut self, v: u64) -> Self {
        self.short_sleep_rate_limit_ns = Some(v);
        self
    }

    /// Set the sleep counted as "short" for the wake_cnt hysteresis in nsecs.
    pub fn hysteresis_sleep_ns(mut self, v: u64) -> Self {
        self.hysteresis_sleep_ns = Some(v);
        self
    }

    /// Set the long-sleep gauge-collapse window in nsecs.
    pub fn long_sleep_ns(mut self, v: u64) -> Self {
        self.long_sleep_ns = Some(v);
        self
    }

    /// Set the Q1 dispatch quota.
    pub fn q1_quota(mut self, v: u32) -> Self {
        self.q1_quota = Some(v);
        self
    }

    /// Set the Q2 dispatch quota.
    pub fn q2_quota(mut self, v: u32) -> Self {
        self.q2_quota = Some(v);
        self
    }

    /// Set the dispatch-loop bound.
    pub fn dispatch_max_batch(mut self, v: u32) -> Self {
        self.dispatch_max_batch = Some(v);
        self
    }

    /// Assemble and validate the configuration.
    ///
    /// Returns an error if any invariant is violated; the resulting
    /// `Config` is guaranteed valid.
    pub fn build(self) -> Result<Config> {
        let defaults = Config::default();
        let cfg = Config {
            q1_slice_ns: self.q1_slice_ns.unwrap_or(defaults.q1_slice_ns),
            q2_slice_ns: self.q2_slice_ns.unwrap_or(defaults.q2_slice_ns),
            q3_slice_ns: self.q3_slice_ns.unwrap_or(defaults.q3_slice_ns),
            budget_max_ns: self.budget_max_ns.unwrap_or(defaults.budget_max_ns),
            alpha: self.alpha.unwrap_or(defaults.alpha),
            t_l_ns: self.t_l_ns.unwrap_or(defaults.t_l_ns),
            t_h_ns: self.t_h_ns.unwrap_or(defaults.t_h_ns),
            ema_half_life_ns: self.ema_half_life_ns.unwrap_or(defaults.ema_half_life_ns),
            aging_period_ns: self.aging_period_ns.unwrap_or(defaults.aging_period_ns),
            short_sleep_ns: self.short_sleep_ns.unwrap_or(defaults.short_sleep_ns),
            short_sleep_rate_limit_ns: self
                .short_sleep_rate_limit_ns
                .unwrap_or(defaults.short_sleep_rate_limit_ns),
            hysteresis_sleep_ns: self
                .hysteresis_sleep_ns
                .unwrap_or(defaults.hysteresis_sleep_ns),
            long_sleep_ns: self.long_sleep_ns.unwrap_or(defaults.long_sleep_ns),
            q1_quota: self.q1_quota.unwrap_or(defaults.q1_quota),
            q2_quota: self.q2_quota.unwrap_or(defaults.q2_quota),
            dispatch_max_batch: self
                .dispatch_max_batch
                .unwrap_or(defaults.dispatch_max_batch),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_intf_h() {
        /*
         * Cross-check the Config defaults against the bindgen-generated
         * enum mlfq_consts constants, the way topology.rs cross-checks its
         * constants: intf.h is the single source of truth, and this test
         * pins the binding so a default that diverges from the BPF side
         * (or a constant that stops existing) fails here.
         */
        use crate::bpf_intf::{
            mlfq_consts_MLFQ_AGING_PERIOD_NS, mlfq_consts_MLFQ_ALPHA,
            mlfq_consts_MLFQ_BUDGET_MAX_NS, mlfq_consts_MLFQ_DISPATCH_MAX_BATCH,
            mlfq_consts_MLFQ_EMA_HALF_LIFE_NS, mlfq_consts_MLFQ_HYSTERESIS_SLEEP_NS,
            mlfq_consts_MLFQ_LONG_SLEEP_NS, mlfq_consts_MLFQ_Q1_QUOTA,
            mlfq_consts_MLFQ_Q1_SLICE_NS, mlfq_consts_MLFQ_Q2_QUOTA, mlfq_consts_MLFQ_Q2_SLICE_NS,
            mlfq_consts_MLFQ_Q3_SLICE_NS, mlfq_consts_MLFQ_SHORT_SLEEP_NS,
            mlfq_consts_MLFQ_SHORT_SLEEP_RATE_LIMIT_NS, mlfq_consts_MLFQ_T_H_NS,
            mlfq_consts_MLFQ_T_L_NS,
        };

        let cfg = Config::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.q1_slice_ns, mlfq_consts_MLFQ_Q1_SLICE_NS as u64);
        assert_eq!(cfg.q2_slice_ns, mlfq_consts_MLFQ_Q2_SLICE_NS as u64);
        assert_eq!(cfg.q3_slice_ns, mlfq_consts_MLFQ_Q3_SLICE_NS as u64);
        assert_eq!(cfg.budget_max_ns, mlfq_consts_MLFQ_BUDGET_MAX_NS as u64);
        assert_eq!(cfg.alpha, mlfq_consts_MLFQ_ALPHA as u64);
        assert_eq!(cfg.t_l_ns, mlfq_consts_MLFQ_T_L_NS as u64);
        assert_eq!(cfg.t_h_ns, mlfq_consts_MLFQ_T_H_NS as u64);
        assert_eq!(
            cfg.ema_half_life_ns,
            mlfq_consts_MLFQ_EMA_HALF_LIFE_NS as u64
        );
        assert_eq!(cfg.aging_period_ns, mlfq_consts_MLFQ_AGING_PERIOD_NS as u64);
        assert_eq!(cfg.short_sleep_ns, mlfq_consts_MLFQ_SHORT_SLEEP_NS as u64);
        assert_eq!(
            cfg.short_sleep_rate_limit_ns,
            mlfq_consts_MLFQ_SHORT_SLEEP_RATE_LIMIT_NS as u64
        );
        assert_eq!(
            cfg.hysteresis_sleep_ns,
            mlfq_consts_MLFQ_HYSTERESIS_SLEEP_NS as u64
        );
        assert_eq!(cfg.long_sleep_ns, mlfq_consts_MLFQ_LONG_SLEEP_NS as u64);
        assert_eq!(cfg.q1_quota, mlfq_consts_MLFQ_Q1_QUOTA);
        assert_eq!(cfg.q2_quota, mlfq_consts_MLFQ_Q2_QUOTA);
        assert_eq!(cfg.dispatch_max_batch, mlfq_consts_MLFQ_DISPATCH_MAX_BATCH);
    }

    #[test]
    fn builder_defaults_equal_config_defaults() {
        let cfg = ConfigBuilder::default().build().unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn builder_overrides_individual_fields() {
        let cfg = ConfigBuilder::default()
            .q1_slice_ns(500_000)
            .build()
            .unwrap();
        assert_eq!(cfg.q1_slice_ns, 500_000);
        assert_eq!(cfg.q2_slice_ns, Config::default().q2_slice_ns);
    }

    #[test]
    fn rejects_zero_slices() {
        assert!(ConfigBuilder::default().q1_slice_ns(0).build().is_err());
        assert!(ConfigBuilder::default().q2_slice_ns(0).build().is_err());
        assert!(ConfigBuilder::default().q3_slice_ns(0).build().is_err());
    }

    #[test]
    fn rejects_t_l_at_or_above_t_h() {
        assert!(ConfigBuilder::default().t_l_ns(2_000_000).build().is_err());
        assert!(ConfigBuilder::default().t_l_ns(3_000_000).build().is_err());
    }

    #[test]
    fn rejects_t_h_at_or_above_budget_max() {
        assert!(ConfigBuilder::default().t_h_ns(6_000_000).build().is_err());
        assert!(ConfigBuilder::default().t_h_ns(7_000_000).build().is_err());
    }

    #[test]
    fn rejects_zero_quotas() {
        assert!(ConfigBuilder::default().q1_quota(0).build().is_err());
        assert!(ConfigBuilder::default().q2_quota(0).build().is_err());
        assert!(ConfigBuilder::default()
            .dispatch_max_batch(0)
            .build()
            .is_err());
    }

    #[test]
    fn rejects_quotas_consuming_the_batch() {
        // Q1+Q2 must leave headroom for Q3 within dispatch_max_batch.
        let cfg = ConfigBuilder::default()
            .q1_quota(16)
            .q2_quota(16)
            .dispatch_max_batch(32)
            .build();
        assert!(cfg.is_err());
    }

    #[test]
    fn rejects_dispatch_batch_above_ops_bound() {
        // The rodata batch must never exceed the ops-table bound
        // (.dispatch_max_batch = MLFQ_DISPATCH_MAX_BATCH in main.bpf.c).
        let cfg = ConfigBuilder::default()
            .dispatch_max_batch(crate::bpf_intf::mlfq_consts_MLFQ_DISPATCH_MAX_BATCH + 1)
            .build();
        assert!(cfg.is_err());
        // At the ops-table bound itself the config is valid.
        let cfg = ConfigBuilder::default()
            .dispatch_max_batch(crate::bpf_intf::mlfq_consts_MLFQ_DISPATCH_MAX_BATCH)
            .build();
        assert!(cfg.is_ok());
    }

    #[test]
    fn rejects_zero_aging_period() {
        assert!(ConfigBuilder::default().aging_period_ns(0).build().is_err());
    }

    #[test]
    fn describe_is_stable() {
        let cfg = Config::default();
        let s = cfg.describe();
        assert!(s.contains("slices: Q1=1000us Q2=2000us Q3=4000us"));
        assert!(s.contains("T_L=250us, T_H=2000us"));
        assert!(s.contains("aging_period=1s"));
        assert!(s.contains("quotas: Q1=4 Q2=8 max_batch=32"));
    }
}
