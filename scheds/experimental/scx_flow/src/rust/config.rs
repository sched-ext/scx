// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults that match intf.h.

use crate::flow::ADMIT_PERMILLE;
use crate::flow::CAP_BASE;
use crate::flow::HINT_MAX;
use crate::flow::PERIOD_NS;
use crate::flow::QUANTUM_NS;
use crate::flow::WEIGHT_BASE;
use crate::flow::WEIGHT_MAX;
use crate::flow::WEIGHT_MIN;
use anyhow::Result;
use anyhow::bail;

/// Default fixed slice in nanos.
const DEF_QUANTUM_NS: u64 = QUANTUM_NS;
/// Default dispatch batch for the ops table with no knob. Mirrors
/// FLOW_DISPATCH_MAX_BATCH in intf.h, so the ops table holds every
/// pass with room and no shared math.
const DEF_BATCH: u32 = 16;

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Fixed slice in nanos. Always 2ms with no knob.
    pub quantum_ns: u64,
    /// Dispatch batch for the ops table. Always 16 with no knob.
    pub dispatch_batch: u32,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            quantum_ns: DEF_QUANTUM_NS,
            dispatch_batch: DEF_BATCH,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds the BPF side relies on.
    /// An invalid value is a programming fault, not a runtime state.
    /// The slice stays fixed at 2ms with base weight 128 in range
    /// 1 to 16384. The period stays at 16ms. The batch stays fixed
    /// at 16. Admission holds use under 950 per mille with base capacity
    /// 1024. Queues hold 512 local plus 8 node plus machine plus
    /// overflow with ids in the 0x5100 region. Hints hold 4096 flat
    /// rows with no timer wait.
    pub fn validate(&self) -> Result<()> {
        if self.quantum_ns != QUANTUM_NS {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if self.quantum_ns != 2_000_000 {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 128 || WEIGHT_MAX != 16_384 {
            bail!("weight bounds bad");
        }
        if PERIOD_NS != 16_000_000 {
            bail!("period bounds bad");
        }
        if self.dispatch_batch != DEF_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch != 16 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if ADMIT_PERMILLE != 950 {
            bail!("admission bound bad");
        }
        if CAP_BASE != 1024 {
            bail!("capacity base bad");
        }
        if HINT_MAX != 4096 {
            bail!("hint bound bad");
        }
        Ok(())
    }

    /// One line summary of the constants for the start log.
    /// Values print in microseconds for brevity.
    pub fn describe(&self) -> String {
        format!(
            "quantum={}us batch={}",
            self.quantum_ns / 1000,
            self.dispatch_batch,
        )
    }
}

/// Builder for Config used only by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    quantum_ns: Option<u64>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the fixed slice.
    pub fn quantum_ns(mut self, v: u64) -> Self {
        self.quantum_ns = Some(v);
        self
    }
    /// Set the fixed dispatch batch. Only 16 passes.
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /// Assemble and validate the result.
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let cfg = Config {
            quantum_ns: self.quantum_ns.unwrap_or(d.quantum_ns),
            dispatch_batch: self.dispatch_batch.unwrap_or(d.dispatch_batch),
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
        let b = ConfigBuilder::default().quantum_ns(1_000_000).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_non_fixed_batch() {
        for bad in [0, 1, 8, 15, 17, 32] {
            let got = ConfigBuilder::default().dispatch_batch(bad).build();
            assert!(got.is_err(), "batch {bad} must fail");
        }
        let ok = ConfigBuilder::default().dispatch_batch(16).build();
        assert!(ok.is_ok());
    }

    #[test]
    /// Summary holds the fixed slice with no knob.
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("quantum=2000us"));
        assert!(s.contains("batch=16"));
    }

    #[test]
    /// Defaults match the shared header with local plus shared queues.
    fn defaults_match_intf_h() {
        assert_eq!(
            DEF_BATCH,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH
        );
        assert_eq!(DEF_BATCH, 16);
        assert_eq!(
            Config::default().quantum_ns,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 522);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x5A01);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MACHINE as u64, 0x5A00);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_LOCAL_BASE as u64, 0x5100);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_NODE_BASE as u64, 0x5900);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64,
            crate::flow_cgrp::HINT_MAX
        );
    }
}
