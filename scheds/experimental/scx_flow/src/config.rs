// SPDX-License-Identifier: GPL-2.0
/*
 * Validated scheduling constants
 *
 * Holds the validated scheduling constants with defaults that match the
 * shared BPF header. Validation keeps bad values from reaching the BPF
 * object. The slice is fixed at 1ms with no knob.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use crate::flow::DISPATCH_BATCH;
use crate::flow::EST_MAX_NS;
use crate::flow::EST_MIN_NS;
use crate::flow::SLICE_NS;
use crate::flow::SLOT_BUDGET;
use crate::flow::SLOT_D;
use anyhow::Result;
use anyhow::bail;

/* Default fixed slice in nanos. */
const DEF_SLICE_NS: u64 = SLICE_NS;
/* Default tasks moved in one dispatch pass. */
const DEF_BATCH: u32 = DISPATCH_BATCH;
/* Default tasks moved by one slot trip. */
const DEF_SLOT_D: u32 = SLOT_D;
/* Default tasks moved by one slot dispatch pass. */
const DEF_SLOT_BUDGET: u32 = SLOT_BUDGET;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Fixed slice in nanos. */
    pub slice_ns: u64,
    /* Fixed tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
    /* Fixed tasks moved by one slot trip. */
    pub slot_d: u32,
    /* Fixed tasks moved by one slot dispatch pass. */
    pub slot_budget: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            slice_ns: DEF_SLICE_NS,
            dispatch_batch: DEF_BATCH,
            slot_d: DEF_SLOT_D,
            slot_budget: DEF_SLOT_BUDGET,
        }
    }
}

impl Config {
    /*
     * Validate the constants against the bounds the BPF
     * side relies on. An invalid value is a programming
     * fault, not a runtime state. The slice stays fixed
     * at 1ms and the batch stays fixed at 32, so one
     * slice pairs with one budget with no knob. The slot
     * trip stays fixed at 4 and the slot budget stays
     * fixed at 32, so one dispatch owns four trips with
     * no knob.
     */
    pub fn validate(&self) -> Result<()> {
        if self.slice_ns != SLICE_NS {
            bail!("slice bad {}", self.slice_ns);
        }
        if self.slice_ns != 1_000_000 {
            bail!("slice bad {}", self.slice_ns);
        }
        if EST_MIN_NS != 1 {
            bail!("est floor bad {}", EST_MIN_NS);
        }
        if EST_MAX_NS != 1_000_000_000 {
            bail!("est ceiling bad {}", EST_MAX_NS);
        }
        if self.dispatch_batch != DISPATCH_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch != 32 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.slot_d != SLOT_D {
            bail!("slot trip bad {}", self.slot_d);
        }
        if self.slot_d != 4 {
            bail!("slot trip bad {}", self.slot_d);
        }
        if self.slot_budget != SLOT_BUDGET {
            bail!("slot budget bad {}", self.slot_budget);
        }
        if self.slot_budget != 32 {
            bail!("slot budget bad {}", self.slot_budget);
        }
        Ok(())
    }

    /*
     * One line summary of the constants for the start
     * log. Values print in microseconds for brevity.
     */
    pub fn describe(&self) -> String {
        format!(
            "slice={}us batch={}",
            self.slice_ns / 1000,
            self.dispatch_batch,
        )
    }
}

/*
 * Builder for Config used only by tests. Production
 * uses Config default directly. Each setter is optional
 * and missing fields fall back to the defaults.
 */
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    slice_ns: Option<u64>,
    dispatch_batch: Option<u32>,
    slot_d: Option<u32>,
    slot_budget: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /* Set the fixed slice. */
    pub fn slice_ns(mut self, v: u64) -> Self {
        self.slice_ns = Some(v);
        self
    }
    /* Set the fixed dispatch batch. Only 32 passes. */
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /* Set the fixed slot trip. Only 4 passes. */
    pub fn slot_d(mut self, v: u32) -> Self {
        self.slot_d = Some(v);
        self
    }
    /* Set the fixed slot budget. Only 32 passes. */
    pub fn slot_budget(mut self, v: u32) -> Self {
        self.slot_budget = Some(v);
        self
    }
    /* Assemble and validate the result. */
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let slice = self.slice_ns.unwrap_or(d.slice_ns);
        let batch = self.dispatch_batch.unwrap_or(d.dispatch_batch);
        let slot_d = self.slot_d.unwrap_or(d.slot_d);
        let slot_budget = self.slot_budget.unwrap_or(d.slot_budget);
        let cfg = Config {
            slice_ns: slice,
            dispatch_batch: batch,
            slot_d,
            slot_budget,
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
    fn builder_explicit_fixed_matches_default() {
        let cfg = ConfigBuilder::default().dispatch_batch(32).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.dispatch_batch, 32);
        assert_eq!(cfg.slice_ns, Config::default().slice_ns);
    }

    #[test]
    fn slot_consts_are_fixed() {
        assert_eq!(Config::default().slot_d, 4);
        assert_eq!(Config::default().slot_budget, 32);
        assert_eq!(Config::default().slot_d, crate::flow_slot::SLOT_D);
        assert_eq!(Config::default().slot_budget, crate::flow_slot::SLOT_BUDGET);
    }

    #[test]
    fn rejects_non_fixed_slot() {
        for bad in [0, 1, 3, 5, 8, 32] {
            let got = ConfigBuilder::default().slot_d(bad).build();
            assert!(got.is_err(), "slot trip {bad} must fail");
        }
        let ok = ConfigBuilder::default().slot_d(4).build();
        assert!(ok.is_ok());
        for bad in [0, 4, 16, 31, 33, 64] {
            let got = ConfigBuilder::default().slot_budget(bad).build();
            assert!(got.is_err(), "slot budget {bad} must fail");
        }
        let ok = ConfigBuilder::default().slot_budget(32).build();
        assert!(ok.is_ok());
    }

    #[test]
    fn slice_matches_flow() {
        assert_eq!(Config::default().slice_ns, crate::flow_slice::SLICE_NS);
        assert_eq!(crate::flow_slice::SLICE_NS, 1_000_000);
    }

    #[test]
    fn rejects_bad_slice() {
        let a = ConfigBuilder::default().slice_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().slice_ns(8_000_000).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default().slice_ns(20_000_000).build();
        assert!(c.is_err());
    }

    #[test]
    fn rejects_non_fixed_batch() {
        for bad in [0, 1, 16, 31, 33, 64] {
            let got = ConfigBuilder::default().dispatch_batch(bad).build();
            assert!(got.is_err(), "batch {bad} must fail");
        }
        let ok = ConfigBuilder::default().dispatch_batch(32).build();
        assert!(ok.is_ok());
    }

    #[test]
    /*
     * Summary holds the fixed slice at 1000us with no knob.
     * Slice plus batch stay stable for the start log.
     */
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("slice=1000us"));
        assert!(s.contains("batch=32"));
    }

    #[test]
    /*
     * Defaults match the shared header with the fixed slice at 1ms.
     * Kick coalesce stays at 50us with no slice use, see flow_select.
     */
    fn defaults_match_intf_h() {
        assert_eq!(
            Config::default().slice_ns,
            crate::bpf_intf::flow_consts_FLOW_SLICE_NS as u64
        );
        assert_eq!(crate::flow_slice::SLICE_NS, 1_000_000);
        assert_eq!(
            crate::flow_select::KICK_COALESCE_NS,
            crate::bpf_intf::flow_consts_FLOW_KICK_COALESCE_NS as u64
        );
        assert_eq!(crate::flow_select::KICK_COALESCE_NS, 50_000);
    }
}
