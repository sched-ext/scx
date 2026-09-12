/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Validated scheduling constants for the flow scheduler.
 * The defaults match the shared BPF header. Validation
 * keeps bad values from reaching the BPF object.
 * The slice is fixed at 1ms with no knob.
 */
use crate::flow::DISPATCH_BATCH;
use crate::flow::EST_MAX_NS;
use crate::flow::EST_MIN_NS;
use crate::flow::SLICE_NS;
use anyhow::Result;
use anyhow::bail;

/* Default fixed slice in nanos. */
const DEF_SLICE_NS: u64 = SLICE_NS;
/* Default tasks moved in one dispatch pass. */
const DEF_BATCH: u32 = DISPATCH_BATCH;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Fixed slice in nanos. */
    pub slice_ns: u64,
    /* Fixed tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            slice_ns: DEF_SLICE_NS,
            dispatch_batch: DEF_BATCH,
        }
    }
}

impl Config {
    /*
     * Validate the constants against the bounds the BPF
     * side relies on. An invalid value is a programming
     * fault, not a runtime state. The slice stays fixed
     * at 1ms and the batch stays fixed at 32, so one
     * slice pairs with one budget with no knob.
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
    /* Assemble and validate the result. */
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let slice = self.slice_ns.unwrap_or(d.slice_ns);
        let batch = self.dispatch_batch.unwrap_or(d.dispatch_batch);
        let cfg = Config {
            slice_ns: slice,
            dispatch_batch: batch,
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
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("slice=1000us"));
        assert!(s.contains("batch=32"));
    }
}
