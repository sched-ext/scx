// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Per-layer IRQ protection.
//!
//! Snapshots `/proc/irq/<N>/smp_affinity` for every numeric IRQ at startup
//! and rewrites each mask with the union of CPUs owned by `irq_protect`
//! layers cleared. Three regimes:
//!
//! 1. **Normal** — some CPUs are unprotected. Each IRQ's desired mask is
//!    `orig & ~protected`. If that single IRQ's desired mask is empty
//!    (its original affinity is fully inside the protected set), we
//!    *spill* to the system-wide unprotected set rather than leave the
//!    IRQ pinned inside a protected layer.
//! 2. **Spread** — *every* online CPU is protected. There is no "safe"
//!    place to put IRQs, so we abandon protection and instead spread
//!    each IRQ to a single CPU round-robin across all CPUs (better load
//!    distribution than leaving the kernel's original concentration).
//! 3. **Skipped** — IRQs the kernel rejects (managed/affinity-locked)
//!    are recorded after the first write failure and never retried.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::Result;
use tracing::debug;
use tracing::info;
use tracing::warn;

use scx_utils::Cpumask;

/// Abstraction over the destination for IRQ affinity writes. The
/// production impl writes `/proc/irq/<N>/smp_affinity`; tests use an
/// in-memory recorder.
pub trait IrqSink {
    fn write(&mut self, irq: usize, mask: &Cpumask) -> io::Result<()>;
}

pub struct ProcIrqSink;

impl IrqSink for ProcIrqSink {
    fn write(&mut self, irq: usize, mask: &Cpumask) -> io::Result<()> {
        let path = format!("/proc/irq/{irq}/smp_affinity");
        fs::write(path, format!("{mask:#x}"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    Spread,
    All,
}

/// Selects what `apply` does when one or more IRQs cannot stay on their
/// original CPUs (because those CPUs are protected).
///
/// * `Spread` (default) — preserves per-IRQ home affinity when possible.
///   Only when *every* CPU is protected does it fall back to pinning each
///   IRQ to a single CPU round-robin.
/// * `All` — gives every IRQ the same mask: the system-wide *unprotected*
///   set (or all CPUs when nothing is unprotected). Simpler, fairer load
///   distribution, but discards each IRQ's original locality.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub enum IrqFallback {
    #[default]
    Spread,
    All,
}

pub struct IrqProtector<S: IrqSink = ProcIrqSink> {
    original: BTreeMap<usize, Cpumask>,
    last_applied: BTreeMap<usize, Cpumask>,
    skipped: BTreeSet<usize>,
    /// IRQs we've already logged as having been spilled (so we only warn once).
    spill_warned: BTreeSet<usize>,
    /// Tracks the last regime we ran in, for one-shot transition logging.
    last_mode: Option<Mode>,
    fallback: IrqFallback,
    sink: S,
}

impl IrqProtector<ProcIrqSink> {
    pub fn new(fallback: IrqFallback) -> Result<Self> {
        let original = snapshot_proc_irqs()?;
        debug!(
            "irq_protect: snapshotted {} IRQ affinity mask(s)",
            original.len()
        );
        Ok(Self::with_state(original, fallback, ProcIrqSink))
    }
}

impl<S: IrqSink> IrqProtector<S> {
    pub fn with_snapshot(
        original: BTreeMap<usize, Cpumask>,
        fallback: IrqFallback,
        sink: S,
    ) -> Self {
        Self::with_state(original, fallback, sink)
    }

    fn with_state(original: BTreeMap<usize, Cpumask>, fallback: IrqFallback, sink: S) -> Self {
        Self {
            original,
            last_applied: BTreeMap::new(),
            skipped: BTreeSet::new(),
            spill_warned: BTreeSet::new(),
            last_mode: None,
            fallback,
            sink,
        }
    }

    /// Rewrite snapshotted IRQ affinities given the union of layer-protected
    /// CPUs and the set of all CPUs visible to the scheduler. Returns the
    /// number of IRQs whose mask changed this call.
    pub fn apply(&mut self, protected: &Cpumask, all_cpus: &Cpumask) -> usize {
        let unprotected = all_cpus.and(&protected.not());
        let fully_protected = unprotected.weight() == 0 && all_cpus.weight() > 0;

        let mode = match (self.fallback, fully_protected) {
            (IrqFallback::All, _) => Mode::All,
            (IrqFallback::Spread, true) => Mode::Spread,
            (IrqFallback::Spread, false) => Mode::Normal,
        };

        if self.last_mode != Some(mode) {
            match mode {
                Mode::Spread => warn!(
                    "irq_protect: every CPU is protected ({} CPU(s)); \
                     spreading IRQs evenly across all CPUs",
                    all_cpus.weight(),
                ),
                Mode::All => info!(
                    "irq_protect: fallback=all; assigning every IRQ the unprotected \
                     set ({} CPU(s))",
                    if fully_protected {
                        all_cpus.weight()
                    } else {
                        unprotected.weight()
                    },
                ),
                Mode::Normal => {
                    if self.last_mode.is_some() {
                        info!(
                            "irq_protect: returning to normal mode ({} unprotected CPU(s))",
                            unprotected.weight()
                        );
                    }
                }
            }
            self.last_mode = Some(mode);
        }

        match mode {
            Mode::Spread => self.apply_spread(all_cpus),
            Mode::All => {
                // In All mode every IRQ shares the same desired mask:
                // unprotected if any CPU is free, otherwise the full system mask.
                let desired = if fully_protected {
                    all_cpus.clone()
                } else {
                    unprotected.clone()
                };
                self.apply_uniform(&desired)
            }
            Mode::Normal => self.apply_normal(protected, &unprotected),
        }
    }

    fn apply_uniform(&mut self, desired: &Cpumask) -> usize {
        if desired.weight() == 0 {
            return 0;
        }
        let mut changes = 0usize;
        let mut newly_skipped = Vec::new();
        let irqs: Vec<usize> = self
            .original
            .keys()
            .copied()
            .filter(|i| !self.skipped.contains(i))
            .collect();
        for irq in irqs {
            if let Some(prev) = self.last_applied.get(&irq) {
                if prev == desired {
                    continue;
                }
            }
            match self.sink.write(irq, desired) {
                Ok(()) => {
                    self.last_applied.insert(irq, desired.clone());
                    changes += 1;
                }
                Err(e) => {
                    debug!("irq_protect: irq {irq} write failed ({e}); marking skipped");
                    newly_skipped.push(irq);
                }
            }
        }
        for irq in newly_skipped {
            self.skipped.insert(irq);
        }
        changes
    }

    fn apply_normal(&mut self, protected: &Cpumask, unprotected: &Cpumask) -> usize {
        let allowed = protected.not();
        let mut changes = 0usize;
        let mut newly_skipped = Vec::new();
        let mut newly_spilled = Vec::new();

        for (&irq, orig) in self.original.iter() {
            if self.skipped.contains(&irq) {
                continue;
            }
            let direct = orig.and(&allowed);
            let (desired, spilled) = if direct.weight() > 0 {
                (direct, false)
            } else {
                (unprotected.clone(), true)
            };
            if desired.weight() == 0 {
                // Can't happen in Mode::Normal (unprotected is non-empty), but
                // guard anyway so we never write an empty mask.
                continue;
            }
            if let Some(prev) = self.last_applied.get(&irq) {
                if prev == &desired {
                    continue;
                }
            }
            match self.sink.write(irq, &desired) {
                Ok(()) => {
                    self.last_applied.insert(irq, desired);
                    changes += 1;
                    if spilled && !self.spill_warned.contains(&irq) {
                        newly_spilled.push((irq, orig.clone()));
                    }
                }
                Err(e) => {
                    debug!("irq_protect: irq {irq} write failed ({e}); marking skipped");
                    newly_skipped.push(irq);
                }
            }
        }

        for irq in newly_skipped {
            self.skipped.insert(irq);
        }
        for (irq, orig) in newly_spilled {
            warn!(
                "irq_protect: irq {irq} home affinity {orig:#x} is fully covered by \
                 protected layer(s); spilled to system unprotected CPUs"
            );
            self.spill_warned.insert(irq);
        }
        changes
    }

    fn apply_spread(&mut self, all_cpus: &Cpumask) -> usize {
        let cpus: Vec<usize> = all_cpus.iter().collect();
        if cpus.is_empty() {
            return 0;
        }
        let mut changes = 0usize;
        let mut newly_skipped = Vec::new();
        let irqs: Vec<usize> = self
            .original
            .keys()
            .copied()
            .filter(|i| !self.skipped.contains(i))
            .collect();
        for (idx, irq) in irqs.iter().enumerate() {
            let cpu = cpus[idx % cpus.len()];
            let mut desired = Cpumask::new();
            // set_cpu only errors for an out-of-range CPU; cpu came from
            // all_cpus.iter() so it's in range.
            let _ = desired.set_cpu(cpu);
            if let Some(prev) = self.last_applied.get(irq) {
                if prev == &desired {
                    continue;
                }
            }
            match self.sink.write(*irq, &desired) {
                Ok(()) => {
                    self.last_applied.insert(*irq, desired);
                    changes += 1;
                }
                Err(e) => {
                    debug!("irq_protect: irq {irq} write failed ({e}); marking skipped");
                    newly_skipped.push(*irq);
                }
            }
        }
        for irq in newly_skipped {
            self.skipped.insert(irq);
        }
        changes
    }

    /// Restore every snapshotted IRQ to its original affinity.
    pub fn restore(&mut self) {
        let mut failed = 0usize;
        let restores: Vec<(usize, Cpumask)> = self
            .original
            .iter()
            .map(|(&irq, mask)| (irq, mask.clone()))
            .collect();
        for (irq, orig) in restores {
            if let Err(e) = self.sink.write(irq, &orig) {
                debug!("irq_protect: failed to restore irq {irq}: {e}");
                failed += 1;
            }
        }
        if failed > 0 {
            warn!("irq_protect: {failed} IRQ(s) could not be restored");
        }
    }
}

fn snapshot_proc_irqs() -> Result<BTreeMap<usize, Cpumask>> {
    let mut original = BTreeMap::new();
    for entry in fs::read_dir("/proc/irq")? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let irq: usize = match name.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let affinity_path = format!("/proc/irq/{irq}/smp_affinity");
        let raw = match fs::read_to_string(Path::new(&affinity_path)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cleaned: String = raw.chars().filter(|c| *c != ',' && *c != '\n').collect();
        if cleaned.is_empty() {
            continue;
        }
        match Cpumask::from_str(&cleaned) {
            Ok(mask) => {
                original.insert(irq, mask);
            }
            Err(e) => {
                debug!("irq_protect: skipping irq {irq}: bad smp_affinity ({e})");
            }
        }
    }
    Ok(original)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scx_utils::set_cpumask_test_width;
    use std::io;

    struct RecordingSink {
        writes: Vec<(usize, Cpumask)>,
        fail_for: BTreeSet<usize>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                writes: Vec::new(),
                fail_for: BTreeSet::new(),
            }
        }

        fn fail(mut self, irq: usize) -> Self {
            self.fail_for.insert(irq);
            self
        }

        fn last_mask_for(&self, irq: usize) -> Option<&Cpumask> {
            self.writes
                .iter()
                .rev()
                .find(|(i, _)| *i == irq)
                .map(|(_, m)| m)
        }

        fn write_count(&self, irq: usize) -> usize {
            self.writes.iter().filter(|(i, _)| *i == irq).count()
        }
    }

    impl IrqSink for RecordingSink {
        fn write(&mut self, irq: usize, mask: &Cpumask) -> io::Result<()> {
            if self.fail_for.contains(&irq) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "managed"));
            }
            self.writes.push((irq, mask.clone()));
            Ok(())
        }
    }

    fn mask(hex: &str) -> Cpumask {
        set_cpumask_test_width(16);
        Cpumask::from_str(hex).unwrap()
    }

    #[test]
    fn apply_normal_strips_protected_cpus() {
        // IRQ 1 originally on CPU 0 only; protecting CPU 0 forces a spill
        // because direct strip is empty.
        // IRQ 2 covers CPUs 0-1; protecting CPU 0 leaves CPU 1.
        let mut snap = BTreeMap::new();
        snap.insert(1, mask("0x1"));
        snap.insert(2, mask("0x3"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::Spread, sink);
        // all_cpus = 0..4, protected = CPU 0.
        let changes = p.apply(&mask("0x1"), &mask("0xf"));

        assert_eq!(changes, 2);
        assert_eq!(
            p.sink.last_mask_for(1).cloned(),
            Some(mask("0xe")),
            "IRQ 1 home is fully protected -> spilled to unprotected (CPUs 1-3)"
        );
        assert_eq!(
            p.sink.last_mask_for(2).cloned(),
            Some(mask("0x2")),
            "IRQ 2 keeps its CPU 1"
        );
        assert!(p.spill_warned.contains(&1));
        assert!(!p.spill_warned.contains(&2));
    }

    #[test]
    fn managed_irq_is_skipped_after_first_failure() {
        let mut snap = BTreeMap::new();
        snap.insert(5, mask("0xff"));

        let sink = RecordingSink::new().fail(5);
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::Spread, sink);

        let c1 = p.apply(&mask("0x1"), &mask("0xff"));
        assert_eq!(c1, 0);
        assert!(p.skipped.contains(&5));
        assert_eq!(p.sink.write_count(5), 0);

        let _ = p.apply(&mask("0x2"), &mask("0xff"));
        assert_eq!(p.sink.write_count(5), 0, "no retry on subsequent apply");
    }

    #[test]
    fn redundant_write_is_elided() {
        let mut snap = BTreeMap::new();
        snap.insert(7, mask("0xff"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::Spread, sink);

        p.apply(&mask("0x1"), &mask("0xff"));
        p.apply(&mask("0x1"), &mask("0xff"));
        p.apply(&mask("0x1"), &mask("0xff"));

        assert_eq!(p.sink.write_count(7), 1);
    }

    #[test]
    fn restore_writes_originals_for_every_snapshotted_irq() {
        let mut snap = BTreeMap::new();
        snap.insert(1, mask("0xf"));
        snap.insert(2, mask("0xff00"));
        snap.insert(3, mask("0x10"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap.clone(), IrqFallback::Spread, sink);

        p.apply(&mask("0xf"), &mask("0xffff"));
        let pre_restore = p.sink.writes.len();
        p.restore();

        let restored = &p.sink.writes[pre_restore..];
        assert_eq!(restored.len(), 3);
        for (irq, original) in snap.iter() {
            let last = restored
                .iter()
                .rev()
                .find(|(i, _)| i == irq)
                .map(|(_, m)| m)
                .expect("each irq must be restored");
            assert_eq!(last, original);
        }
    }

    #[test]
    fn spread_mode_distributes_irqs_round_robin_when_all_protected() {
        // 4 IRQs, 4 CPUs, every CPU protected -> spread mode pins each
        // IRQ to one CPU, rotating through all_cpus in order.
        let mut snap = BTreeMap::new();
        snap.insert(10, mask("0xf"));
        snap.insert(11, mask("0xf"));
        snap.insert(12, mask("0xf"));
        snap.insert(13, mask("0xf"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::Spread, sink);
        let changes = p.apply(&mask("0xf"), &mask("0xf"));

        assert_eq!(changes, 4);
        assert_eq!(p.last_mode, Some(Mode::Spread));
        // Sorted IRQ order 10,11,12,13 round-robin onto CPUs 0,1,2,3.
        assert_eq!(p.sink.last_mask_for(10).cloned(), Some(mask("0x1")));
        assert_eq!(p.sink.last_mask_for(11).cloned(), Some(mask("0x2")));
        assert_eq!(p.sink.last_mask_for(12).cloned(), Some(mask("0x4")));
        assert_eq!(p.sink.last_mask_for(13).cloned(), Some(mask("0x8")));
    }

    #[test]
    fn spread_mode_wraps_when_more_irqs_than_cpus() {
        let mut snap = BTreeMap::new();
        for irq in 20..25 {
            snap.insert(irq, mask("0x3"));
        }
        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::Spread, sink);
        p.apply(&mask("0x3"), &mask("0x3"));

        // 5 IRQs, 2 CPUs -> 20:cpu0, 21:cpu1, 22:cpu0, 23:cpu1, 24:cpu0.
        assert_eq!(p.sink.last_mask_for(20).cloned(), Some(mask("0x1")));
        assert_eq!(p.sink.last_mask_for(21).cloned(), Some(mask("0x2")));
        assert_eq!(p.sink.last_mask_for(22).cloned(), Some(mask("0x1")));
        assert_eq!(p.sink.last_mask_for(23).cloned(), Some(mask("0x2")));
        assert_eq!(p.sink.last_mask_for(24).cloned(), Some(mask("0x1")));
    }

    #[test]
    fn all_mode_assigns_unprotected_set_to_every_irq() {
        let mut snap = BTreeMap::new();
        snap.insert(1, mask("0x1"));
        snap.insert(2, mask("0x8"));
        snap.insert(3, mask("0xf"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::All, sink);
        // all_cpus = 0..4, protected = CPUs 0-1, unprotected = CPUs 2-3 = 0xc.
        let changes = p.apply(&mask("0x3"), &mask("0xf"));

        assert_eq!(changes, 3);
        assert_eq!(p.last_mode, Some(Mode::All));
        for irq in [1, 2, 3] {
            assert_eq!(
                p.sink.last_mask_for(irq).cloned(),
                Some(mask("0xc")),
                "irq {irq} should be set to the unprotected set"
            );
        }
    }

    #[test]
    fn all_mode_falls_back_to_all_cpus_when_fully_protected() {
        let mut snap = BTreeMap::new();
        snap.insert(1, mask("0x1"));
        snap.insert(2, mask("0x4"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::All, sink);
        let changes = p.apply(&mask("0xf"), &mask("0xf"));

        assert_eq!(changes, 2);
        for irq in [1, 2] {
            assert_eq!(
                p.sink.last_mask_for(irq).cloned(),
                Some(mask("0xf")),
                "irq {irq} should be set to the full all_cpus mask"
            );
        }
    }

    #[test]
    fn mode_transitions_from_spread_back_to_normal() {
        let mut snap = BTreeMap::new();
        snap.insert(1, mask("0xf"));

        let sink = RecordingSink::new();
        let mut p = IrqProtector::with_snapshot(snap, IrqFallback::Spread, sink);

        // First, fully protected -> spread mode pins IRQ 1 to CPU 0.
        p.apply(&mask("0xf"), &mask("0xf"));
        assert_eq!(p.last_mode, Some(Mode::Spread));
        assert_eq!(p.sink.last_mask_for(1).cloned(), Some(mask("0x1")));

        // Layer shrinks -> normal mode strips CPU 0, leaves CPUs 1-3.
        p.apply(&mask("0x1"), &mask("0xf"));
        assert_eq!(p.last_mode, Some(Mode::Normal));
        assert_eq!(p.sink.last_mask_for(1).cloned(), Some(mask("0xe")));
    }
}
