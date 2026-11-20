// SPDX-License-Identifier: GPL-2.0
//! CPU placement inputs sampled before attaching the scheduler.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::path::Path;

use scx_utils::{CoreType, Cpu, Topology};

const PREFERENCE_SOURCES: [&str; 2] = [
    "cpufreq/amd_pstate_prefcore_ranking",
    "acpi_cppc/highest_perf",
];

#[derive(Debug)]
pub struct CoreIdentity {
    pub id: usize,
    pub package: usize,
    pub llc: usize,
    pub cpus: Vec<usize>,
}

#[derive(Debug)]
pub struct CorePerformance {
    pub identity: CoreIdentity,
    pub capacity: Option<u32>,
    pub effective_capacity: Option<u32>,
    pub preference: Option<u32>,
    max_frequency_khz: Option<u32>,
    scaling_max_khz: Option<u32>,
    scaling_min_khz: Option<u32>,
    bios_limit_khz: Option<u32>,
    governor: Option<String>,
    epp: Option<String>,
    boost: Option<String>,
    // Available only with consistent sibling data. An absent BIOS limit is normal.
    ceiling: Option<(u32, u32)>,
    split_limits: Vec<&'static str>,
}

impl CorePerformance {
    fn rank(&self) -> (Option<u32>, Option<u32>) {
        (self.effective_capacity, self.preference)
    }
}

#[derive(Debug)]
pub struct CorePerformanceLayout {
    pub cores: Vec<CorePerformance>,
    pub preference_source: Option<&'static str>,
    pub capacity_complete: bool,
    disabled_by: Option<&'static str>,
    ceiling_status: CeilingStatus,
    // None preserves the existing topology classification on hosts with no override.
    little_cores: Option<BTreeSet<usize>>,
}

#[derive(Debug, PartialEq, Eq)]
enum CeilingStatus {
    Applied,
    Unrestricted,
    Incomplete,
    Incomparable,
}

fn read_text(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn disabled(value: Option<&str>) -> bool {
    matches!(value, Some("disabled" | "0" | "N" | "n"))
}

// Some(None) means every sibling lacks this optional attribute. None means
// sibling disagreement, which cannot represent a single physical-core limit.
fn uniform<T: Eq>(mut values: impl Iterator<Item = Option<T>>) -> Option<Option<T>> {
    let first = values.next()?;
    values.all(|v| v == first).then_some(first)
}

fn positive_number(value: Option<String>) -> Option<u32> {
    value?.parse::<u32>().ok().filter(|n| *n != 0)
}

impl CorePerformanceLayout {
    pub fn discover(topo: &Topology) -> Self {
        let base = Path::new("/sys/devices/system/cpu");
        let identities = topo
            .all_cores
            .values()
            .filter_map(|core| {
                let first = core.cpus.values().next()?;
                Some(CoreIdentity {
                    id: core.id,
                    package: first.package_id,
                    llc: core.llc_id,
                    cpus: core.cpus.keys().copied().collect(),
                })
            })
            .collect();
        let amd_prefcore = read_text(&base.join("amd_pstate/prefcore"));
        let global_boost = read_text(&base.join("cpufreq/boost")).or_else(|| {
            match read_text(&base.join("intel_pstate/no_turbo")).as_deref() {
                Some("0") => Some("1".to_owned()),
                Some("1") => Some("0".to_owned()),
                _ => None,
            }
        });
        let itmt = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            read_text(Path::new("/sys/kernel/debug/x86/sched_itmt_enabled"))
        } else {
            None
        };
        Self::snapshot(
            identities,
            amd_prefcore.as_deref(),
            itmt.as_deref(),
            |cpu, suffix| {
                let value = read_text(&base.join(format!("cpu{cpu}")).join(suffix));
                if suffix == "cpufreq/boost" {
                    value.or_else(|| global_boost.clone())
                } else {
                    value
                }
            },
        )
    }

    fn snapshot(
        identities: Vec<CoreIdentity>,
        amd_prefcore: Option<&str>,
        itmt: Option<&str>,
        mut read: impl FnMut(usize, &str) -> Option<String>,
    ) -> Self {
        let disabled_by = if disabled(amd_prefcore) {
            Some("amd_pstate/prefcore")
        } else if disabled(itmt) {
            Some("x86/sched_itmt_enabled")
        } else if identities
            .iter()
            .flat_map(|c| &c.cpus)
            .any(|&cpu| disabled(read(cpu, "cpufreq/amd_pstate_hw_prefcore").as_deref()))
        {
            Some("amd_pstate_hw_prefcore")
        } else {
            None
        };
        let mut core_value = |core: &CoreIdentity, suffix: &str| {
            uniform(core.cpus.iter().map(|&cpu| read(cpu, suffix)))
        };
        let mut preference_source = None;
        let mut preferences = vec![None; identities.len()];
        if disabled_by.is_none() {
            for source in PREFERENCE_SOURCES {
                let ranks: Vec<_> = identities
                    .iter()
                    .map(|c| positive_number(core_value(c, source).flatten()))
                    .collect();
                if !ranks.is_empty() && ranks.iter().all(Option::is_some) {
                    preference_source = Some(source);
                    preferences = ranks;
                    break;
                }
            }
        }
        let mut cores: Vec<_> = identities
            .into_iter()
            .zip(preferences)
            .map(|(identity, preference)| {
                let mut field = |suffix: &str| core_value(&identity, suffix);
                let capacity = positive_number(field("cpu_capacity").flatten());
                let mut split_limits = Vec::new();
                let mut limit_field = |suffix: &'static str| {
                    let value = field(suffix);
                    if value.is_none() {
                        split_limits.push(suffix);
                    }
                    value
                };
                let max_frequency_khz =
                    positive_number(limit_field("cpufreq/cpuinfo_max_freq").flatten());
                let scaling_max_khz =
                    positive_number(limit_field("cpufreq/scaling_max_freq").flatten());
                let bios = limit_field("cpufreq/bios_limit");
                let bios_limit_khz = positive_number(bios.clone().flatten());
                // amd-pstate reduces cpuinfo_max_freq to nominal when boost is off;
                // amd_pstate_max_freq still exposes the reference ceiling in kHz.
                let amd_max = limit_field("cpufreq/amd_pstate_max_freq");
                let reference = match &amd_max {
                    Some(None) => max_frequency_khz,
                    Some(value) => positive_number(value.clone())
                        .filter(|&v| max_frequency_khz.is_some_and(|m| v >= m)),
                    None => None,
                };
                let ceiling = reference
                    .zip(scaling_max_khz)
                    .zip(max_frequency_khz)
                    .filter(|_| bios == Some(None) || bios_limit_khz.is_some())
                    .map(|((reference, policy), hardware)| {
                        let limit = policy.min(hardware);
                        (
                            bios_limit_khz.map_or(limit, |bios| limit.min(bios)),
                            reference,
                        )
                    });
                CorePerformance {
                    capacity,
                    effective_capacity: None,
                    preference,
                    max_frequency_khz,
                    scaling_max_khz,
                    scaling_min_khz: field("cpufreq/scaling_min_freq")
                        .flatten()
                        .and_then(|v| v.parse().ok()),
                    bios_limit_khz,
                    governor: field("cpufreq/scaling_governor").flatten(),
                    epp: field("cpufreq/energy_performance_preference").flatten(),
                    boost: field("cpufreq/boost").flatten(),
                    ceiling,
                    split_limits,
                    identity,
                }
            })
            .collect();
        let capacity_complete = !cores.is_empty() && cores.iter().all(|c| c.capacity.is_some());
        let reference = cores.first().and_then(|c| c.ceiling).map(|(_, r)| r);
        // Across different CPU designs kHz alone is insufficient. Without
        // architectural capacities compare caps only on a common reference.
        let ceiling_status = if reference.is_none() || cores.iter().any(|c| c.ceiling.is_none()) {
            CeilingStatus::Incomplete
        } else if cores
            .iter()
            .all(|c| c.ceiling.is_some_and(|(lim, r)| lim == r))
        {
            CeilingStatus::Unrestricted
        } else if !capacity_complete && cores.iter().any(|c| c.ceiling.map(|(_, r)| r) != reference)
        {
            CeilingStatus::Incomparable
        } else {
            CeilingStatus::Applied
        };
        let use_limits = ceiling_status == CeilingStatus::Applied;
        for c in &mut cores {
            c.effective_capacity = if use_limits {
                let (limit, reference) = c.ceiling.unwrap();
                let capacity = if capacity_complete {
                    c.capacity.unwrap()
                } else {
                    1024
                };
                Some(
                    ((u64::from(capacity) * u64::from(limit)) / u64::from(reference)).max(1) as u32,
                )
            } else {
                c.capacity.filter(|_| capacity_complete)
            };
        }
        let max = cores
            .iter()
            .filter_map(|c| c.effective_capacity)
            .max()
            .unwrap_or(0);
        let min = cores
            .iter()
            .filter_map(|c| c.effective_capacity)
            .min()
            .unwrap_or(0);
        let heterogeneous = min > 0 && u64::from(max) * 10 >= u64::from(min) * 13;
        let little_cores = if disabled_by.is_some() || use_limits || heterogeneous {
            // Use the same 1.3x threshold as scx_utils, but never infer a
            // performance class from CPPC values the administrator disabled.
            let mut little = BTreeSet::new();
            if heterogeneous {
                let count: u64 = cores.iter().map(|c| c.identity.cpus.len() as u64).sum();
                let total: u64 = cores
                    .iter()
                    .map(|c| {
                        u64::from(c.effective_capacity.unwrap()) * c.identity.cpus.len() as u64
                    })
                    .sum();
                little.extend(
                    cores
                        .iter()
                        .filter(|c| u64::from(c.effective_capacity.unwrap()) * count < total)
                        .map(|c| c.identity.id),
                );
            }
            Some(little)
        } else {
            None
        };
        cores.sort_by_key(|c| (Reverse(c.rank()), c.identity.id));
        Self {
            cores,
            preference_source,
            capacity_complete,
            disabled_by,
            ceiling_status,
            little_cores,
        }
    }

    pub fn preferences_disabled(&self) -> bool {
        self.disabled_by.is_some()
    }

    pub fn big_cpu(&self, cpu: &Cpu) -> bool {
        match &self.little_cores {
            Some(little) => !little.contains(&cpu.core_id),
            None => cpu.core_type != CoreType::Little,
        }
    }

    /// Complete narrow-host tiers. Wide hosts retain the kernel picker.
    pub fn rank_words(&self) -> Vec<u64> {
        if self
            .cores
            .iter()
            .any(|c| c.identity.cpus.iter().any(|cpu| *cpu >= 64))
        {
            return Vec::new();
        }
        let mut tiers: Vec<u64> = Vec::new();
        let mut previous = None;
        for c in &self.cores {
            let key = c.rank();
            if previous != Some(key) {
                tiers.push(0);
                previous = Some(key);
            }
            if let Some(word) = tiers.last_mut() {
                for cpu in &c.identity.cpus {
                    *word |= 1u64 << cpu;
                }
            }
        }
        tiers
    }

    pub fn summary(&self) -> String {
        let mut order = String::new();
        let mut previous = None;
        for c in &self.cores {
            let key = c.rank();
            if let Some(prev) = previous {
                order.push_str(if prev == key { " = " } else { " > " });
            }
            order.push_str(&format!("{:?}", c.identity.cpus));
            previous = Some(key);
        }
        let preference = self
            .disabled_by
            .map(|source| format!("disabled by {source}"))
            .unwrap_or_else(|| {
                self.preference_source
                    .unwrap_or("unavailable (equal)")
                    .to_owned()
            });
        let ceilings = match self.ceiling_status {
            CeilingStatus::Applied => "effective frequency ceilings applied",
            CeilingStatus::Unrestricted => "frequency ceilings at hardware maxima",
            CeilingStatus::Incomplete => {
                "frequency ceilings skipped (incomplete or inconsistent core data)"
            }
            CeilingStatus::Incomparable => {
                "frequency ceilings skipped (unequal reference clocks and incomplete architectural capacities)"
            }
        };
        format!(
            "platform core order {order}; capacity {}, preference {preference}; {ceilings}; advisory startup snapshot",
            if self.capacity_complete {
                "available"
            } else {
                "unknown/partial"
            }
        )
    }

    pub fn details(&self) -> Vec<String> {
        self.cores
            .iter()
            .map(|c| {
                let mut fields = Vec::new();
                for (name, value) in [
                    ("capacity", c.capacity),
                    ("effective capacity", c.effective_capacity),
                    ("preference", c.preference),
                    ("advertised max kHz", c.max_frequency_khz),
                    ("policy min kHz", c.scaling_min_khz),
                    ("policy max kHz", c.scaling_max_khz),
                    ("BIOS max kHz", c.bios_limit_khz),
                ] {
                    if let Some(v) = value {
                        fields.push(format!("{name} {v}"));
                    }
                }
                if !c.split_limits.is_empty() {
                    fields.push(format!(
                        "SMT siblings disagree on {}",
                        c.split_limits.join(", ")
                    ));
                } else if let Some((limit, reference)) = c.ceiling {
                    if self.ceiling_status == CeilingStatus::Applied {
                        fields.push(format!("capacity ceiling {limit}/{reference} kHz"));
                    }
                } else {
                    fields.push("frequency ceiling unavailable".into());
                }
                for (name, value) in [
                    ("boost", &c.boost),
                    ("governor", &c.governor),
                    ("EPP", &c.epp),
                ] {
                    if let Some(v) = value {
                        fields.push(format!("{name} {v}"));
                    }
                }
                format!(
                    "core {} package {} LLC {} CPUs {:?}: {}",
                    c.identity.id,
                    c.identity.package,
                    c.identity.llc,
                    c.identity.cpus,
                    fields.join(", ")
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(
        ids: Vec<CoreIdentity>,
        mut value: impl FnMut(usize, &str) -> Option<u32>,
    ) -> CorePerformanceLayout {
        CorePerformanceLayout::snapshot(ids, None, None, |cpu, key| {
            value(cpu, key).map(|v| v.to_string())
        })
    }

    fn cores() -> Vec<CoreIdentity> {
        vec![
            CoreIdentity {
                id: 4,
                package: 0,
                llc: 0,
                cpus: vec![2, 70],
            },
            CoreIdentity {
                id: 9,
                package: 1,
                llc: 1,
                cpus: vec![5, 130],
            },
        ]
    }

    #[test]
    fn sparse_smt_groups_follow_preference_not_cpu_id() {
        let layout = read(cores(), |cpu, source| match source {
            "cpufreq/amd_pstate_prefcore_ranking" => {
                Some(if cpu == 5 || cpu == 130 { 196 } else { 176 })
            }
            "cpu_capacity" => Some(1024),
            _ => None,
        });
        assert_eq!(layout.cores[0].identity.cpus, [5, 130]);
        assert!(layout.summary().contains("[5, 130] > [2, 70]"));
    }

    #[test]
    fn missing_information_and_equal_ranks_do_not_invent_a_slow_core() {
        for value in [None, Some(0), Some(100)] {
            let layout = read(cores(), |_, _| value);
            assert!(layout.summary().contains("[2, 70] = [5, 130]"));
        }
    }

    #[test]
    fn incomplete_source_falls_back_as_a_whole() {
        let layout = read(cores(), |cpu, source| match source {
            "cpufreq/amd_pstate_prefcore_ranking" if cpu == 2 || cpu == 70 => Some(196),
            "acpi_cppc/highest_perf" => Some(100),
            _ => None,
        });
        assert_eq!(layout.preference_source, Some("acpi_cppc/highest_perf"));
        assert!(layout.summary().contains("[2, 70] = [5, 130]"));
    }

    #[test]
    fn conflicting_siblings_are_unknown_not_two_different_cores() {
        let layout = read(cores(), |cpu, source| {
            (source == "cpufreq/amd_pstate_prefcore_ranking").then_some(cpu as u32)
        });
        assert_eq!(layout.preference_source, None);
        assert!(layout.summary().contains(" = "));
    }

    #[test]
    fn capacity_is_distinct_from_preference_and_clock() {
        let layout = read(cores(), |cpu, source| {
            let big = cpu == 2 || cpu == 70;
            match source {
                "cpu_capacity" => Some(if big { 1024 } else { 512 }),
                "cpufreq/amd_pstate_prefcore_ranking" => Some(if big { 100 } else { 200 }),
                "cpufreq/cpuinfo_max_freq" => Some(if big { 3000000 } else { 4000000 }),
                _ => None,
            }
        });
        assert_eq!(layout.cores[0].identity.id, 4);
        assert!(layout.capacity_complete);
    }

    #[test]
    fn partial_capacity_does_not_demote_unknown_core() {
        let layout = read(cores(), |cpu, source| {
            (source == "cpu_capacity" && cpu == 2).then_some(1024)
        });
        assert!(!layout.capacity_complete);
        assert!(layout.summary().contains(" = "));
    }

    #[test]
    fn cold_rank_words_preserve_smt_ties_and_capacity_order() {
        let ids = vec![
            CoreIdentity {
                id: 0,
                package: 0,
                llc: 0,
                cpus: vec![0, 4],
            },
            CoreIdentity {
                id: 1,
                package: 0,
                llc: 0,
                cpus: vec![1, 5],
            },
            CoreIdentity {
                id: 2,
                package: 0,
                llc: 1,
                cpus: vec![2, 6],
            },
        ];
        let layout = read(ids, |cpu, source| match source {
            "cpu_capacity" => Some(if cpu % 4 == 2 { 512 } else { 1024 }),
            "cpufreq/amd_pstate_prefcore_ranking" => Some(if cpu % 4 == 2 { 200 } else { 100 }),
            _ => None,
        });
        assert_eq!(layout.rank_words(), vec![0x33, 0x44]);
    }

    #[test]
    fn rank_words_handle_cpu63_and_unknown_equal_hardware() {
        let ids = vec![CoreIdentity {
            id: 0,
            package: 0,
            llc: 0,
            cpus: vec![3, 63],
        }];
        let layout = read(ids, |_, _| None);
        assert_eq!(layout.rank_words(), vec![(1u64 << 63) | 8]);
    }

    #[test]
    fn wide_and_empty_layouts_keep_kernel_selection() {
        assert!(read(cores(), |_, _| Some(100)).rank_words().is_empty());
        assert!(read(vec![], |_, _| None).rank_words().is_empty());
    }

    #[test]
    fn explicit_opt_out_blocks_firmware_fallback() {
        for (amd, itmt, policy) in [
            (Some("disabled"), None, None),
            (None, Some("N"), None),
            (None, None, Some("disabled")),
        ] {
            let layout =
                CorePerformanceLayout::snapshot(cores(), amd, itmt, |cpu, key| match key {
                    "cpufreq/amd_pstate_hw_prefcore" if cpu == 130 => policy.map(str::to_owned),
                    "cpufreq/amd_pstate_prefcore_ranking" | "acpi_cppc/highest_perf" => {
                        Some(if cpu == 2 || cpu == 70 { "200" } else { "50" }.into())
                    }
                    _ => None,
                });
            assert!(layout.preferences_disabled());
            assert!(layout.preference_source.is_none());
            assert_eq!(layout.little_cores, Some(BTreeSet::new()));
            assert!(layout.summary().contains(" = "));
        }
    }

    #[test]
    fn policy_and_firmware_caps_scale_each_cores_architectural_capacity() {
        let layout = read(cores(), |cpu, key| {
            let left = cpu == 2 || cpu == 70;
            match key {
                "cpufreq/cpuinfo_max_freq" => Some(4000000),
                "cpufreq/scaling_max_freq" => Some(if left { 3000000 } else { 4000000 }),
                "cpufreq/bios_limit" if !left => Some(2000000),
                "cpu_capacity" => Some(if left { 1024 } else { 768 }),
                "acpi_cppc/highest_perf" => Some(if left { 100 } else { 200 }),
                _ => None,
            }
        });
        assert_eq!(layout.cores[0].effective_capacity, Some(768));
        assert_eq!(layout.cores[1].effective_capacity, Some(384));
        assert_eq!(layout.little_cores, Some(BTreeSet::from([9])));
        assert!(layout.details()[1].contains("capacity ceiling 2000000/4000000 kHz"));
        assert!(
            layout
                .summary()
                .contains("effective frequency ceilings applied")
        );
    }

    #[test]
    fn boost_disabled_uses_amd_full_frequency_as_reference() {
        let layout = read(cores(), |cpu, key| match key {
            "cpufreq/amd_pstate_max_freq" => Some(5000000),
            "cpufreq/cpuinfo_max_freq" | "cpufreq/scaling_max_freq" => {
                Some(if cpu == 2 || cpu == 70 {
                    4000000
                } else {
                    5000000
                })
            }
            _ => None,
        });
        assert_eq!(layout.cores[0].identity.id, 9);
        assert_eq!(layout.cores[1].effective_capacity, Some(819));
    }

    #[test]
    fn incomplete_or_conflicting_ceilings_do_not_reorder_cores() {
        for defect in [
            "missing policy",
            "split BIOS",
            "split policy",
            "different reference",
        ] {
            let layout = read(cores(), |cpu, key| {
                let left = cpu == 2 || cpu == 70;
                match key {
                    "cpufreq/cpuinfo_max_freq" => {
                        Some(if defect == "different reference" && left {
                            3000000
                        } else {
                            4000000
                        })
                    }
                    "cpufreq/scaling_max_freq" if defect == "split policy" && cpu == 2 => {
                        Some(1000000)
                    }
                    "cpufreq/scaling_max_freq" if !(defect == "missing policy" && left) => {
                        Some(if left { 2000000 } else { 4000000 })
                    }
                    "cpufreq/bios_limit" if defect == "split BIOS" && cpu == 2 => Some(1000000),
                    _ => None,
                }
            });
            assert!(
                layout.cores.iter().all(|c| c.effective_capacity.is_none()),
                "{defect}"
            );
            assert!(layout.summary().contains("frequency ceilings skipped"));
            let core = &layout.details()[0];
            match defect {
                "split BIOS" => {
                    assert!(core.contains("SMT siblings disagree on cpufreq/bios_limit"))
                }
                "split policy" => {
                    assert!(core.contains("SMT siblings disagree on cpufreq/scaling_max_freq"))
                }
                "missing policy" => assert!(core.contains("frequency ceiling unavailable")),
                _ => assert!(layout.summary().contains("unequal reference clocks")),
            }
        }
    }

    #[test]
    fn diagnostic_policy_values_do_not_rank_cores() {
        let layout = CorePerformanceLayout::snapshot(cores(), None, None, |cpu, key| {
            let left = cpu == 2 || cpu == 70;
            match key {
                "cpufreq/scaling_governor" => {
                    Some(if left { "performance" } else { "powersave" }.into())
                }
                "cpufreq/energy_performance_preference" => {
                    Some(if left { "power" } else { "performance" }.into())
                }
                "cpufreq/scaling_min_freq" => Some(if left { "2000000" } else { "400000" }.into()),
                "cpufreq/boost" => Some(if left { "0" } else { "1" }.into()),
                _ => None,
            }
        });
        assert!(layout.summary().contains(" = "));
        assert!(layout.details()[0].contains("governor performance"));
        assert!(layout.details()[0].contains("EPP power"));
    }
}
