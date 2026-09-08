// SPDX-License-Identifier: GPL-2.0
//! Startup-only platform preference discovery. These are hints, not speed ratios.

use std::cmp::Reverse;
use std::path::Path;

use scx_utils::Topology;

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
    pub preference: Option<u32>,
    pub max_frequency_khz: Option<u32>,
}

#[derive(Debug)]
pub struct CorePerformanceLayout {
    /// Ordered by complete capacity data, then complete preferred-core data.
    /// IDs only stabilize ties; they never imply different performance.
    pub cores: Vec<CorePerformance>,
    pub preference_source: Option<&'static str>,
    pub capacity_complete: bool,
}

impl CorePerformanceLayout {
    pub fn discover(topo: &Topology) -> Self {
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
        Self::read(identities, |cpu, suffix| {
            std::fs::read_to_string(
                Path::new("/sys/devices/system/cpu")
                    .join(format!("cpu{cpu}"))
                    .join(suffix),
            )
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
        })
    }

    fn read(
        identities: Vec<CoreIdentity>,
        mut read: impl FnMut(usize, &str) -> Option<u32>,
    ) -> Self {
        // Use one source across all cores. Partial or conflicting sibling
        // readings must not silently rank unknown CPUs below known ones.
        let mut read_core = |core: &CoreIdentity, suffix: &str| {
            let mut values = core.cpus.iter().map(|cpu| read(*cpu, suffix));
            let first = values.next().flatten().filter(|v| *v > 0)?;
            values.all(|v| v == Some(first)).then_some(first)
        };
        let mut preference_source = None;
        let mut preferences = vec![None; identities.len()];
        for source in PREFERENCE_SOURCES {
            let values: Vec<_> = identities.iter().map(|c| read_core(c, source)).collect();
            if !values.is_empty() && values.iter().all(Option::is_some) {
                preference_source = Some(source);
                preferences = values;
                break;
            }
        }
        let mut cores: Vec<_> = identities
            .into_iter()
            .zip(preferences)
            .map(|(identity, preference)| CorePerformance {
                capacity: read_core(&identity, "cpu_capacity"),
                max_frequency_khz: read_core(&identity, "cpufreq/cpuinfo_max_freq"),
                identity,
                preference,
            })
            .collect();
        let capacity_complete = !cores.is_empty() && cores.iter().all(|c| c.capacity.is_some());
        cores.sort_by_key(|c| {
            (
                Reverse(if capacity_complete { c.capacity } else { None }),
                Reverse(c.preference),
                c.identity.id,
            )
        });
        Self {
            cores,
            preference_source,
            capacity_complete,
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
            let key = (
                if self.capacity_complete {
                    c.capacity
                } else {
                    None
                },
                c.preference,
            );
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
            let key = (
                if self.capacity_complete {
                    c.capacity
                } else {
                    None
                },
                c.preference,
            );
            if let Some(prev) = previous {
                order.push_str(if prev == key { " = " } else { " > " });
            }
            order.push_str(&format!("{:?}", c.identity.cpus));
            previous = Some(key);
        }
        format!(
            "platform core order {order}; capacity {}, preference {}; advisory startup snapshot",
            if self.capacity_complete {
                "available"
            } else {
                "unknown/partial"
            },
            self.preference_source.unwrap_or("unavailable (equal)")
        )
    }

    pub fn details(&self) -> Vec<String> {
        let value = |v: Option<u32>| v.map_or_else(|| "unknown".into(), |v| v.to_string());
        self.cores.iter().map(|c| format!(
            "core {} package {} LLC {} CPUs {:?}: capacity {}, preference {}, advertised max {} kHz",
            c.identity.id, c.identity.package, c.identity.llc, c.identity.cpus,
            value(c.capacity), value(c.preference), value(c.max_frequency_khz)
        )).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let layout = CorePerformanceLayout::read(cores(), |cpu, source| match source {
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
            let layout = CorePerformanceLayout::read(cores(), |_, _| value);
            assert!(layout.summary().contains("[2, 70] = [5, 130]"));
        }
    }

    #[test]
    fn incomplete_source_falls_back_as_a_whole() {
        let layout = CorePerformanceLayout::read(cores(), |cpu, source| match source {
            "cpufreq/amd_pstate_prefcore_ranking" if cpu == 2 || cpu == 70 => Some(196),
            "acpi_cppc/highest_perf" => Some(100),
            _ => None,
        });
        assert_eq!(layout.preference_source, Some("acpi_cppc/highest_perf"));
        assert!(layout.summary().contains("[2, 70] = [5, 130]"));
    }

    #[test]
    fn conflicting_siblings_are_unknown_not_two_different_cores() {
        let layout = CorePerformanceLayout::read(cores(), |cpu, source| {
            (source == "cpufreq/amd_pstate_prefcore_ranking").then_some(cpu as u32)
        });
        assert_eq!(layout.preference_source, None);
        assert!(layout.summary().contains(" = "));
    }

    #[test]
    fn capacity_is_distinct_from_preference_and_clock() {
        let layout = CorePerformanceLayout::read(cores(), |cpu, source| {
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
        let layout = CorePerformanceLayout::read(cores(), |cpu, source| {
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
        let layout = CorePerformanceLayout::read(ids, |cpu, source| match source {
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
        let layout = CorePerformanceLayout::read(ids, |_, _| None);
        assert_eq!(layout.rank_words(), vec![(1u64 << 63) | 8]);
    }

    #[test]
    fn wide_and_empty_layouts_keep_kernel_selection() {
        assert!(CorePerformanceLayout::read(cores(), |_, _| Some(100))
            .rank_words()
            .is_empty());
        assert!(CorePerformanceLayout::read(vec![], |_, _| None)
            .rank_words()
            .is_empty());
    }
}
