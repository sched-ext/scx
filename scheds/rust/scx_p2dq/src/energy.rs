use anyhow::Result;
use scx_utils::{EnergyModel as KernelEnergyModel, Topology};
use std::collections::BTreeMap;
use tracing::info;

/// Energy characteristics for a CPU type
#[derive(Debug, Clone)]
pub struct CpuEnergyProfile {
    pub capacity: u32,         // Relative performance (0-1024)
    pub base_power_mw: u32,    // Base power consumption (mW)
    pub dynamic_power_mw: u32, // Dynamic power at 100% util (mW)
    pub efficiency: f32,       // Performance per watt
    cost_override: Option<u32>,
}

impl CpuEnergyProfile {
    /// Calculate energy cost coefficient for placement decisions
    /// Returns cost in arbitrary units clamped to 1..=u16::MAX (higher = less efficient)
    pub fn energy_cost(&self) -> u32 {
        if let Some(cost) = self.cost_override {
            return cost.clamp(1, u16::MAX as u32);
        }

        if self.capacity == 0 {
            return u16::MAX as u32;
        }

        // Cost = power / capacity (mW per unit of performance)
        // Scale to integer for BPF
        let total_power = self.base_power_mw as u64 + self.dynamic_power_mw as u64;
        let scaled = ((total_power as f64 / self.capacity as f64) * 1024.0).round();
        if !scaled.is_finite() || scaled >= u16::MAX as f64 {
            return u16::MAX as u32;
        }

        (scaled as u32).clamp(1, u16::MAX as u32)
    }
}

pub struct EnergyModel {
    /// Map from CPU ID to energy profile
    cpu_profiles: BTreeMap<usize, CpuEnergyProfile>,
    /// Utilization threshold for small tasks (prefer little cores)
    pub small_task_threshold: u32,
    /// Utilization threshold for large tasks (prefer big cores)
    pub large_task_threshold: u32,
}

impl EnergyModel {
    /// Create new energy model from system topology
    /// Tries to use kernel energy model first, falls back to heuristics
    pub fn new(topo: &Topology) -> Result<Self> {
        let mut cpu_profiles = BTreeMap::new();

        // Try to use kernel energy model if available
        if let Ok(kernel_em) = KernelEnergyModel::new() {
            info!("Using kernel energy model from /sys/kernel/debug/energy_model");
            let artificial_max_cost = Self::artificial_em_max_cost(&kernel_em);

            for cpu in topo.all_cpus.values() {
                let profile =
                    Self::create_profile_from_kernel_em(cpu, topo, &kernel_em, artificial_max_cost);
                cpu_profiles.insert(cpu.id, profile);
            }
        } else {
            info!("Kernel energy model not available, using frequency-based estimates");

            for cpu in topo.all_cpus.values() {
                let profile = Self::create_profile_from_heuristics(cpu, topo);
                cpu_profiles.insert(cpu.id, profile);
            }
        }

        // Derive thresholds from actual capacity distribution
        let (small_thresh, large_thresh) = Self::derive_thresholds(topo);

        Ok(EnergyModel {
            cpu_profiles,
            small_task_threshold: small_thresh,
            large_task_threshold: large_thresh,
        })
    }

    /// Detect artificial, cost-based kernel Energy Models (e.g., Intel hybrid
    /// `intel_pstate` where every PerfState has a constant placeholder `power`
    /// such as EM_MAX_POWER = 64000000 and real efficiency differences are
    /// encoded in `cost`). Returns `Some(max_cost)` for artificial EMs, or
    /// `None` for real power-based EMs so their existing power math stays
    /// unchanged.
    fn artificial_em_max_cost(kernel_em: &KernelEnergyModel) -> Option<usize> {
        let mut first_power: Option<usize> = None;
        let mut all_power_same = true;
        let mut state_count = 0usize;
        let mut max_top_cost = 0usize;

        for pd in kernel_em.perf_doms.values() {
            if let Some((_, top_ps)) = pd.perf_table.last_key_value() {
                max_top_cost = max_top_cost.max(top_ps.cost);
            }
            for ps in pd.perf_table.values() {
                state_count += 1;
                match first_power {
                    None => first_power = Some(ps.power),
                    Some(p) if p != ps.power => all_power_same = false,
                    _ => {}
                }
            }
        }

        if state_count >= 2 && all_power_same && max_top_cost > 0 {
            Some(max_top_cost)
        } else {
            None
        }
    }

    /// Derive task size thresholds from CPU capacity distribution
    fn derive_thresholds(topo: &Topology) -> (u32, u32) {
        // Find min and max capacities
        let mut min_cap = u32::MAX;
        let mut max_cap = 0u32;

        for cpu in topo.all_cpus.values() {
            let cap = cpu.cpu_capacity as u32;
            min_cap = min_cap.min(cap);
            max_cap = max_cap.max(cap);
        }

        // If homogeneous (all cores similar capacity), use percentage-based thresholds
        if max_cap - min_cap < 200 {
            // Less than ~20% variation
            return (256, 768); // 25% and 75% of 1024
        }

        // For big.LITTLE or heterogeneous systems:
        // Small task threshold: 25% of little core capacity
        // Large task threshold: 75% of big core capacity
        let small_thresh = (min_cap / 4).max(128);
        let large_thresh = ((max_cap * 3) / 4).min(896);

        (small_thresh, large_thresh)
    }

    /// Create energy profile from kernel energy model
    fn create_profile_from_kernel_em(
        cpu: &scx_utils::Cpu,
        topo: &Topology,
        kernel_em: &KernelEnergyModel,
        artificial_max_cost: Option<usize>,
    ) -> CpuEnergyProfile {
        if let Some(pd) = kernel_em.get_pd_by_cpu_id(cpu.id) {
            // Use highest performance state (max frequency) for power/cost estimates
            if let Some((_, ps)) = pd.perf_table.last_key_value() {
                // Kernel provides power in microwatts, convert to milliwatts
                let dynamic_power_mw = (ps.power / 1000) as u32;

                // Estimate idle power as ~2-5% of dynamic power
                let base_power_mw = (dynamic_power_mw / 30).max(10);

                // On artificial cost-based EMs (e.g. Intel hybrid `intel_pstate`),
                // `ps.power` is a constant placeholder (EM_MAX_POWER = 64000000),
                // so dividing power by capacity inverts big/little efficiency and
                // overflows u16. Use `ps.cost` scaled to the same ~3000 baseline
                // as `create_profile_from_heuristics()` so BPF's
                // `capacity * 10 - energy_cost / 10` score stays well-calibrated.
                if let Some(max_cost) = artificial_max_cost
                    && ps.cost > 0
                {
                    const ARTIFICIAL_COST_SCALE: f64 = 3000.0;
                    let scaled_cost = (((ps.cost as f64) / (max_cost as f64))
                        * ARTIFICIAL_COST_SCALE)
                        .round()
                        .clamp(1.0, u16::MAX as f64) as u32;

                    return CpuEnergyProfile {
                        capacity: cpu.cpu_capacity as u32,
                        base_power_mw,
                        dynamic_power_mw,
                        efficiency: (ARTIFICIAL_COST_SCALE as f32) / (scaled_cost as f32),
                        cost_override: Some(scaled_cost),
                    };
                }

                return CpuEnergyProfile {
                    capacity: cpu.cpu_capacity as u32,
                    base_power_mw,
                    dynamic_power_mw,
                    efficiency: if dynamic_power_mw > 0 {
                        (cpu.cpu_capacity as f32) / (dynamic_power_mw as f32)
                    } else {
                        0.0
                    },
                    cost_override: None,
                };
            }
        }

        // Fallback if we can't find this CPU in the energy model
        Self::create_profile_from_heuristics(cpu, topo)
    }

    /// Create energy profile based on CPU characteristics using heuristics
    /// Uses frequency and capacity to estimate power consumption
    fn create_profile_from_heuristics(cpu: &scx_utils::Cpu, topo: &Topology) -> CpuEnergyProfile {
        // Find max capacity in the system to determine core type
        let max_capacity = topo
            .all_cpus
            .values()
            .map(|c| c.cpu_capacity)
            .max()
            .unwrap_or(1024);

        // Determine if this is a big or little core
        // Consider it "big" if capacity is >= 78% of max capacity
        let is_big_core = cpu.cpu_capacity >= (max_capacity * 78) / 100;

        // Power scales roughly with frequency and voltage
        // P ≈ C * V^2 * f, and V ≈ f for modern CPUs
        // So P ≈ k * f^3 (simplified)

        let freq_ratio = if cpu.max_freq > 0 {
            cpu.max_freq as f64 / 2500000.0 // Normalize to ~2.5GHz baseline
        } else {
            1.0
        };

        let capacity_ratio = cpu.cpu_capacity as f64 / 1024.0;

        if is_big_core {
            // Big core - scale power based on frequency
            let base_dynamic_power = 3000.0; // 3W baseline for 2.5GHz big core
            let dynamic_power_mw = (base_dynamic_power * freq_ratio.powf(2.5)) as u32;
            let base_power_mw = (dynamic_power_mw / 60).max(30); // ~1.6-3% of dynamic

            CpuEnergyProfile {
                capacity: cpu.cpu_capacity as u32,
                base_power_mw,
                dynamic_power_mw,
                efficiency: (cpu.cpu_capacity as f32) / (dynamic_power_mw as f32),
                cost_override: None,
            }
        } else {
            // Little core - more efficient, lower power
            let base_dynamic_power = 1200.0; // 1.2W baseline for little core
            let dynamic_power_mw =
                (base_dynamic_power * freq_ratio.powf(2.5) * capacity_ratio) as u32;
            let base_power_mw = (dynamic_power_mw / 50).max(15); // ~2% of dynamic

            CpuEnergyProfile {
                capacity: cpu.cpu_capacity as u32,
                base_power_mw,
                dynamic_power_mw,
                efficiency: (cpu.cpu_capacity as f32) / (dynamic_power_mw as f32),
                cost_override: None,
            }
        }
    }

    /// Get energy cost for a CPU
    pub fn cpu_energy_cost(&self, cpu: usize) -> u32 {
        self.cpu_profiles
            .get(&cpu)
            .map(|p| p.energy_cost())
            .unwrap_or(1024)
    }

    /// Get CPU capacity
    pub fn cpu_capacity(&self, cpu: usize) -> u32 {
        self.cpu_profiles
            .get(&cpu)
            .map(|p| p.capacity)
            .unwrap_or(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scx_utils::{CoreType, Cpu, Cpumask, PerfDomain, PerfState};
    use std::sync::Arc;

    fn make_cpu(id: usize, capacity: usize, core_type: CoreType) -> Cpu {
        Cpu {
            id,
            min_freq: 400_000,
            max_freq: 2_100_000,
            base_freq: 2_100_000,
            trans_lat_ns: 0,
            l2_id: 0,
            l3_id: 0,
            cache_size: 0,
            cpu_capacity: capacity,
            kernel_cpu_capacity: Some(capacity),
            pm_qos_resume_latency_us: 0,
            core_type,
            node_id: 0,
            llc_id: 0,
            core_id: id,
            package_id: 0,
            cluster_id: 0,
            smt_level: 1,
        }
    }

    fn make_pd(cpu_id: usize, states: &[(usize, usize, usize)]) -> Arc<PerfDomain> {
        let mut span = Cpumask::new();
        span.set_cpu(cpu_id).unwrap();

        let mut perf_table = BTreeMap::new();
        for &(perf, cost, power) in states {
            perf_table.insert(
                perf,
                Arc::new(PerfState {
                    cost,
                    frequency: perf,
                    inefficient: 0,
                    performance: perf,
                    power,
                }),
            );
        }

        Arc::new(PerfDomain {
            id: cpu_id,
            span,
            perf_table,
        })
    }

    #[test]
    fn test_artificial_em_lunar_lake_prefers_lpe_over_p_core() {
        // Intel Core Ultra 5 226V (Lunar Lake) artificial EM from intel_pstate:
        // all perf states have constant power = EM_MAX_POWER (64000000), while
        // relative efficiency is encoded in `cost`.
        const EM_MAX_POWER: usize = 64_000_000;
        let mut perf_doms = BTreeMap::new();
        perf_doms.insert(
            0,
            make_pd(
                0,
                &[
                    (409, 4, EM_MAX_POWER),
                    (614, 5, EM_MAX_POWER),
                    (819, 6, EM_MAX_POWER),
                    (1024, 7, EM_MAX_POWER),
                ],
            ),
        );
        perf_doms.insert(
            4,
            make_pd(
                4,
                &[
                    (344, 2, EM_MAX_POWER),
                    (516, 3, EM_MAX_POWER),
                    (688, 4, EM_MAX_POWER),
                    (860, 5, EM_MAX_POWER),
                ],
            ),
        );
        let kernel_em = KernelEnergyModel {
            perf_doms,
            eq_perf_doms: BTreeMap::new(),
        };

        let topo = Topology::new().unwrap();
        let p_cpu = make_cpu(0, 1024, CoreType::Big { turbo: true });
        let lpe_cpu = make_cpu(4, 860, CoreType::Little);
        let max_cost = EnergyModel::artificial_em_max_cost(&kernel_em);
        assert_eq!(max_cost, Some(7));

        let p_profile =
            EnergyModel::create_profile_from_kernel_em(&p_cpu, &topo, &kernel_em, max_cost);
        let lpe_profile =
            EnergyModel::create_profile_from_kernel_em(&lpe_cpu, &topo, &kernel_em, max_cost);

        let p_cost = p_profile.energy_cost();
        let lpe_cost = lpe_profile.energy_cost();

        assert!(
            lpe_cost < p_cost,
            "LPE cost ({lpe_cost}) must be lower than P-core cost ({p_cost})"
        );
        assert!((1..=u16::MAX as u32).contains(&p_cost));
        assert!((1..=u16::MAX as u32).contains(&lpe_cost));
        assert_eq!(p_cost, 3000);
        assert_eq!(lpe_cost, 2143);
    }

    #[test]
    fn test_real_em_keeps_existing_power_calculation() {
        let mut perf_doms = BTreeMap::new();
        perf_doms.insert(0, make_pd(0, &[(1024, 8000, 3_000_000)]));
        perf_doms.insert(1, make_pd(1, &[(512, 2000, 1_200_000)]));
        let kernel_em = KernelEnergyModel {
            perf_doms,
            eq_perf_doms: BTreeMap::new(),
        };

        let topo = Topology::new().unwrap();
        let big_cpu = make_cpu(0, 1024, CoreType::Big { turbo: true });
        let little_cpu = make_cpu(1, 512, CoreType::Little);
        let artificial_max_cost = EnergyModel::artificial_em_max_cost(&kernel_em);
        assert_eq!(artificial_max_cost, None);

        let big_cost = EnergyModel::create_profile_from_kernel_em(
            &big_cpu,
            &topo,
            &kernel_em,
            artificial_max_cost,
        )
        .energy_cost();
        let little_cost = EnergyModel::create_profile_from_kernel_em(
            &little_cpu,
            &topo,
            &kernel_em,
            artificial_max_cost,
        )
        .energy_cost();

        // Big: dynamic=3000mW, base=100mW, cap=1024 -> 3100
        // Little: dynamic=1200mW, base=40mW, cap=512 -> 2480
        assert_eq!(big_cost, 3100);
        assert_eq!(little_cost, 2480);
    }

    #[test]
    fn test_energy_cost_clamps_instead_of_wrapping_u16() {
        // Previously, EM_MAX_POWER (64000000 uW -> 64000 mW + 2133 mW = 66133 mW)
        // exceeded u16::MAX (65535) and wrapped on `as u16` cast.
        let high_power = CpuEnergyProfile {
            capacity: 860,
            base_power_mw: 2133,
            dynamic_power_mw: 64000,
            efficiency: 0.0,
            cost_override: None,
        };
        assert_eq!(high_power.energy_cost(), u16::MAX as u32);

        let zero_cap = CpuEnergyProfile {
            capacity: 0,
            base_power_mw: 100,
            dynamic_power_mw: 1000,
            efficiency: 0.0,
            cost_override: None,
        };
        assert_eq!(zero_cap.energy_cost(), u16::MAX as u32);

        let tiny_power = CpuEnergyProfile {
            capacity: 1024,
            base_power_mw: 0,
            dynamic_power_mw: 0,
            efficiency: 0.0,
            cost_override: None,
        };
        assert_eq!(tiny_power.energy_cost(), 1);
    }
}
