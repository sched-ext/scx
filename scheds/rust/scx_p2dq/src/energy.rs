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
}

impl CpuEnergyProfile {
    /// Calculate energy cost coefficient for placement decisions
    /// Returns cost in arbitrary units (higher = less efficient)
    pub fn energy_cost(&self) -> u32 {
        // Cost = power / capacity (mW per unit of performance)
        // Scale to integer for BPF
        let total_power = self.base_power_mw + self.dynamic_power_mw;
        ((total_power as f64 / self.capacity as f64) * 1024.0) as u32
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

            for cpu in topo.all_cpus.values() {
                let profile = Self::create_profile_from_kernel_em(cpu, &kernel_em);
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
        kernel_em: &KernelEnergyModel,
    ) -> CpuEnergyProfile {
        if let Some(pd) = kernel_em.get_pd_by_cpu_id(cpu.id) {
            // Use highest performance state (max frequency) for power estimates
            if let Some((_, ps)) = pd.perf_table.last_key_value() {
                // Kernel provides power in microwatts, convert to milliwatts
                let dynamic_power_mw = (ps.power / 1000) as u32;

                // Estimate idle power as ~2-5% of dynamic power
                let base_power_mw = (dynamic_power_mw / 30).max(10);

                return CpuEnergyProfile {
                    capacity: cpu.cpu_capacity as u32,
                    base_power_mw,
                    dynamic_power_mw,
                    efficiency: (cpu.cpu_capacity as f32) / (dynamic_power_mw as f32),
                };
            }
        }

        // Fallback if we can't find this CPU in the energy model
        Self::create_profile_from_heuristics(cpu, &Topology::new().unwrap())
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
