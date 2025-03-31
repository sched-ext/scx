#![cfg(feature = "gpu-topology")]

use crate::misc::read_from_file;
use crate::{Cpumask, NR_CPU_IDS};
use nvml_wrapper::bitmasks::InitFlags;
use nvml_wrapper::enum_wrappers::device::{Clock, TopologyLevel};
use nvml_wrapper::Nvml;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum GpuIndex {
    Nvidia { nvml_id: u32 },
}

#[derive(Debug, Clone)]
pub struct Gpu {
    pub index: GpuIndex,
    pub node_id: usize,
    pub max_graphics_clock: usize,
    // AMD uses CU for this value
    pub max_sm_clock: usize,
    pub memory: u64,
    pub cpu_mask: Cpumask,
    // Represents the ordered list of nearest
    // available devices in term of topology
    // connectivity (as for now in term of PCI board).
    pub nearest: Vec<GpuIndex>,
}

pub fn create_gpus() -> BTreeMap<usize, Vec<Gpu>> {
    let mut gpus: BTreeMap<usize, Vec<Gpu>> = BTreeMap::new();

    // Don't fail if the system has no NVIDIA GPUs.
    let Ok(nvml) = Nvml::init_with_flags(InitFlags::NO_GPUS) else {
        return BTreeMap::new();
    };
    if let Ok(nvidia_gpu_count) = nvml.device_count() {
        for i in 0..nvidia_gpu_count {
            let Ok(nvidia_gpu) = nvml.device_by_index(i) else {
                continue;
            };
            let graphics_boost_clock = nvidia_gpu
                .max_customer_boost_clock(Clock::Graphics)
                .unwrap_or(0);
            let sm_boost_clock = nvidia_gpu.max_customer_boost_clock(Clock::SM).unwrap_or(0);
            let Ok(memory_info) = nvidia_gpu.memory_info() else {
                continue;
            };
            let Ok(pci_info) = nvidia_gpu.pci_info() else {
                continue;
            };
            let Ok(index) = nvidia_gpu.index() else {
                continue;
            };

            let cpu_mask = if let Ok(cpu_affinity) = nvidia_gpu.cpu_affinity(*NR_CPU_IDS) {
                // Note: nvml returns it as an arch dependent array of integrals
                #[cfg(target_pointer_width = "32")]
                let cpu_affinity: Vec<u64> = cpu_affinity
                    .chunks_exact(2)
                    .map(|pair| (pair[1] as u64) << 32 | pair[0] as u64)
                    .collect();
                Cpumask::from_vec(cpu_affinity)
            } else {
                Cpumask::new()
            };

            let nearest_gpu_topology_level = if nvidia_gpu.is_multi_gpu_board().unwrap_or(false) {
                // e.g. for some Tesla models, this mode is faster
                // as units are part of the same physical device
                TopologyLevel::Internal
            } else {
                TopologyLevel::HostBridge
            };

            // NVML_TOPOLOGY_HOSTBRIDGE is supported by all models and
            // NVML_TOPOLOGY_SYSTEM is an expensive check (i.e. all sort of
            // multi gpus connection types).
            let nearest = if let Ok(nearest_gpus) =
                nvidia_gpu.topology_nearest_gpus(nearest_gpu_topology_level)
            {
                nearest_gpus
                    .iter()
                    .filter_map(|d| {
                        if let Ok(idx) = d.index() {
                            Some(GpuIndex::Nvidia { nvml_id: idx })
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };

            // The NVML library doesn't return a PCIe bus ID compatible with sysfs. It includes
            // uppercase bus ID values and an extra four leading 0s.
            let bus_id = pci_info.bus_id.to_lowercase();
            let fixed_bus_id = bus_id.strip_prefix("0000").unwrap_or("");
            let numa_path = format!("/sys/bus/pci/devices/{}/numa_node", fixed_bus_id);
            let numa_node = read_from_file(Path::new(&numa_path)).unwrap_or(0_usize);

            let gpu = Gpu {
                index: GpuIndex::Nvidia { nvml_id: index },
                node_id: numa_node as usize,
                max_graphics_clock: graphics_boost_clock as usize,
                max_sm_clock: sm_boost_clock as usize,
                memory: memory_info.total,
                cpu_mask,
                nearest,
            };
            if !gpus.contains_key(&numa_node) {
                gpus.insert(numa_node, vec![gpu]);
                continue;
            }
            if let Some(gpus) = gpus.get_mut(&numa_node) {
                gpus.push(gpu);
            }
        }
    }

    gpus
}
