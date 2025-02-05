#![cfg(feature = "gpu-topology")]

use crate::misc::read_file_usize;
use crate::{Cpumask, NR_CPU_IDS};
use nvml_wrapper::bitmasks::InitFlags;
use nvml_wrapper::enum_wrappers::device::Clock;
use nvml_wrapper::error::{nvml_sym, nvml_try};
use nvml_wrapper::Nvml;
use nvml_wrapper_sys::bindings::{nvmlDeviceAttributes_t, NvmlLib};
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
    // Max Streaming Multiprocessors supported
    pub multiproc_count: u32,
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

            // FIXME: maybe update nvml-wrapper so it wraps this binding and not
            // loading twice NVML ?
            let multiproc_count;
            unsafe {
                let mut attrs: nvmlDeviceAttributes_t = std::mem::zeroed();
                let lib: NvmlLib = NvmlLib::new("libnvidia-ml.so").unwrap();
                let nvml_device_get_attributes_v2 =
                    nvml_sym(lib.nvmlDeviceGetAttributes_v2.as_ref()).unwrap();
                // Allows for workload estimate/distribution, some other attributes
                // are either redundant or not useful for here (except gpuInstanceSliceCount ?)
                multiproc_count = match nvml_try(nvml_device_get_attributes_v2(
                    nvidia_gpu.handle(),
                    &mut attrs,
                )) {
                    Ok(()) => attrs.multiprocessorCount,
                    _ => 0,
                };
            }

            // The NVML library doesn't return a PCIe bus ID compatible with sysfs. It includes
            // uppercase bus ID values and an extra four leading 0s.
            let bus_id = pci_info.bus_id.to_lowercase();
            let fixed_bus_id = bus_id.strip_prefix("0000").unwrap_or("");
            let numa_path = format!("/sys/bus/pci/devices/{}/numa_node", fixed_bus_id);
            let numa_node = read_file_usize(&Path::new(&numa_path)).unwrap_or(0);

            let gpu = Gpu {
                index: GpuIndex::Nvidia { nvml_id: index },
                node_id: numa_node as usize,
                max_graphics_clock: graphics_boost_clock as usize,
                max_sm_clock: sm_boost_clock as usize,
                memory: memory_info.total,
                cpu_mask,
                multiproc_count,
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
