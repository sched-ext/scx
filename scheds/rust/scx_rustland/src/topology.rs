// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::HashMap;
use std::fs;

/// scx_rustland: CPU topology.
///
/// CoreMapping provides a map of the CPU topology, with the list of CPU ids in the system grouped
/// by their corresponding core id.
///
/// The CPU / core mapping is stored in a HashMap using the core ID as the key. An example content
/// of the HashMap can be the following:
///
///  core 0: [4, 0]
///  core 1: [5, 1]
///  core 2: [6, 2]
///  core 3: [7, 3]
///
/// This information can be used by the scheduler to apply a more efficient scheduling policy, for
/// example dispatching tasks on the CPUs that have all the siblings idle first, and later move to
/// the CPUs with busy siblings.

const CPU_PATH: &str = "/sys/devices/system/cpu";

pub struct CoreMapping {
    // Map of core IDs -> list of CPU ids.
    //
    // NOTE: we must periodically refresh this map if we want to support CPU hotplugging, for now
    // let's assume it's static.
    pub map: HashMap<i32, Vec<i32>>,

    // Number of available CPUs in the system.
    //
    // NOTE: we must periodically refresh this value if we want to support CPU hotplugging, for now
    // let's assume it's static.
    pub nr_cpus_online: i32,
}

impl CoreMapping {
    pub fn new() -> Self {
        let mut core_mapping = CoreMapping {
            map: HashMap::new(),
            nr_cpus_online: 0,
        };
        core_mapping.init_mapping();

        core_mapping
    }

    // Evaluate the amount of available CPUs in the system.
    // Initialize the core ids -> CPU ids HashMap, parsing all the information from
    // /sys/devices/system/cpu/cpu<id>/topology/core_id.
    fn init_mapping(&mut self) {
        let cpu_entries: Vec<_> = fs::read_dir(CPU_PATH)
            .expect(format!("Failed to read: {}", CPU_PATH).as_str())
            .filter_map(|entry| entry.ok())
            .collect();

        // Generate core map.
        for entry in cpu_entries {
            let entry_path = entry.path();
            let cpu_name = entry.file_name();
            let cpu_id_str = cpu_name.to_string_lossy().to_string();
            if cpu_id_str.starts_with("cpu") {
                if let Some(cpu_id) = cpu_id_str.chars().skip(3).collect::<String>().parse().ok() {
                    let core_id_path = entry_path.join("topology/core_id");
                    if let Some(core_id) = fs::read_to_string(&core_id_path)
                        .ok()
                        .and_then(|content| content.trim().parse().ok())
                    {
                        // Add CPU id to the core map.
                        self.map.entry(core_id).or_insert(Vec::new()).push(cpu_id);

                        // Update total CPU ids counter.
                        self.nr_cpus_online += 1;
                    }
                }
            }
        }
    }
}
