use serde::{Deserialize, Serialize};
use serde_json::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct VMConfig {
    pub vm_id: u64,
    pub vcpus: Vec<u64>,
}

pub fn parse_vm_config(json_data: &str) -> Result<Vec<VMConfig>> {
    let vm_configs: Vec<VMConfig> = serde_json::from_str(json_data)?;
    Ok(vm_configs)
}

pub fn allocate_cpus_to_vms(vm_configs: &[VMConfig], num_cpus: u32) -> Vec<u64> {
    let mut cpu_allocation = vec![0; num_cpus as usize]; // Initialize a vector of size num_cpus
    let total_vcpus: u32 = vm_configs.iter().map(|vm| vm.vcpus.len() as u32).sum(); // Calculate total vcpus

    let mut cpu_counter = 1;
    let usable_cpus = num_cpus - 1; // Reserve one CPU for the central CPU

    // Iterate through each VM and allocate CPUs proportional to its vcpu count
    for vm in vm_configs {
        // Calculate the proportion of CPUs to allocate for this VM
        let allocated_cpus =
            ((vm.vcpus.len() as f64 / total_vcpus as f64) * usable_cpus as f64).round() as u32;

        for _ in 0..allocated_cpus {
            if cpu_counter > usable_cpus {
                break; // Stop if we've exhausted the available CPUs
            }
            // Assign the current CPU (index) to the current VM (value)
            cpu_allocation[cpu_counter as usize] = vm.vm_id;
            cpu_counter += 1;
        }
    }

    cpu_allocation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_1() {
        // Scenario 1: Two VMs, one with 2 vCPUs and one with 4 vCPUs
        let config_json = r#"
        [
            {
                "vm_id": 1,
                "vcpus": [11,12]
            },
            {
                "vm_id": 2,
                "vcpus": [21,22,23,24]
            }
        ]
        "#;

        let vm_configs = parse_vm_config(config_json).unwrap();

        // Total system cores: 5
        let num_cpus: u32 = 5;

        // Expected CPU allocation should be proportional
        let expected_allocation = vec![0, 1, 2, 2, 2]; // 1 CPU to VM 1, 3 CPUs to VM 2

        // Perform CPU allocation
        let cpu_allocation = allocate_cpus_to_vms(&vm_configs, num_cpus);

        // Check if the allocation matches the expected values
        assert_eq!(cpu_allocation, expected_allocation);
    }

    #[test]
    fn test_scenario_2() {
        // Scenario 2: Two VMs, each with 4 vCPUs
        let config_json = r#"
        [
            {
                "vm_id": 1,
                "vcpus": [11,12,13,14]
            },
            {
                "vm_id": 2,
                "vcpus": [21,22,23,24]
            }
        ]
        "#;
        let vm_configs = parse_vm_config(config_json).unwrap();

        // Total system cores: 5
        let num_cpus: u32 = 5;

        // Expected allocation should be equal
        let expected_allocation = vec![0, 1, 1, 2, 2]; // 2 CPUs to VM 1, 2 CPUs to VM 2

        // Perform CPU allocation
        let cpu_allocation = allocate_cpus_to_vms(&vm_configs, num_cpus);

        // Check if the allocation matches the expected values
        assert_eq!(cpu_allocation, expected_allocation);
    }

    #[test]
    fn test_single_vm() {
        // Scenario 3: Single VM with 4 vCPUs
        let config_json = r#"
        [
            {
                "vm_id": 1,
                "vcpus": [11,12,13,14]
            }
        ]
        "#;

        let vm_configs = parse_vm_config(config_json).unwrap();

        // Total system cores: 5
        let num_cpus: u32 = 5;

        // Expected allocation: All 4 CPUs should go to the single VM
        let expected_allocation = vec![0, 1, 1, 1, 1]; // All CPUs to VM 1

        // Perform CPU allocation
        let cpu_allocation = allocate_cpus_to_vms(&vm_configs, num_cpus);

        // Check if the allocation matches the expected values
        assert_eq!(cpu_allocation, expected_allocation);
    }
}
