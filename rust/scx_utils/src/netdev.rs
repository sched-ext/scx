// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::misc::read_from_file;
use crate::Cpumask;
use anyhow::Result;

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetDev {
    iface: String,
    node: usize,
    pub irqs: BTreeMap<usize, Cpumask>,
    irq_hints: BTreeMap<usize, Cpumask>,
}

impl NetDev {
    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn node(&self) -> usize {
        self.node
    }

    pub fn irq_hints(&self) -> &BTreeMap<usize, Cpumask> {
        &self.irq_hints
    }

    pub fn update_irq_cpumask(&mut self, irq: usize, cpumask: Cpumask) {
        if let Some(cur_cpumask) = self.irqs.get_mut(&irq) {
            *cur_cpumask = cpumask;
        }
    }

    pub fn apply_cpumasks(&self) -> Result<()> {
        for (irq, cpumask) in self.irqs.iter() {
            let irq_path = format!("/proc/irq/{irq}/smp_affinity");
            fs::write(irq_path, format!("{cpumask:#x}"))?
        }
        Ok(())
    }
}

pub fn read_netdevs() -> Result<BTreeMap<String, NetDev>> {
    let mut netdevs: BTreeMap<String, NetDev> = BTreeMap::new();

    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let iface = entry.file_name().to_string_lossy().into_owned();
        let iface_path_raw = format!("/sys/class/net/{iface}/device/enable");
        let iface_path = Path::new(&iface_path_raw);
        let is_enabled = read_from_file(iface_path).unwrap_or(0_usize);
        if is_enabled < 1 {
            continue;
        }
        let raw_path = format!("/sys/class/net/{iface}/device/msi_irqs");
        let msi_irqs_path = Path::new(&raw_path);
        if !msi_irqs_path.exists() {
            continue;
        }

        let node_path_raw = format!("/sys/class/net/{iface}/device/numa_node");
        let node_path = Path::new(&node_path_raw);
        let node = read_from_file(node_path).unwrap_or(0_usize);
        let mut irqs = BTreeMap::new();
        let mut irq_hints = BTreeMap::new();

        for entry in fs::read_dir(msi_irqs_path)? {
            let entry = entry.unwrap();
            let irq = entry.file_name().to_string_lossy().into_owned();
            if let Ok(irq) = irq.parse::<usize>() {
                let irq_path_raw = format!("/proc/irq/{irq}");
                let irq_path = Path::new(&irq_path_raw);
                if !irq_path.exists() {
                    continue;
                }
                let affinity_raw_path = format!("/proc/irq/{irq}/smp_affinity");
                let smp_affinity_path = Path::new(&affinity_raw_path);
                let smp_affinity = fs::read_to_string(smp_affinity_path)?
                    .replace(",", "")
                    .replace("\n", "");
                let cpumask = Cpumask::from_str(&smp_affinity)?;
                irqs.insert(irq, cpumask);

                // affinity hints
                let affinity_hint_raw_path = format!("/proc/irq/{irq}/affinity_hint");
                let affinity_hint_path = Path::new(&affinity_hint_raw_path);
                let affinity_hint = fs::read_to_string(affinity_hint_path)?
                    .replace(",", "")
                    .replace("\n", "");
                let hint_cpumask = Cpumask::from_str(&affinity_hint)?;
                irq_hints.insert(irq, hint_cpumask);
            }
        }
        netdevs.insert(
            iface.clone(),
            NetDev {
                iface,
                node,
                irqs,
                irq_hints,
            },
        );
    }
    Ok(netdevs)
}
