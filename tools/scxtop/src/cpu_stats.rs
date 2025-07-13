use anyhow::{bail, Result};
use fb_procfs::ProcReader;
use std::collections::BTreeMap;
use sysinfo::System;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuUtilData {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

impl CpuUtilData {
    pub fn total_util(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    pub fn active_util(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuStatSnapshot {
    pub cpu_util_data: CpuUtilData,
    pub freq_khz: u64,
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuStatTracker {
    pub prev: BTreeMap<usize, CpuStatSnapshot>,
    pub current: BTreeMap<usize, CpuStatSnapshot>,
}

impl CpuStatTracker {
    pub fn update(&mut self, proc_reader: &ProcReader, sys: &mut System) -> Result<()> {
        self.prev = std::mem::take(&mut self.current);

        let proc_stat_data = proc_reader.read_stat()?;
        sys.refresh_cpu_frequency();

        if let Some(mut cpu_map) = proc_stat_data.cpus_map {
            for (i, cpu) in sys.cpus().iter().enumerate() {
                let cpu_util_data = procfs_cpu_to_util_data(
                    cpu_map
                        .remove(&(i as u32))
                        .expect("Cpu should exist in cpu map data"),
                );
                let snapshot = CpuStatSnapshot {
                    cpu_util_data,
                    freq_khz: cpu.frequency(),
                };
                self.current.insert(i, snapshot);
            }
        } else {
            bail!("Failed to parse cpu stats from /proc/stat");
        }

        Ok(())
    }
}

fn procfs_cpu_to_util_data(stat: fb_procfs::CpuStat) -> CpuUtilData {
    CpuUtilData {
        user: stat.user_usec.expect("missing user"),
        nice: stat.nice_usec.expect("missing nice"),
        system: stat.system_usec.expect("missing system"),
        idle: stat.idle_usec.expect("missing idle"),
        iowait: stat.iowait_usec.expect("missing iowait"),
        irq: stat.irq_usec.expect("missing irq"),
        softirq: stat.softirq_usec.expect("missing softirq"),
        steal: stat.stolen_usec.expect("missing steal"),
        guest: stat.guest_usec.expect("missing guest"),
        guest_nice: stat.guest_nice_usec.expect("missing guest_nice"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_convert_to_stat_snapshot_success() {
        let input = fb_procfs::CpuStat {
            user_usec: Some(100),
            nice_usec: Some(200),
            system_usec: Some(300),
            idle_usec: Some(400),
            iowait_usec: Some(500),
            irq_usec: Some(600),
            softirq_usec: Some(700),
            stolen_usec: Some(800),
            guest_usec: Some(900),
            guest_nice_usec: Some(1000),
        };

        let snapshot = procfs_cpu_to_util_data(input);

        assert_eq!(snapshot.user, 100);
        assert_eq!(snapshot.nice, 200);
        assert_eq!(snapshot.system, 300);
        assert_eq!(snapshot.idle, 400);
        assert_eq!(snapshot.iowait, 500);
        assert_eq!(snapshot.irq, 600);
        assert_eq!(snapshot.softirq, 700);
        assert_eq!(snapshot.steal, 800);
        assert_eq!(snapshot.guest, 900);
        assert_eq!(snapshot.guest_nice, 1000);
    }

    #[test]
    #[should_panic(expected = "missing user")]
    fn test_convert_to_stat_snapshot_missing_user_panics() {
        let input = fb_procfs::CpuStat {
            user_usec: None, // <- this will trigger the panic
            nice_usec: Some(200),
            system_usec: Some(300),
            idle_usec: Some(400),
            iowait_usec: Some(500),
            irq_usec: Some(600),
            softirq_usec: Some(700),
            stolen_usec: Some(800),
            guest_usec: Some(900),
            guest_nice_usec: Some(1000),
        };

        let _ = procfs_cpu_to_util_data(input);
    }

    #[test]
    fn test_snapshot_totals() {
        let snap = CpuUtilData {
            user: 1,
            nice: 2,
            system: 3,
            idle: 4,
            iowait: 5,
            irq: 6,
            softirq: 7,
            steal: 8,
            guest: 0,
            guest_nice: 0,
        };

        assert_eq!(snap.total_util(), 36);
        assert_eq!(snap.active_util(), 27);
    }

    #[test]
    fn test_read_proc_stat_cpu_lines_real_system() -> Result<()> {
        let proc_reader = ProcReader::default();
        let proc_fs_data = proc_reader.read_stat();

        assert!(proc_fs_data.is_ok());

        if let Ok(proc_fs_data) = proc_fs_data {
            if let Some(cpu_map) = proc_fs_data.cpus_map {
                for (_, stat) in cpu_map {
                    assert!(stat.user_usec.is_some());
                    assert!(stat.nice_usec.is_some());
                    assert!(stat.system_usec.is_some());
                    assert!(stat.idle_usec.is_some());
                    assert!(stat.iowait_usec.is_some());
                    assert!(stat.irq_usec.is_some());
                    assert!(stat.softirq_usec.is_some());
                    assert!(stat.stolen_usec.is_some());
                    assert!(stat.guest_usec.is_some());
                    assert!(stat.guest_nice_usec.is_some());
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_integration_test() -> Result<()> {
        let mut tracker = CpuStatTracker::default();
        let proc_reader = ProcReader::default();
        let sys = Arc::new(Mutex::new(System::new_all()));
        let mut sys_guard = sys.lock().unwrap();
        tracker.update(&proc_reader, &mut sys_guard)?;

        std::thread::sleep(std::time::Duration::from_secs(1));

        tracker.update(&proc_reader, &mut *sys_guard)?;

        assert!(!tracker.prev.is_empty());
        assert!(!tracker.current.is_empty());

        for (cpu, prev) in &tracker.prev {
            let current = tracker.current.get(cpu).unwrap();
            assert!(current.cpu_util_data.total_util() >= prev.cpu_util_data.total_util());
            assert!(current.cpu_util_data.active_util() >= prev.cpu_util_data.active_util());
        }

        Ok(())
    }
}
