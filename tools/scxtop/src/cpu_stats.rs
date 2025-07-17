use anyhow::Result;
use procfs::{CpuTime, CurrentSI, KernelStats};
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
    pub fn update(&mut self, sys: &mut System) -> Result<()> {
        self.prev = std::mem::take(&mut self.current);

        let kernel_stats = KernelStats::current()?;
        let cpu_stat_data = kernel_stats.cpu_time;
        sys.refresh_cpu_frequency();

        for (i, cpu) in sys.cpus().iter().enumerate() {
            if let Some(cpu_time) = cpu_stat_data.get(i) {
                let cpu_util_data = procfs_cpu_to_util_data(cpu_time);
                let snapshot = CpuStatSnapshot {
                    cpu_util_data,
                    freq_khz: cpu.frequency(),
                };
                self.current.insert(i, snapshot);
            }
        }

        Ok(())
    }
}

fn procfs_cpu_to_util_data(stat: &CpuTime) -> CpuUtilData {
    CpuUtilData {
        user: stat.user,
        nice: stat.nice,
        system: stat.system,
        idle: stat.idle,
        iowait: stat.iowait.expect("missing iowait"),
        irq: stat.irq.expect("missing irq"),
        softirq: stat.softirq.expect("missing softirq"),
        steal: stat.steal.expect("missing steal"),
        guest: stat.guest.expect("missing guest"),
        guest_nice: stat.guest_nice.expect("missing guest_nice"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_convert_to_stat_snapshot_success() {
        let kernel_stats = KernelStats::current().unwrap();
        let mut cpu_time = kernel_stats.total;

        // We'll just take over the cpu_time in order to test it
        cpu_time.user = 100;
        cpu_time.nice = 200;
        cpu_time.system = 300;
        cpu_time.idle = 400;
        cpu_time.iowait = Some(500);
        cpu_time.irq = Some(600);
        cpu_time.softirq = Some(700);
        cpu_time.steal = Some(800);
        cpu_time.guest = Some(900);
        cpu_time.guest_nice = Some(1000);

        let snapshot = procfs_cpu_to_util_data(&cpu_time);

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
    #[should_panic(expected = "missing iowait")]
    fn test_convert_to_stat_snapshot_missing_iowait_panics() {
        let kernel_stats = KernelStats::current().unwrap();
        let mut cpu_time = kernel_stats.total;

        // We'll just take over the cpu_time in order to test it
        cpu_time.user = 100;
        cpu_time.nice = 200;
        cpu_time.system = 300;
        cpu_time.idle = 400;
        cpu_time.iowait = None; // <- this should cause a panic
        cpu_time.irq = Some(600);
        cpu_time.softirq = Some(700);
        cpu_time.steal = Some(800);
        cpu_time.guest = Some(900);
        cpu_time.guest_nice = Some(1000);

        let _ = procfs_cpu_to_util_data(&cpu_time);
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
    fn test_integration_test() -> Result<()> {
        let mut tracker = CpuStatTracker::default();
        let sys = Arc::new(Mutex::new(System::new_all()));
        let mut sys_guard = sys.lock().unwrap();
        tracker.update(&mut sys_guard)?;

        std::thread::sleep(std::time::Duration::from_secs(1));

        tracker.update(&mut sys_guard)?;

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
