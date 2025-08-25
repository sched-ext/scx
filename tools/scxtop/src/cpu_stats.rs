use anyhow::Result;
use procfs::{CpuTime, KernelStats};
use std::collections::BTreeMap;
use sysinfo::System;

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

impl From<&CpuTime> for CpuUtilData {
    fn from(stat: &CpuTime) -> Self {
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
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuStatSnapshot {
    pub cpu_util_data: CpuUtilData,
    pub freq_khz: u64,
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuStatTracker {
    pub system_prev: CpuStatSnapshot,
    pub system_current: CpuStatSnapshot,
    pub prev: BTreeMap<usize, CpuStatSnapshot>,
    pub current: BTreeMap<usize, CpuStatSnapshot>,
}

impl CpuStatTracker {
    /// Update CPU statistics, reading frequency data from sysinfo
    /// Note: The System reference should have CPU frequencies refreshed externally
    /// by a background thread to avoid blocking the main loop
    pub fn update(&mut self, sys: &mut System) -> Result<()> {
        self.prev = std::mem::take(&mut self.current);
        self.system_prev = std::mem::take(&mut self.system_current);

        let kernel_stats = KernelStats::new()?;
        let cpu_stat_data = kernel_stats.cpu_time;

        // Read CPU frequencies from sysinfo (should be refreshed by background thread)
        let mut total_freq_khz = 0;
        for (i, cpu) in sys.cpus().iter().enumerate() {
            if let Some(cpu_time) = cpu_stat_data.get(i) {
                let freq_khz = cpu.frequency();
                total_freq_khz += freq_khz;
                let snapshot = CpuStatSnapshot {
                    cpu_util_data: cpu_time.into(),
                    freq_khz,
                };
                self.current.insert(i, snapshot);
            }
        }

        self.system_current = CpuStatSnapshot {
            cpu_util_data: (&kernel_stats.total).into(),
            freq_khz: total_freq_khz,
        };

        Ok(())
    }

    pub fn system_active_util(&self) -> u64 {
        self.system_current.cpu_util_data.active_util()
            - self.system_prev.cpu_util_data.active_util()
    }

    pub fn system_total_util(&self) -> u64 {
        self.system_current.cpu_util_data.total_util() - self.system_prev.cpu_util_data.total_util()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_convert_to_stat_snapshot_success() {
        let kernel_stats = KernelStats::new().unwrap();
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

        let snapshot: CpuUtilData = (&cpu_time).into();

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
        let kernel_stats = KernelStats::new().unwrap();
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

        let _: CpuUtilData = (&cpu_time).into();
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
    fn test_system_active_total() -> Result<()> {
        let mut tracker = CpuStatTracker::default();
        assert_eq!(tracker.system_active_util(), 0);
        assert_eq!(tracker.system_total_util(), 0);

        let sys = Arc::new(Mutex::new(System::new_all()));
        let mut sys_guard = sys.lock().unwrap();
        tracker.update(&mut sys_guard)?;

        assert!(tracker.system_active_util() > 0);
        assert!(tracker.system_total_util() > 0);

        Ok(())
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
