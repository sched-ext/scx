use anyhow::Result;
use fb_procfs::ProcReader;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct CpuStatSnapshot {
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

impl CpuStatSnapshot {
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    pub fn active(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }
}

#[derive(Default, Debug, Clone)]
pub struct CpuStatTracker {
    pub prev: BTreeMap<usize, CpuStatSnapshot>,
    pub current: BTreeMap<usize, CpuStatSnapshot>,
}

impl CpuStatTracker {
    pub fn update(&mut self, proc_reader: &ProcReader) -> Result<()> {
        self.prev = std::mem::take(&mut self.current);

        let proc_stat_data = proc_reader.read_stat()?;

        if let Some(cpu_map) = proc_stat_data.cpus_map {
            for (cpu, stat) in cpu_map {
                let snapshot = procfs_cpu_to_stat_snapshot(stat);
                self.current.insert(cpu as usize, snapshot);
            }
        } else {
            bail!("Failed to parse cpu stats from /proc/stat");
        }

        Ok(())
    }
}

fn procfs_cpu_to_stat_snapshot(stat: fb_procfs::CpuStat) -> CpuStatSnapshot {
    CpuStatSnapshot {
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

        let snapshot = procfs_cpu_to_stat_snapshot(input);

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

        let _ = procfs_cpu_to_stat_snapshot(input);
    }

    #[test]
    fn test_snapshot_totals() {
        let snap = CpuStatSnapshot {
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

        assert_eq!(snap.total(), 36);
        assert_eq!(snap.active(), 27);
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
        tracker.update(&proc_reader)?;

        std::thread::sleep(std::time::Duration::from_secs(1));

        tracker.update(&proc_reader)?;

        assert!(!tracker.prev.is_empty());
        assert!(!tracker.current.is_empty());

        for (cpu, prev) in &tracker.prev {
            let current = tracker.current.get(cpu).unwrap();
            assert!(current.total() >= prev.total());
            assert!(current.active() >= prev.active());
        }

        Ok(())
    }
}
