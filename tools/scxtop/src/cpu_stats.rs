use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

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
    pub fn update(&mut self) -> Result<()> {
        let lines = read_proc_stat_cpu_lines()?;

        self.prev = std::mem::take(&mut self.current);

        for line in lines {
            if let Some((cpu, snapshot)) = parse_cpu_stat_line(&line) {
                self.current.insert(cpu, snapshot);
            } else {
                bail!("Failed to parse line from /proc/stat: {:?}", line);
            }
        }

        Ok(())
    }
}

fn read_proc_stat_cpu_lines() -> Result<Vec<String>> {
    let file = File::open("/proc/stat").expect("Failed to open /proc/stat");
    let reader = BufReader::new(file);

    let lines = reader
        .lines()
        .map_while(Result::ok)
        .skip(1)
        .filter(|l| l.starts_with("cpu"))
        .map(|l| l.trim().to_string())
        .collect();

    Ok(lines)
}

fn parse_cpu_stat_line(line: &str) -> Option<(usize, CpuStatSnapshot)> {
    let parts: Vec<u64> = line
        .strip_prefix("cpu")?
        .split_whitespace()
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();

    if parts.len() < 11 {
        return None;
    }

    Some((
        parts[0] as usize,
        CpuStatSnapshot {
            user: parts[1],
            nice: parts[2],
            system: parts[3],
            idle: parts[4],
            iowait: parts[5],
            irq: parts[6],
            softirq: parts[7],
            steal: parts[8],
            guest: parts[9],
            guest_nice: parts[10],
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_stat_line_valid() {
        let line = "cpu0 100 200 300 400 500 600 700 800 900 1000 1100";
        let result = parse_cpu_stat_line(&line);
        assert!(result.is_some());

        let (cpu, snapshot) = result.unwrap();
        assert_eq!(cpu, 0);
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
    fn test_parse_cpu_stat_line_invalid() {
        let line = "cpu0 100 200";
        let result = parse_cpu_stat_line(line);
        assert!(result.is_none());

        let line = "0 100 200 300 400 500 600 700 800 900 1000 1100";
        let result = parse_cpu_stat_line(line);
        assert!(result.is_none());
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
        let lines = read_proc_stat_cpu_lines()?;

        assert!(!lines.is_empty());

        for line in &lines {
            let parsed = parse_cpu_stat_line(line);
            assert!(parsed.is_some(), "Failed to parse line: {:?}", line);
        }

        Ok(())
    }

    #[test]
    fn test_integration_test() -> Result<()> {
        let mut tracker = CpuStatTracker::new();
        tracker.update()?;

        std::thread::sleep(std::time::Duration::from_secs(1));

        tracker.update()?;

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
