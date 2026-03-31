use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum AffinityMode {
    None,
    Fixed(BTreeSet<usize>),
    Random { from: BTreeSet<usize>, count: usize },
    SingleCpu(usize),
}

#[derive(Debug, Clone, Copy)]
pub enum WorkType {
    CpuSpin,
    YieldHeavy,
    Mixed,
    IoSync,
    /// Work hard for burst_ms, sleep for sleep_ms, repeat. Frees CPUs during sleep for borrowing.
    Bursty {
        burst_ms: u64,
        sleep_ms: u64,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum SchedPolicy {
    Normal,
    Batch,
    Idle,
    Fifo(u32),
    RoundRobin(u32),
}

#[derive(Debug, Clone)]
pub struct WorkloadConfig {
    pub num_workers: usize,
    pub affinity: AffinityMode,
    pub work_type: WorkType,
    pub sched_policy: SchedPolicy,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self {
            num_workers: 1,
            affinity: AffinityMode::None,
            work_type: WorkType::CpuSpin,
            sched_policy: SchedPolicy::Normal,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Migration {
    pub at_ns: u64,
    pub from_cpu: usize,
    pub to_cpu: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkerReport {
    pub tid: u32,
    pub work_units: u64,
    pub cpu_time_ns: u64,
    pub wall_time_ns: u64,
    pub runnable_ns: u64,
    pub migration_count: u64,
    pub cpus_used: BTreeSet<usize>,
    pub migrations: Vec<Migration>,
    /// Longest gap between work iterations (ms). High = task was stuck waiting for CPU.
    pub max_gap_ms: u64,
    /// CPU where the longest gap happened.
    pub max_gap_cpu: usize,
    /// When the longest gap happened (ms from start).
    pub max_gap_at_ms: u64,
}

/// PID of the scheduler process. Workers kill it on stall to trigger dump.
static SCHED_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// In repro mode, don't kill the scheduler on stall — keep it alive for assertions.
static REPRO_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_sched_pid(pid: u32) {
    SCHED_PID.store(pid as i32, std::sync::atomic::Ordering::Relaxed);
}

pub fn set_repro_mode(v: bool) {
    REPRO_MODE.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Handle to running worker processes (forked, not threads).
/// Each worker is a separate process so it can be in its own cgroup.
pub struct WorkloadHandle {
    children: Vec<(u32, std::os::unix::io::RawFd, std::os::unix::io::RawFd)>,
    started: bool,
}

impl WorkloadHandle {
    pub fn spawn(config: &WorkloadConfig) -> Result<Self> {
        let mut children = Vec::with_capacity(config.num_workers);

        for i in 0..config.num_workers {
            let affinity = resolve_affinity(&config.affinity, i)?;

            // Create pipe for report and a second pipe for "start" signal
            let mut report_fds = [0i32; 2];
            let mut start_fds = [0i32; 2];
            if unsafe { libc::pipe(report_fds.as_mut_ptr()) } != 0
                || unsafe { libc::pipe(start_fds.as_mut_ptr()) } != 0
            {
                anyhow::bail!("pipe failed: {}", std::io::Error::last_os_error());
            }

            let pid = unsafe { libc::fork() };
            match pid {
                -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
                0 => {
                    // Child: install signal handler FIRST (before start wait)
                    // to prevent SIGUSR1 killing us before we're ready
                    STOP.store(false, Ordering::Relaxed);
                    unsafe {
                        libc::signal(
                            libc::SIGUSR1,
                            sigusr1_handler as *const () as libc::sighandler_t,
                        );
                    }
                    // Close unused pipe ends
                    unsafe {
                        libc::close(report_fds[0]);
                        libc::close(start_fds[1]);
                    }
                    // Wait for parent to move us to cgroup before starting work
                    let mut buf = [0u8; 1];
                    let mut f = unsafe { std::fs::File::from_raw_fd(start_fds[0]) };
                    let _ = f.read_exact(&mut buf);
                    drop(f);
                    // Reset stop flag in case SIGUSR1 arrived during wait
                    STOP.store(false, Ordering::Relaxed);
                    // Now run
                    let report = worker_main(affinity, config.work_type, config.sched_policy);
                    let json = serde_json::to_vec(&report).unwrap_or_default();
                    let mut f = unsafe { std::fs::File::from_raw_fd(report_fds[1]) };
                    let _ = f.write_all(&json);
                    drop(f);
                    unsafe {
                        libc::_exit(0);
                    }
                }
                child_pid => {
                    // Parent: close unused pipe ends
                    unsafe {
                        libc::close(report_fds[1]);
                        libc::close(start_fds[0]);
                    }
                    children.push((child_pid as u32, report_fds[0], start_fds[1]));
                }
            }
        }

        Ok(Self {
            children,
            started: false,
        })
    }

    pub fn tids(&self) -> Vec<u32> {
        self.children.iter().map(|(pid, _, _)| *pid).collect()
    }

    /// Signal all children to start working (after they've been moved to cgroups).
    pub fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        for &(_, _, start_fd) in &self.children {
            unsafe {
                libc::write(start_fd, b"s".as_ptr() as *const _, 1);
                libc::close(start_fd);
            }
        }
    }

    pub fn set_affinity(&self, idx: usize, cpus: &BTreeSet<usize>) -> Result<()> {
        let (pid, _, _) = self.children[idx];
        set_thread_affinity(pid, cpus)
    }

    pub fn stop_and_collect(mut self) -> Vec<WorkerReport> {
        // Auto-start if not explicitly started (workers in parent cgroup)
        let was_started = self.started;
        self.start();

        // If we just started workers, give them time to begin before stopping
        if !was_started {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let mut reports = Vec::new();
        let children = std::mem::take(&mut self.children);

        // Signal all children to stop
        for &(pid, _, _) in &children {
            unsafe {
                libc::kill(pid as i32, libc::SIGUSR1);
            }
        }

        // Collect reports and wait for exit
        for (pid, read_fd, _) in children {
            let mut buf = Vec::new();
            let mut f = unsafe { std::fs::File::from_raw_fd(read_fd) };
            let _ = f.read_to_end(&mut buf);
            drop(f);

            // Wait for child
            let mut status = 0i32;
            unsafe {
                libc::waitpid(pid as i32, &mut status, 0);
            }

            if let Ok(report) = serde_json::from_slice::<WorkerReport>(&buf) {
                reports.push(report);
            }
        }

        reports
    }
}

impl Drop for WorkloadHandle {
    fn drop(&mut self) {
        for &(pid, rfd, wfd) in &self.children {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
                libc::waitpid(pid as i32, std::ptr::null_mut(), 0);
                libc::close(rfd);
                libc::close(wfd);
            }
        }
    }
}

use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

fn worker_main(
    affinity: Option<BTreeSet<usize>>,
    work_type: WorkType,
    sched_policy: SchedPolicy,
) -> WorkerReport {
    let tid = unsafe { libc::getpid() } as u32;

    if let Some(ref cpus) = affinity {
        let _ = set_thread_affinity(tid, cpus);
    }
    let _ = set_sched_policy(tid, sched_policy);

    let start = Instant::now();
    let mut work_units: u64 = 0;
    let mut migration_count: u64 = 0;
    let mut cpus_used = BTreeSet::new();
    let mut migrations = Vec::new();
    let mut last_cpu = sched_getcpu();
    cpus_used.insert(last_cpu);
    let mut last_iter_time = start;
    let mut max_gap_ns: u64 = 0;
    let mut max_gap_cpu: usize = last_cpu;
    let mut max_gap_at_ns: u64 = 0;

    while !STOP.load(Ordering::Relaxed) {
        match work_type {
            WorkType::CpuSpin => {
                for _ in 0..1024 {
                    work_units = work_units.wrapping_add(1);
                    std::hint::spin_loop();
                }
            }
            WorkType::YieldHeavy => {
                work_units = work_units.wrapping_add(1);
                std::thread::yield_now();
            }
            WorkType::Mixed => {
                for _ in 0..1024 {
                    work_units = work_units.wrapping_add(1);
                    std::hint::spin_loop();
                }
                std::thread::yield_now();
            }
            WorkType::IoSync => {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(format!("/tmp/stt_io_{tid}"))
                    .unwrap();
                let buf = [0u8; 4096];
                for _ in 0..16 {
                    let _ = f.write_all(&buf);
                    work_units = work_units.wrapping_add(1);
                }
                let _ = f.sync_all();
            }
            WorkType::Bursty { burst_ms, sleep_ms } => {
                let burst_end = Instant::now() + Duration::from_millis(burst_ms);
                while Instant::now() < burst_end && !STOP.load(Ordering::Relaxed) {
                    for _ in 0..1024 {
                        work_units = work_units.wrapping_add(1);
                        std::hint::spin_loop();
                    }
                }
                if !STOP.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(sleep_ms));
                }
            }
        }

        if work_units % 1024 == 0 {
            let now = Instant::now();
            let gap = now.duration_since(last_iter_time).as_nanos() as u64;
            if gap > max_gap_ns {
                max_gap_ns = gap;
                max_gap_cpu = last_cpu;
                max_gap_at_ns = now.duration_since(start).as_nanos() as u64;
            }
            // If stuck >2s and not in repro mode, send SIGUSR2 to the
            // scheduler to trigger scx_bpf_error in ops.tick. In repro
            // mode, keep it alive for assertion scripts.
            if gap > 2_000_000_000 && !REPRO_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                let pid = SCHED_PID.load(std::sync::atomic::Ordering::Relaxed);
                if pid > 0 {
                    unsafe { libc::kill(pid, libc::SIGUSR2) };
                }
            }
            last_iter_time = now;

            let cpu = sched_getcpu();
            if cpu != last_cpu {
                migration_count += 1;
                cpus_used.insert(cpu);
                migrations.push(Migration {
                    at_ns: start.elapsed().as_nanos() as u64,
                    from_cpu: last_cpu,
                    to_cpu: cpu,
                });
                last_cpu = cpu;
            }
        }
    }

    let wall_time = start.elapsed();
    let cpu_time_ns = thread_cpu_time_ns();
    let wall_time_ns = wall_time.as_nanos() as u64;

    WorkerReport {
        tid,
        work_units,
        cpu_time_ns,
        wall_time_ns,
        runnable_ns: wall_time_ns.saturating_sub(cpu_time_ns),
        migration_count,
        cpus_used,
        migrations,
        max_gap_ms: max_gap_ns / 1_000_000,
        max_gap_cpu,
        max_gap_at_ms: max_gap_at_ns / 1_000_000,
    }
}

extern "C" fn sigusr1_handler(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn resolve_affinity(mode: &AffinityMode, _idx: usize) -> Result<Option<BTreeSet<usize>>> {
    match mode {
        AffinityMode::None => Ok(None),
        AffinityMode::Fixed(cpus) => Ok(Some(cpus.clone())),
        AffinityMode::SingleCpu(cpu) => Ok(Some([*cpu].into_iter().collect())),
        AffinityMode::Random { from, count } => {
            use rand::seq::SliceRandom;
            let pool: Vec<usize> = from.iter().copied().collect();
            let count = (*count).min(pool.len()).max(1);
            Ok(Some(
                pool.choose_multiple(&mut rand::thread_rng(), count)
                    .copied()
                    .collect(),
            ))
        }
    }
}

fn sched_getcpu() -> usize {
    unsafe { libc::sched_getcpu() as usize }
}

fn thread_cpu_time_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn set_sched_policy(pid: u32, policy: SchedPolicy) -> Result<()> {
    let (pol, prio) = match policy {
        SchedPolicy::Normal => return Ok(()),
        SchedPolicy::Batch => (libc::SCHED_BATCH, 0),
        SchedPolicy::Idle => (libc::SCHED_IDLE, 0),
        SchedPolicy::Fifo(p) => (libc::SCHED_FIFO, p.clamp(1, 99) as i32),
        SchedPolicy::RoundRobin(p) => (libc::SCHED_RR, p.clamp(1, 99) as i32),
    };
    let param = libc::sched_param {
        sched_priority: prio,
    };
    if unsafe { libc::sched_setscheduler(pid as i32, pol, &param) } != 0 {
        anyhow::bail!("sched_setscheduler: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_thread_affinity(pid: u32, cpus: &BTreeSet<usize>) -> Result<()> {
    use nix::sched::{sched_setaffinity, CpuSet};
    use nix::unistd::Pid;
    let mut cpu_set = CpuSet::new();
    for &cpu in cpus {
        cpu_set
            .set(cpu)
            .with_context(|| format!("CPU {cpu} out of range"))?;
    }
    sched_setaffinity(Pid::from_raw(pid as i32), &cpu_set)
        .with_context(|| format!("sched_setaffinity pid={pid}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_affinity_none() {
        let r = resolve_affinity(&AffinityMode::None, 0).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_affinity_fixed() {
        let cpus: BTreeSet<usize> = [0, 1, 2].into_iter().collect();
        let r = resolve_affinity(&AffinityMode::Fixed(cpus.clone()), 0).unwrap();
        assert_eq!(r, Some(cpus));
    }

    #[test]
    fn resolve_affinity_single_cpu() {
        let r = resolve_affinity(&AffinityMode::SingleCpu(5), 0).unwrap();
        assert_eq!(r, Some([5].into_iter().collect()));
    }

    #[test]
    fn resolve_affinity_random() {
        let from: BTreeSet<usize> = (0..8).collect();
        let r = resolve_affinity(&AffinityMode::Random { from, count: 3 }, 0).unwrap();
        let cpus = r.unwrap();
        assert_eq!(cpus.len(), 3);
        assert!(cpus.iter().all(|c| *c < 8));
    }

    #[test]
    fn resolve_affinity_random_clamps_count() {
        let from: BTreeSet<usize> = [0, 1].into_iter().collect();
        let r = resolve_affinity(&AffinityMode::Random { from, count: 10 }, 0).unwrap();
        assert_eq!(r.unwrap().len(), 2);
    }

    #[test]
    fn workload_config_default() {
        let c = WorkloadConfig::default();
        assert_eq!(c.num_workers, 1);
        assert!(matches!(c.work_type, WorkType::CpuSpin));
        assert!(matches!(c.sched_policy, SchedPolicy::Normal));
        assert!(matches!(c.affinity, AffinityMode::None));
    }

    #[test]
    fn worker_report_serde_roundtrip() {
        let r = WorkerReport {
            tid: 42,
            work_units: 1000,
            cpu_time_ns: 5_000_000_000,
            wall_time_ns: 10_000_000_000,
            runnable_ns: 5_000_000_000,
            migration_count: 3,
            cpus_used: [0, 1, 2].into_iter().collect(),
            migrations: vec![Migration {
                at_ns: 100,
                from_cpu: 0,
                to_cpu: 1,
            }],
            max_gap_ms: 50,
            max_gap_cpu: 1,
            max_gap_at_ms: 500,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: WorkerReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r.tid, r2.tid);
        assert_eq!(r.work_units, r2.work_units);
        assert_eq!(r.migration_count, r2.migration_count);
        assert_eq!(r.cpus_used, r2.cpus_used);
        assert_eq!(r.max_gap_ms, r2.max_gap_ms);
    }

    #[test]
    fn migration_serde() {
        let m = Migration {
            at_ns: 12345,
            from_cpu: 0,
            to_cpu: 3,
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: Migration = serde_json::from_str(&json).unwrap();
        assert_eq!(m.at_ns, m2.at_ns);
        assert_eq!(m.from_cpu, m2.from_cpu);
        assert_eq!(m.to_cpu, m2.to_cpu);
    }

    #[test]
    fn spawn_start_collect_integration() {
        let config = WorkloadConfig {
            num_workers: 2,
            affinity: AffinityMode::None,
            work_type: WorkType::CpuSpin,
            sched_policy: SchedPolicy::Normal,
        };
        let mut h = WorkloadHandle::spawn(&config).unwrap();
        assert_eq!(h.tids().len(), 2);
        h.start();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let reports = h.stop_and_collect();
        assert_eq!(reports.len(), 2);
        for r in &reports {
            assert!(r.work_units > 0, "worker {} did no work", r.tid);
            assert!(r.wall_time_ns > 0);
            assert!(!r.cpus_used.is_empty());
        }
    }

    #[test]
    fn spawn_auto_start_on_collect() {
        let config = WorkloadConfig {
            num_workers: 1,
            affinity: AffinityMode::None,
            work_type: WorkType::CpuSpin,
            sched_policy: SchedPolicy::Normal,
        };
        let h = WorkloadHandle::spawn(&config).unwrap();
        // Don't call start() - collect should auto-start
        let reports = h.stop_and_collect();
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn spawn_yield_heavy_produces_work() {
        let config = WorkloadConfig {
            num_workers: 1,
            affinity: AffinityMode::None,
            work_type: WorkType::YieldHeavy,
            sched_policy: SchedPolicy::Normal,
        };
        let mut h = WorkloadHandle::spawn(&config).unwrap();
        h.start();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let reports = h.stop_and_collect();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].work_units > 0);
    }

    #[test]
    fn spawn_mixed_produces_work() {
        let config = WorkloadConfig {
            num_workers: 1,
            affinity: AffinityMode::None,
            work_type: WorkType::Mixed,
            sched_policy: SchedPolicy::Normal,
        };
        let mut h = WorkloadHandle::spawn(&config).unwrap();
        h.start();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let reports = h.stop_and_collect();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].work_units > 0);
    }

    #[test]
    fn spawn_multiple_workers_distinct_pids() {
        let config = WorkloadConfig {
            num_workers: 4,
            affinity: AffinityMode::None,
            work_type: WorkType::CpuSpin,
            sched_policy: SchedPolicy::Normal,
        };
        let h = WorkloadHandle::spawn(&config).unwrap();
        let tids = h.tids();
        assert_eq!(tids.len(), 4);
        let unique: std::collections::HashSet<u32> = tids.iter().copied().collect();
        assert_eq!(unique.len(), 4, "all worker PIDs should be distinct");
        let reports = h.stop_and_collect();
        assert_eq!(reports.len(), 4);
    }

    #[test]
    fn spawn_with_fixed_affinity() {
        let config = WorkloadConfig {
            num_workers: 1,
            affinity: AffinityMode::Fixed([0].into_iter().collect()),
            work_type: WorkType::CpuSpin,
            sched_policy: SchedPolicy::Normal,
        };
        let mut h = WorkloadHandle::spawn(&config).unwrap();
        h.start();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let reports = h.stop_and_collect();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].cpus_used.contains(&0));
        assert_eq!(reports[0].cpus_used.len(), 1, "should only use pinned CPU");
    }

    #[test]
    fn drop_kills_children() {
        let config = WorkloadConfig {
            num_workers: 2,
            ..Default::default()
        };
        let h = WorkloadHandle::spawn(&config).unwrap();
        let pids = h.tids();
        drop(h);
        // After drop, children should be dead
        for pid in pids {
            let alive = unsafe { libc::kill(pid as i32, 0) } == 0;
            assert!(!alive, "child {} should be dead after drop", pid);
        }
    }
}
