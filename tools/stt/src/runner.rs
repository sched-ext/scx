use anyhow::{bail, Context, Result};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::cgroup::CgroupManager;
use crate::scenario::{self, Ctx, Flag, FlagProfile, Scenario};
use crate::topology::TestTopology;
use crate::verify::ScenarioStats;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub mitosis_bin: String,
    pub parent_cgroup: String,
    pub duration_s: u64,
    pub workers_per_cell: usize,
    pub json: bool,
    pub verbose: bool,
    pub active_flags: Option<Vec<Flag>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScenarioResult {
    pub scenario_name: String,
    pub passed: bool,
    pub duration_s: f64,
    pub details: Vec<String>,
    #[serde(default)]
    pub stats: ScenarioStats,
}

pub struct Runner {
    pub config: RunConfig,
    pub topo: TestTopology,
}

impl Runner {
    pub fn new(config: RunConfig, topo: TestTopology) -> Result<Self> {
        Ok(Self { config, topo })
    }

    pub fn run_scenarios(&self, scenarios: &[&Scenario]) -> Result<Vec<ScenarioResult>> {
        let mut runs: Vec<(&Scenario, FlagProfile)> = Vec::new();
        for s in scenarios {
            let profiles = match &self.config.active_flags {
                None => s.profiles(),
                Some(flags) => s.profiles_with(flags),
            };
            for p in profiles {
                runs.push((s, p));
            }
        }
        runs.sort_by(|a, b| a.1.name().cmp(&b.1.name()));

        let mut results = Vec::new();
        let mut cur_profile = String::new();
        let mut sched: Option<SchedulerProcess> = None;

        for (s, profile) in &runs {
            let qname = s.qualified_name(profile);
            let pname = profile.name();

            let start = Instant::now();
            let cgroups = CgroupManager::new(&self.config.parent_cgroup);
            let needs_cpu_ctrl = !profile.flags.contains(&Flag::CpuControllerDisabled);
            cgroups.setup(needs_cpu_ctrl).context("cgroup setup")?;

            if pname != cur_profile {
                if let Some(mut p) = sched.take() {
                    p.stop();
                }
                let args = s.scheduler_args(&self.config.parent_cgroup, profile);
                tracing::info!(bin = %self.config.mitosis_bin, ?args, "starting scheduler");
                let mut p = SchedulerProcess::start(&self.config.mitosis_bin, &args)?;
                std::thread::sleep(Duration::from_millis(500));
                if p.is_dead() {
                    let _ = cgroups.cleanup_all();
                    std::mem::forget(cgroups);
                    bail!("scheduler exited immediately");
                }
                tracing::info!("scheduler running");
                sched = Some(p);
                cur_profile = pname;
            }

            let sched_pid = sched.as_ref().map(|s| s.pid()).unwrap_or(0);
            crate::workload::set_sched_pid(sched_pid);
            let ctx = Ctx {
                cgroups: &cgroups,
                topo: &self.topo,
                duration: Duration::from_secs(self.config.duration_s),
                workers_per_cell: self.config.workers_per_cell,
                sched_pid,
            };

            tracing::info!(qname, "starting scenario");
            let res = scenario::run_scenario(s, &ctx);
            tracing::info!(qname, elapsed = ?start.elapsed(), "scenario complete");

            let sched_dead = sched.as_mut().map(|s| s.is_dead()).unwrap_or(false);
            if sched_dead {
                tracing::warn!(qname, "scheduler died");
            }

            let _ = cgroups.cleanup_all();
            std::mem::forget(cgroups);
            std::thread::sleep(Duration::from_millis(200));

            let r = match res {
                Ok(mut v) => {
                    if sched_dead {
                        v.passed = false;
                        v.details.push("scheduler died".into());
                    }
                    // On failure: kill scheduler so it writes exit dump, then read it
                    if !v.passed {
                        if let Some(mut s) = sched.take() {
                            s.stop();
                            std::thread::sleep(Duration::from_millis(100));
                            let dump = s.read_stderr();
                            if !dump.is_empty() {
                                for line in dump.lines() {
                                    if !line.trim().is_empty() {
                                        v.details.push(line.to_string());
                                    }
                                }
                            }
                        }
                        cur_profile.clear();
                    } else if sched_dead {
                        sched.take();
                        cur_profile.clear();
                    }
                    ScenarioResult {
                        scenario_name: qname,
                        passed: v.passed,
                        duration_s: start.elapsed().as_secs_f64(),
                        details: v.details,
                        stats: v.stats,
                    }
                }
                Err(e) => {
                    let mut details = vec![format!("{e:#}")];
                    if let Some(mut s) = sched.take() {
                        s.stop();
                        std::thread::sleep(Duration::from_millis(100));
                        let dump = s.read_stderr();
                        for line in dump.lines() {
                            if !line.trim().is_empty() {
                                details.push(line.to_string());
                            }
                        }
                    }
                    cur_profile.clear();
                    ScenarioResult {
                        scenario_name: qname,
                        passed: false,
                        duration_s: start.elapsed().as_secs_f64(),
                        details,
                        stats: Default::default(),
                    }
                }
            };
            results.push(r);
        }

        if let Some(mut p) = sched.take() {
            p.stop();
        }
        Ok(results)
    }
}

pub struct SchedulerProcess {
    child: Child,
    stderr_path: std::path::PathBuf,
}

impl SchedulerProcess {
    fn start(bin: &str, args: &[String]) -> Result<Self> {
        let stderr_path =
            std::path::PathBuf::from(format!("/tmp/stt-sched-{}.log", std::process::id()));
        let stderr_file = std::fs::File::create(&stderr_path)?;
        let child = Command::new(bin)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| format!("spawn {bin}"))?;
        Ok(Self { child, stderr_path })
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    /// Read scheduler output (includes watchdog dumps on stall exit).
    pub fn read_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
    pub fn is_dead(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_some()
    }
    fn stop(&mut self) {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        let _ = kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for SchedulerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_result_serde_roundtrip() {
        let r = ScenarioResult {
            scenario_name: "test/default".into(),
            passed: false,
            duration_s: 15.5,
            details: vec!["unfair".into(), "stuck 3000ms".into()],
            stats: ScenarioStats {
                cells: vec![],
                total_workers: 4,
                total_cpus: 8,
                total_migrations: 12,
                worst_spread: 25.0,
                worst_gap_ms: 3000,
                worst_gap_cpu: 5,
            },
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.scenario_name, r2.scenario_name);
        assert_eq!(r.passed, r2.passed);
        assert_eq!(r.details, r2.details);
        assert_eq!(r.stats.worst_gap_ms, r2.stats.worst_gap_ms);
        assert_eq!(r.stats.total_workers, r2.stats.total_workers);
    }

    #[test]
    fn scenario_result_default_stats() {
        let json = r#"{"scenario_name":"t","passed":true,"duration_s":1.0,"details":[]}"#;
        let r: ScenarioResult = serde_json::from_str(json).unwrap();
        assert!(r.passed);
        assert_eq!(r.stats.total_workers, 0);
        assert_eq!(r.stats.cells.len(), 0);
    }

    #[test]
    fn scenario_result_with_cells() {
        let r = ScenarioResult {
            scenario_name: "proportional/default".into(),
            passed: true,
            duration_s: 20.0,
            details: vec![],
            stats: ScenarioStats {
                cells: vec![
                    crate::verify::CellStats {
                        num_workers: 4,
                        num_cpus: 4,
                        avg_runnable_pct: 75.0,
                        min_runnable_pct: 70.0,
                        max_runnable_pct: 80.0,
                        spread: 10.0,
                        max_gap_ms: 50,
                        max_gap_cpu: 0,
                        total_migrations: 3,
                    },
                    crate::verify::CellStats {
                        num_workers: 4,
                        num_cpus: 4,
                        avg_runnable_pct: 72.0,
                        min_runnable_pct: 68.0,
                        max_runnable_pct: 76.0,
                        spread: 8.0,
                        max_gap_ms: 30,
                        max_gap_cpu: 4,
                        total_migrations: 2,
                    },
                ],
                total_workers: 8,
                total_cpus: 8,
                total_migrations: 5,
                worst_spread: 10.0,
                worst_gap_ms: 50,
                worst_gap_cpu: 0,
            },
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.stats.cells.len(), 2);
        assert_eq!(r2.stats.cells[0].num_workers, 4);
        assert_eq!(r2.stats.cells[1].max_gap_cpu, 4);
    }

    #[test]
    fn run_config_cpu_controller_flag() {
        let profile_no_ctrl = FlagProfile {
            flags: vec![Flag::CpuControllerDisabled],
        };
        assert!(profile_no_ctrl.flags.contains(&Flag::CpuControllerDisabled));
        let needs_cpu_ctrl = !profile_no_ctrl.flags.contains(&Flag::CpuControllerDisabled);
        assert!(!needs_cpu_ctrl);

        let profile_default = FlagProfile { flags: vec![] };
        let needs_cpu_ctrl = !profile_default.flags.contains(&Flag::CpuControllerDisabled);
        assert!(needs_cpu_ctrl);
    }
}
