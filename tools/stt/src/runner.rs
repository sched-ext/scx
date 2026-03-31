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
    pub repro: bool,
    pub assert_script: Option<String>,
    pub kernel_dir: Option<String>,
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
                Some(flags) if flags.is_empty() => vec![FlagProfile { flags: vec![] }],
                Some(flags) => vec![FlagProfile {
                    flags: flags.clone(),
                }],
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
                let args = s.scheduler_args(&self.config.parent_cgroup, profile, self.config.repro);
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

            // Start bpftrace assertion checker early so probes
            // compile and attach before the scenario runs.
            let assert_handle = if self.config.repro {
                self.config.assert_script.as_ref().map(|script| {
                    let script = script.clone();
                    let kernel_dir = self.config.kernel_dir.clone();
                    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let stop_clone = stop.clone();
                    let handle = std::thread::spawn(move || {
                        run_assert_script(&script, kernel_dir.as_deref(), &stop_clone)
                    });
                    // Give bpftrace time to compile and attach probes
                    std::thread::sleep(Duration::from_secs(3));
                    (handle, stop)
                })
            } else {
                None
            };

            tracing::info!(qname, "starting scenario");
            let res = scenario::run_scenario(s, &ctx);
            tracing::info!(qname, elapsed = ?start.elapsed(), "scenario complete");

            // Stop assertion checker and collect results
            let assert_output = if let Some((handle, stop)) = assert_handle {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                handle.join().ok().flatten()
            } else {
                None
            };

            let sched_dead = sched.as_mut().map(|s| s.is_dead()).unwrap_or(false);
            if sched_dead {
                tracing::warn!(qname, "scheduler died");
            }

            let _ = cgroups.cleanup_all();
            std::mem::forget(cgroups);
            std::thread::sleep(Duration::from_millis(200));

            let r = match res {
                Ok(mut v) => {
                    if let Some(output) = assert_output {
                        v.passed = false;
                        v.details.push("ASSERTION FAILED".into());
                        for line in output.lines() {
                            if !line.trim().is_empty() {
                                v.details.push(line.to_string());
                            }
                        }
                    }
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

/// Embedded bpftrace assertion scripts.
const ASSERT_SCRIPTS: &[(&str, &str)] = &[(
    "check_deferred_locals",
    include_str!("../scripts/check_deferred_locals.bt"),
)];

/// Resolve an assert script name to a temp file. Accepts a path to an
/// existing file or a name matching an embedded script.
fn resolve_assert_script(name: &str) -> Result<String, String> {
    if std::path::Path::new(name).exists() {
        return Ok(name.to_string());
    }
    let key = name.strip_suffix(".bt").unwrap_or(name);
    for (k, content) in ASSERT_SCRIPTS {
        if *k == key {
            let path = format!("/tmp/stt-assert-{}.bt", key);
            std::fs::write(&path, content).map_err(|e| format!("write script: {e}"))?;
            return Ok(path);
        }
    }
    Err(format!(
        "unknown script: {name}\navailable: {}",
        ASSERT_SCRIPTS
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Run a bpftrace assertion script. Returns violation output or None.
/// When stop is set, SIGTERM the process and return.
fn run_assert_script(
    script: &str,
    kernel_dir: Option<&str>,
    stop: &std::sync::atomic::AtomicBool,
) -> Option<String> {
    use std::sync::atomic::Ordering;

    let script_path = match resolve_assert_script(script) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(%e, "failed to resolve assert script");
            return None;
        }
    };

    let mut child = match Command::new("bpftrace")
        .arg(&script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to spawn bpftrace");
            return None;
        }
    };

    tracing::info!("bpftrace assertion checker started");

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut buf = String::new();
                        let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                        buf
                    })
                    .unwrap_or_default();

                if stdout.contains("VIOLATION") {
                    tracing::warn!("assertion violated");
                    return Some(postprocess_violation(&stdout, kernel_dir));
                }
                if !status.success() {
                    let stderr = child
                        .stderr
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    tracing::warn!(code = status.code(), %stderr, "bpftrace exited with error");
                }
                return None;
            }
            Ok(None) => {
                if stop.load(Ordering::Relaxed) {
                    use nix::sys::signal::{kill, Signal};
                    use nix::unistd::Pid;
                    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                tracing::error!(%e, "bpftrace wait failed");
                return None;
            }
        }
    }
}

/// Post-process bpftrace violation output: symbolize raw addresses
/// with source lines and bootlin links via blazesym.
fn postprocess_violation(stdout: &str, kernel_dir: Option<&str>) -> String {
    use blazesym::symbolize::{self, Symbolizer};
    tracing::info!(?kernel_dir, "postprocessing violation");

    let raw = extract_section(stdout, "---RAW---", "---ENDRAW---");
    let main = stdout.split("---RAW---").next().unwrap_or(stdout).trim();

    // Strip absolute paths in bpftrace output (e.g. BPF source paths)
    let main = strip_abs_paths(main);

    let mut out = String::new();
    out.push_str("=== ASSERTION VIOLATION ===\n");
    out.push_str(&main);
    out.push('\n');

    if raw.is_empty() {
        return out;
    }

    let addrs: Vec<u64> = raw
        .lines()
        .filter_map(|l| u64::from_str_radix(l.trim(), 16).ok())
        .collect();

    if addrs.is_empty() {
        return out;
    }

    let mut ksrc = symbolize::source::Kernel::default();
    ksrc.debug_syms = true;
    if let Some(kd) = kernel_dir {
        let vmlinux = std::path::PathBuf::from(kd).join("vmlinux");
        if vmlinux.exists() {
            ksrc.vmlinux = vmlinux.into();
        }
    }

    let symbolizer = Symbolizer::builder().enable_code_info(true).build();
    let src = symbolize::source::Source::Kernel(ksrc);
    let results = match symbolizer.symbolize(&src, symbolize::Input::AbsAddr(&addrs)) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%e, "symbolization failed");
            return out;
        }
    };

    let version = kernel_version(kernel_dir);

    let mut local_lines: Vec<String> = Vec::new();

    struct Frame {
        name: String,
        rel: String,
        line: u32,
    }
    let mut frames = Vec::new();
    for result in &results {
        if let Some(sym) = result.as_sym() {
            if let Some(ref ci) = sym.code_info {
                let path = ci.to_path();
                let rel = make_relative(&path.to_string_lossy());
                frames.push(Frame {
                    name: sym.name.to_string(),
                    rel,
                    line: ci.line.unwrap_or(0),
                });
            }
        }
    }
    let max_name = frames.iter().map(|f| f.name.len()).max().unwrap_or(0);
    let max_loc = frames
        .iter()
        .map(|f| f.rel.len() + 1 + f.line.to_string().len())
        .max()
        .unwrap_or(0);
    for f in &frames {
        let loc = format!("{}:{}", f.rel, f.line);
        let url = format!(
            "https://elixir.bootlin.com/linux/{version}/source/{}#L{}",
            f.rel, f.line
        );
        local_lines.push(format!(
            "    {:<nw$} @ {:<lw$}  {url}",
            f.name,
            loc,
            nw = max_name,
            lw = max_loc
        ));
    }

    if frames.is_empty() {
        tracing::warn!(
            n_results = results.len(),
            n_with_sym = results.iter().filter(|r| r.as_sym().is_some()).count(),
            "blazesym: no source lines (vmlinux may lack DWARF or /proc/kcore not accessible)"
        );
    }

    if !local_lines.is_empty() {
        out.push_str("  source:\n");
        for l in &local_lines {
            out.push_str(l);
            out.push('\n');
        }
    }

    out
}

fn extract_section(text: &str, start: &str, end: &str) -> String {
    if let Some(idx) = text.find(start) {
        let after = &text[idx + start.len()..];
        let end_idx = after.find(end).unwrap_or(after.len());
        after[..end_idx].trim().to_string()
    } else {
        String::new()
    }
}

fn kernel_version(kernel_dir: Option<&str>) -> String {
    if let Some(kd) = kernel_dir {
        if let Ok(out) = Command::new("git")
            .args(["describe", "--tags", "HEAD"])
            .current_dir(kd)
            .output()
        {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !v.is_empty() {
                return v.split("-virtme").next().unwrap_or(&v).to_string();
            }
        }
    }
    let r = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !r.is_empty() {
        // Strip suffixes like -virtme, -rc1, etc. for bootlin URL
        // Keep only vX.Y.Z
        let clean = r.split('-').next().unwrap_or(&r);
        return format!("v{clean}");
    }
    "latest".into()
}

/// Strip absolute paths to relative paths in text.
/// /home/.../scx/scheds/rust/... -> scheds/rust/...
/// /home/.../linux/kernel/sched/... -> kernel/sched/...
fn strip_abs_paths(text: &str) -> String {
    let mut result = text.to_string();
    // Each (search, keep) — find the marker, strip everything before it
    for (marker, keep_from) in [
        ("/scx/scheds/", "scx/scheds/"),
        ("/kernel/", "kernel/"),
        ("/fs/", "fs/"),
        ("/arch/", "arch/"),
    ] {
        while let Some(pos) = result.find(marker) {
            let before = &result[..pos];
            // Only strip if preceded by a path char (part of an absolute path)
            if let Some(start) =
                before.rfind(|c: char| !c.is_ascii() || c == ' ' || c == '@' || c == '(')
            {
                if before[start + 1..].starts_with('/') {
                    result = format!(
                        "{}{}{}",
                        &result[..start + 1],
                        keep_from,
                        &result[pos + marker.len()..]
                    );
                    continue;
                }
            } else if before.starts_with('/') {
                result = format!("{}{}", keep_from, &result[pos + marker.len()..]);
                continue;
            }
            break;
        }
    }
    result
}

fn make_relative(path: &str) -> String {
    for marker in [
        "/kernel/",
        "/fs/",
        "/arch/",
        "/mm/",
        "/net/",
        "/drivers/",
        "/include/",
        "/block/",
        "/lib/",
        "/security/",
        "/ipc/",
        "/init/",
        "/scx/scheds/",
    ] {
        if let Some(idx) = path.find(marker) {
            return path[idx + 1..].to_string();
        }
    }
    if path.starts_with("./") {
        return path[2..].to_string();
    }
    path.to_string()
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
