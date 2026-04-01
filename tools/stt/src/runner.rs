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
    /// Crash stack for auto-probe (file path or comma-separated function names).
    pub probe_stack: Option<String>,
    /// Auto-repro: crash → extract stack → rerun with probe-stack.
    pub auto_repro: bool,
    pub kernel_dir: Option<String>,
    /// Include bootlin URLs in source line output.
    pub bootlin: bool,
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

            // Start bpftrace probes. For auto-probe, split across
            // multiple processes (6 functions each) to avoid BPF size limits.
            const PROBES_PER_SCRIPT: usize = 6;
            let assert_handles: Vec<(
                std::thread::JoinHandle<Option<String>>,
                std::sync::Arc<std::sync::atomic::AtomicBool>,
            )> = if self.config.repro {
                if let Some(ref stack_input) = self.config.probe_stack {
                    let mut functions = filter_traceable(load_probe_stack(stack_input));
                    // Add BPF sched_ext symbols — not in kernel crash stacks
                    // but critical for seeing scheduler decisions.
                    let bpf_syms = discover_bpf_symbols();
                    if !bpf_syms.is_empty() {
                        tracing::debug!(n = bpf_syms.len(), "auto-probe: BPF symbols discovered");
                        functions.extend(bpf_syms);
                    }
                    let functions = functions;
                    if functions.is_empty() {
                        tracing::warn!("auto-probe: no functions in stack input");
                        vec![]
                    } else {
                        // BPF probes are heavier (bridge maps), use smaller chunks
                        let (bpf_fns, kern_fns): (Vec<_>, Vec<_>) =
                            functions.iter().cloned().partition(|f| f.is_bpf);
                        let mut chunks: Vec<Vec<StackFunction>> = kern_fns
                            .chunks(PROBES_PER_SCRIPT)
                            .map(|c| c.to_vec())
                            .collect();
                        // 2 BPF probes per chunk (each needs bridge kprobes + 18 maps)
                        for bpf_chunk in bpf_fns.chunks(2) {
                            chunks.push(bpf_chunk.to_vec());
                        }
                        tracing::debug!(
                            total = functions.len(),
                            scripts = chunks.len(),
                            "auto-probe: splitting across bpftrace processes"
                        );
                        let mut handles = Vec::new();
                        for (i, chunk) in chunks.iter().enumerate() {
                            let script = generate_probe_script(chunk);
                            let path = format!("/tmp/stt-autoprobe-{}-{i}.bt", std::process::id());
                            if std::fs::write(&path, &script).is_err() {
                                continue;
                            }
                            let stop =
                                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                            let stop_clone = stop.clone();
                            let path_clone = path.clone();
                            let handle = std::thread::spawn(move || {
                                run_bpftrace_raw(&path_clone, &stop_clone)
                            });
                            handles.push((handle, stop));
                        }
                        std::thread::sleep(Duration::from_secs(3));
                        handles
                    }
                } else if let Some(ref script) = self.config.assert_script {
                    if let Ok(path) = resolve_assert_script(script) {
                        let kernel_dir = self.config.kernel_dir.clone();
                        let no_bootlin = !self.config.bootlin;
                        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let stop_clone = stop.clone();
                        let handle = std::thread::spawn(move || {
                            run_assert_script(&path, kernel_dir.as_deref(), no_bootlin, &stop_clone)
                        });
                        std::thread::sleep(Duration::from_secs(3));
                        vec![(handle, stop)]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            tracing::info!(qname, "starting scenario");
            let res = scenario::run_scenario(s, &ctx);
            tracing::info!(qname, elapsed = ?start.elapsed(), "scenario complete");

            // Stop assertion checkers and collect results.
            let assert_output = if !assert_handles.is_empty() {
                let is_autoprobe = self.config.probe_stack.is_some() || self.config.auto_repro;
                let mut all_outputs = Vec::new();
                for (handle, stop) in assert_handles {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    if let Some(output) = handle.join().ok().flatten() {
                        all_outputs.push(output);
                    }
                }
                if all_outputs.is_empty() {
                    None
                } else if is_autoprobe {
                    // Merge raw outputs, then postprocess once
                    let merged = merge_autoprobe_outputs(&all_outputs);
                    let no_bootlin = !self.config.bootlin;
                    Some(postprocess_autoprobe(
                        &merged,
                        self.config.kernel_dir.as_deref(),
                        no_bootlin,
                        self.config.verbose,
                    ))
                } else {
                    // Single assert script — already postprocessed
                    Some(all_outputs.join("\n"))
                }
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
                        if self.config.probe_stack.is_none() && !self.config.auto_repro {
                            v.details.push("ASSERTION FAILED".into());
                        }
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
                                let is_autoprobe =
                                    self.config.probe_stack.is_some() || self.config.auto_repro;
                                for line in dump.lines() {
                                    if line.trim().is_empty() {
                                        continue;
                                    }
                                    if is_autoprobe && !self.config.verbose {
                                        if line.contains("runtime error")
                                            || line.contains("EXIT:")
                                            || line.contains("Error:")
                                            || line.starts_with("CELL[")
                                            || line.starts_with("  CELL[")
                                            || line.starts_with("CPU[")
                                            || line.starts_with("  CPU[")
                                        {
                                            v.details.push(line.to_string());
                                        }
                                    } else {
                                        v.details.push(line.to_string());
                                    }
                                }
                                // Extract stack from the FULL dump (not the
                                // filtered details) for auto-probe rerun
                                if self.config.repro && self.config.probe_stack.is_none() {
                                    let stack_fns = extract_stack_functions_all(&dump);
                                    if !stack_fns.is_empty() {
                                        let stack_path = format!(
                                            "/tmp/stt-crash-stack-{}.txt",
                                            std::process::id()
                                        );
                                        let stack_text: String = stack_fns
                                            .iter()
                                            .map(|f| f.raw_name.as_str())
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        let _ = std::fs::write(&stack_path, &stack_text);
                                        let names: Vec<&str> = stack_fns
                                            .iter()
                                            .map(|f| f.display_name.as_str())
                                            .collect();
                                        v.details.push(format!(
                                            "auto-probe: rerun with --probe-stack {}",
                                            stack_path
                                        ));
                                        v.details
                                            .push(format!("  functions: {}", names.join(", ")));
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

// ---- Auto-probe helpers ----

/// Skip the trigger function and low-level infrastructure that generates
/// massive maps with no scheduler decision data.
fn should_skip_probe(name: &str) -> bool {
    name == "scx_exit"
        || name.starts_with("_raw_spin_")
        || name.starts_with("asm_")
        || name.starts_with("entry_")
        || name.starts_with("__sysvec_")
        || name.starts_with("sysvec_")
}

/// Extract function names from a crash stack trace for the next run.
/// Deduplicates and skips generic functions.
pub fn extract_stack_functions(stack: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    stack
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_start_matches("  ");
            let func = trimmed.split('+').next()?;
            let func = func.trim();
            if func.is_empty()
                || func.contains(' ')
                || func.starts_with('[')
                || func.starts_with('#')
                || func.starts_with('=')
                || func.starts_with('-')
                || func.ends_with(':')
                || func.starts_with("bpf_prog_")
                || !func
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
                || should_skip_probe(func)
            {
                return None;
            }
            if seen.insert(func.to_string()) {
                Some(func.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ---- Auto-probe: crash-stack-driven bpftrace ----

#[derive(Debug, Clone)]
struct StackFunction {
    raw_name: String,
    display_name: String,
    is_bpf: bool,
}

/// Public API for auto-repro: extract function names as strings.
pub fn extract_stack_functions_all_pub(stack: &str) -> Vec<String> {
    extract_stack_functions_all(stack)
        .into_iter()
        .map(|f| f.raw_name)
        .collect()
}

/// Extract function names from a crash stack, including BPF programs.
fn extract_stack_functions_all(stack: &str) -> Vec<StackFunction> {
    let mut seen = std::collections::HashSet::new();
    stack
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_start_matches("  ");
            // Handle "func+0xOFFSET/0xSIZE" and "bpf_prog_HASH_name+0x..."
            let func = trimmed.split('+').next()?.trim();
            if func.is_empty()
                || func.contains(' ')
                || func.starts_with('[')
                || func.starts_with('#')
                || func.starts_with('=')
                || func.starts_with('-')
                || func.ends_with(':')
                || !func
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
                || should_skip_probe(func)
            {
                return None;
            }
            if !seen.insert(func.to_string()) {
                return None;
            }
            let is_bpf = func.starts_with("bpf_prog_");
            let display_name = if is_bpf {
                bpf_short_name(func).unwrap_or(func).to_string()
            } else {
                func.to_string()
            };
            Some(StackFunction {
                raw_name: func.to_string(),
                display_name,
                is_bpf,
            })
        })
        .collect()
}

/// Extract the short function name from a BPF program symbol.
/// "bpf_prog_abc123_mitosis_enqueue" → "mitosis_enqueue"
fn bpf_short_name(raw: &str) -> Option<&str> {
    let rest = raw.strip_prefix("bpf_prog_")?;
    let idx = rest.find('_')?;
    Some(&rest[idx + 1..])
}

/// Convert a BPF program symbol to a bpftrace wildcard pattern.
/// "bpf_prog_abc123_enqueue" → "bpf_prog_*_enqueue"
fn bpf_kprobe_pattern(raw: &str) -> Option<String> {
    let short = bpf_short_name(raw)?;
    Some(format!("bpf_prog_*_{short}"))
}

/// Load --probe-stack input: file path, inline stack, or comma-separated names.
fn load_probe_stack(input: &str) -> Vec<StackFunction> {
    // File path?
    if std::path::Path::new(input).exists() {
        if let Ok(contents) = std::fs::read_to_string(input) {
            return extract_stack_functions_all(&contents);
        }
    }
    // Inline stack (has +0x or newlines)?
    if input.contains("+0x") || input.contains('\n') {
        return extract_stack_functions_all(input);
    }
    // Comma-separated function names
    input
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let s = s.trim();
            let is_bpf = s.starts_with("bpf_prog_");
            StackFunction {
                raw_name: s.to_string(),
                display_name: if is_bpf {
                    bpf_short_name(s).unwrap_or(s).to_string()
                } else {
                    s.to_string()
                },
                is_bpf,
            }
        })
        .collect()
}

// ---- BTF-driven function signature parsing ----

#[derive(Debug, Clone)]
struct BtfParam {
    name: String,
    /// Resolved struct name for pointers (e.g., "task_struct", "rq")
    struct_name: Option<String>,
    /// True if this is a pointer type
    is_ptr: bool,
}

#[derive(Debug, Clone)]
struct BtfFunc {
    name: String,
    params: Vec<BtfParam>,
}

/// Struct types we know how to dereference in bpftrace.
/// Maps struct name → list of (field_access, output_key) pairs.
const STRUCT_FIELDS: &[(&str, &[(&str, &str)])] = &[
    (
        "task_struct",
        &[
            ("->pid", "pid"),
            ("->cpus_ptr->bits[0]", "cpus_ptr"),
            ("->scx.ddsp_dsq_id", "dsq_id"),
        ],
    ),
    ("rq", &[("->cpu", "cpu")]),
    ("scx_dispatch_q", &[("->id", "dsq_id")]),
];

/// Parse BTF from vmlinux for a set of function names using btf-rs.
fn parse_btf_functions(func_names: &[&str], vmlinux_path: Option<&str>) -> Vec<BtfFunc> {
    use btf_rs::{Btf, BtfType, Type};

    let btf_path = vmlinux_path.unwrap_or("/sys/kernel/btf/vmlinux");
    let btf = match Btf::from_file(btf_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(%e, path = btf_path, "btf: failed to parse");
            return Vec::new();
        }
    };

    // Resolve a parameter's type_id to its underlying struct name,
    // following PTR/CONST/VOLATILE/TYPEDEF chains.
    let resolve_struct_name = |type_id: u32| -> Option<String> {
        let mut t = match btf.resolve_type_by_id(type_id) {
            Ok(t) => t,
            Err(_) => return None,
        };
        for _ in 0..10 {
            match &t {
                Type::Ptr(_)
                | Type::Const(_)
                | Type::Volatile(_)
                | Type::Typedef(_)
                | Type::Restrict(_)
                | Type::TypeTag(_) => {
                    t = match btf.resolve_chained_type(t.as_btf_type().unwrap()) {
                        Ok(next) => next,
                        Err(_) => return None,
                    };
                }
                Type::Struct(s) => {
                    return btf.resolve_name(s).ok();
                }
                Type::Union(u) => {
                    return btf.resolve_name(u).ok();
                }
                _ => return None,
            }
        }
        None
    };

    let is_ptr =
        |type_id: u32| -> bool { matches!(btf.resolve_type_by_id(type_id), Ok(Type::Ptr(_))) };

    let mut results = Vec::new();

    for func_name in func_names {
        let types = match btf.resolve_types_by_name(func_name) {
            Ok(t) => t,
            Err(_) => continue,
        };

        for t in &types {
            if let Type::Func(func) = t {
                // Resolve the FuncProto
                let proto = match btf.resolve_chained_type(func) {
                    Ok(Type::FuncProto(fp)) => fp,
                    _ => continue,
                };

                let mut params = Vec::new();
                for param in &proto.parameters {
                    let name = btf.resolve_name(param).unwrap_or_default();
                    let tid = param.get_type_id().unwrap_or(0);
                    let struct_name = resolve_struct_name(tid)
                        .filter(|n| STRUCT_FIELDS.iter().any(|(s, _)| s == n));
                    params.push(BtfParam {
                        name,
                        struct_name,
                        is_ptr: is_ptr(tid),
                    });
                }

                results.push(BtfFunc {
                    name: func_name.to_string(),
                    params,
                });
                break; // take first match
            }
        }
    }

    tracing::debug!(n = results.len(), "btf: parsed function signatures");
    results
}

/// Generate bpftrace probe code for a function using BTF info.
fn generate_btf_probe(func: &BtfFunc, safe: &str) -> (String, String) {
    let mut capture = String::new();
    let mut dump = String::new();

    let mut field_keys: Vec<String> = Vec::new();

    // x86_64 kprobes only support arg0-arg5
    let max_args = func.params.len().min(6);
    for (i, param) in func.params[..max_args].iter().enumerate() {
        if let Some(ref sname) = param.struct_name {
            // Known struct — dereference useful fields
            if let Some((_, fields)) = STRUCT_FIELDS.iter().find(|(s, _)| *s == sname) {
                let var = format!("$btf_{}", param.name);
                capture.push_str(&format!("    {var} = (struct {sname} *)arg{i};\n"));
                for (field_access, key) in *fields {
                    let map_key = format!("{safe}_{}", key);
                    capture.push_str(&format!(
                        "    @fn_{map_key}[tid] = (uint64){var}{field_access};\n"
                    ));
                    field_keys.push(format!("{key}=%lu",));
                }
            }
        } else if !param.is_ptr {
            // Scalar — save raw with param name
            let map_key = format!("{safe}_{}", param.name);
            capture.push_str(&format!("    @fn_{map_key}[tid] = (uint64)arg{i};\n"));
            field_keys.push(format!("{}=%lu", param.name));
        } else {
            // Unknown pointer — save raw
            let map_key = format!("{safe}_arg{i}");
            capture.push_str(&format!("    @fn_{map_key}[tid] = (uint64)arg{i};\n"));
            field_keys.push(format!("arg{i}=%lu"));
        }
    }

    // Build printf for the dump section
    if !field_keys.is_empty() {
        let fmt = field_keys.join(" ");
        let args: Vec<String> = func.params[..max_args]
            .iter()
            .enumerate()
            .map(|(i, param)| {
                if let Some(ref sname) = param.struct_name {
                    if let Some((_, fields)) = STRUCT_FIELDS.iter().find(|(s, _)| *s == sname) {
                        fields
                            .iter()
                            .map(|(_, key)| format!("@fn_{safe}_{key}[tid]"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    } else {
                        format!("@fn_{safe}_arg{i}[tid]")
                    }
                } else if !param.is_ptr {
                    format!("@fn_{safe}_{}[tid]", param.name)
                } else {
                    format!("@fn_{safe}_arg{i}[tid]")
                }
            })
            .collect();

        dump.push_str(&format!(
            "    printf(\"  {fmt}\\n\", {});\n",
            args.join(", ")
        ));
    }

    (capture, dump)
}

/// Discover BPF sched_ext program symbols from /proc/kallsyms.
/// These are JIT'd at runtime and not in the crash stack, but they're
/// the entry points where BPF schedulers make dispatch decisions.
fn discover_bpf_symbols() -> Vec<StackFunction> {
    // Get scheduler's prog IDs (struct_ops programs)
    let bpftool_out = Command::new("bpftool")
        .args(["prog", "show"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let sched_prog_ids: std::collections::HashSet<String> = bpftool_out
        .lines()
        .filter(|l| l.contains("struct_ops"))
        .filter_map(|l| l.split(':').next().map(|s| s.trim().to_string()))
        .collect();

    if sched_prog_ids.is_empty() {
        tracing::debug!("discover_bpf_symbols: no struct_ops programs found");
        return Vec::new();
    }

    // List all probeable BPF functions via bpftrace
    // Format: fentry:bpf:PROG_ID:func_name
    let bpftrace_out = Command::new("bpftrace")
        .args(["-l", "fentry:bpf:*"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut seen = std::collections::HashSet::new();
    let results: Vec<StackFunction> = bpftrace_out
        .lines()
        .filter_map(|line| {
            // fentry:bpf:9:mitosis_enqueue
            let rest = line.strip_prefix("fentry:bpf:")?;
            let (id, func) = rest.split_once(':')?;
            // Only include functions from the scheduler's programs
            if !sched_prog_ids.contains(id) {
                return None;
            }
            if !seen.insert(func.to_string()) {
                return None;
            }
            Some(StackFunction {
                raw_name: format!("bpf_prog_{id}_{func}"),
                display_name: func.to_string(),
                is_bpf: true,
            })
        })
        .collect();

    tracing::debug!(n = results.len(), "discover_bpf_symbols");
    results
}

/// Filter functions to only those traceable via kprobe.
/// Falls back to /proc/kallsyms if tracefs unavailable.
fn filter_traceable(functions: Vec<StackFunction>) -> Vec<StackFunction> {
    let available = std::fs::read_to_string("/sys/kernel/tracing/available_filter_functions")
        .or_else(|_| std::fs::read_to_string("/proc/kallsyms"))
        .unwrap_or_default();

    if available.is_empty() {
        tracing::warn!("filter_traceable: no symbol source, skipping filter");
        return functions;
    }

    let before = functions.len();
    let filtered: Vec<StackFunction> = functions
        .into_iter()
        .filter(|f| {
            if f.is_bpf {
                let short = bpf_short_name(&f.raw_name).unwrap_or("");
                available.lines().any(|l| {
                    let sym = l.split_whitespace().next().unwrap_or("");
                    sym.starts_with("bpf_prog_") && sym.ends_with(&format!("_{short}"))
                })
            } else {
                available
                    .lines()
                    .any(|l| l.split_whitespace().next() == Some(f.raw_name.as_str()))
            }
        })
        .collect();

    tracing::debug!(before, after = filtered.len(), "filter_traceable");
    filtered
}

/// Generate a bpftrace script that probes each function in the crash
/// stack, saves arguments per-tid, and dumps on scx_exit.
/// Uses BTF for type-aware argument access when available.
fn generate_probe_script(functions: &[StackFunction]) -> String {
    // Try to get BTF signatures for all kernel functions
    let kernel_names: Vec<&str> = functions
        .iter()
        .filter(|f| !f.is_bpf)
        .map(|f| f.raw_name.as_str())
        .collect();
    let btf_funcs = parse_btf_functions(&kernel_names, None);

    let mut script = String::new();
    script.push_str("/* Auto-generated by stt --probe-stack (BTF-aware) */\n\n");

    // If this chunk has BPF probes, add a bridge kprobe on do_enqueue_task.
    // It runs on the same tid right before BPF sched_ext ops and captures
    // the real task_struct args that fentry:bpf can't read directly.
    let has_bpf_probes = functions.iter().any(|f| f.is_bpf);
    if has_bpf_probes {
        let bridge_fields = [
            ("pid", "$p->pid"),
            ("cpus", "$p->cpus_ptr->bits[0]"),
            ("dsq", "$p->scx.ddsp_dsq_id"),
            ("enqflags", "$p->scx.ddsp_enq_flags"),
            ("slice", "$p->scx.slice"),
            ("vtime", "$p->scx.dsq_vtime"),
            ("weight", "(uint64)$p->scx.weight"),
            ("sticky", "(uint64)$p->scx.sticky_cpu"),
            ("flags", "(uint64)$p->scx.flags"),
        ];

        // Each BPF op has a kernel caller. Bridge from that caller.
        // Maps: BPF op short name → (kernel caller, task arg index)
        let op_callers: &[(&str, &str, usize)] = &[
            ("select_cpu", "do_enqueue_task", 1),
            ("enqueue", "do_enqueue_task", 1),
            ("dispatch", "balance_one", 0), // no task arg, rq only
            ("running", "set_next_task_scx", 1),
            ("stopping", "put_prev_task_scx", 1),
            ("tick", "task_tick_scx", 1),
            ("set_cpumask", "set_cpus_allowed_scx", 1),
            ("init_task", "scx_enable_task", 1),
            ("enable", "scx_enable_task", 1),
        ];

        // Find which kernel callers we need bridges for
        let mut needed_callers = std::collections::HashSet::new();
        for f in functions.iter().filter(|f| f.is_bpf) {
            for (op, caller, _) in op_callers {
                if f.display_name.contains(op) {
                    needed_callers.insert(*caller);
                    break;
                }
            }
        }

        // Generate bridge kprobes for each needed kernel caller.
        // All maps keyed by task_struct pointer (unique per task).
        for (op, caller, task_arg) in op_callers {
            if !needed_callers.contains(caller) {
                continue;
            }
            needed_callers.remove(caller); // only emit once per caller
            if *task_arg == 0 && *op == "dispatch" {
                continue;
            }
            // Entry: capture state, save pointer for kretprobe + subprog bridge
            script.push_str(&format!("kprobe:{caller} {{\n"));
            script.push_str(&format!("    $p = (struct task_struct *)arg{task_arg};\n"));
            script.push_str("    $tptr = (uint64)$p;\n");
            script.push_str("    @stt_task_ptr[tid] = $tptr;\n");
            script.push_str(&format!("    @bpf_{caller}_seen[$tptr] = 1;\n"));
            script.push_str(&format!("    @bpf_{caller}_ts[$tptr] = nsecs;\n"));
            for (name, expr) in &bridge_fields {
                script.push_str(&format!("    @bpf_{caller}_{name}[$tptr] = {expr};\n"));
            }
            script.push_str("}\n\n");

            // Exit: read pointer back, capture post-BPF state
            script.push_str(&format!("kretprobe:{caller} {{\n"));
            script.push_str("    $tptr = @stt_task_ptr[tid];\n");
            script.push_str(&format!("    $p = (struct task_struct *)$tptr;\n"));
            script.push_str(&format!("    @bpf_{caller}_exit_seen[$tptr] = 1;\n"));
            script.push_str(&format!("    @bpf_{caller}_exit_ts[$tptr] = nsecs;\n"));
            for (name, expr) in &bridge_fields {
                script.push_str(&format!("    @bpf_{caller}_exit_{name}[$tptr] = {expr};\n"));
            }
            script.push_str("}\n\n");
        }

        // Capture crashed task pointer for bridge lookup
        script.push_str("kprobe:task_can_run_on_remote_rq {\n");
        script.push_str("    @stt_crashed_ptr[tid] = (uint64)arg1;\n");
        script.push_str("}\n\n");

        // Subprog bridge: ALL callers set @stt_task_ptr[tid] so subprogs
        // can key by task pointer. Callers already handled above set it;
        // add any missing ones.
        let all_callers: &[(&str, usize)] = &[
            ("do_enqueue_task", 1),
            ("set_next_task_scx", 1),
            ("put_prev_task_scx", 1),
            ("task_tick_scx", 1),
            ("set_cpus_allowed_scx", 1),
            ("scx_enable_task", 1),
        ];
        // Every chunk needs its own @stt_task_ptr setter (maps aren't
        // shared across bpftrace processes). Emit all callers unconditionally.
        for (caller, arg_idx) in all_callers {
            script.push_str(&format!("kprobe:{caller} {{\n"));
            script.push_str(&format!(
                "    @stt_task_ptr[tid] = (uint64)((struct task_struct *)arg{arg_idx});\n"
            ));
            script.push_str("}\n\n");
        }
    }

    // Per-function probes.
    let mut probe_infos: Vec<(String, String, String, bool)> = Vec::new(); // (safe, label, dump_code, is_bpf)

    for f in functions {
        // BPF functions: use fentry:bpf:prog_name syntax.
        // kprobe/kfunc don't work on BPF JIT code.
        let probe = if f.is_bpf {
            format!("fentry:bpf:{}", f.display_name)
        } else {
            format!("kprobe:{}", f.raw_name)
        };

        let safe = f.display_name.replace(['.', '-'], "_");
        let tag = if f.is_bpf { " (BPF)" } else { "" };
        let label = format!("{}{tag}", f.display_name);

        script.push_str(&format!("{probe} {{\n"));

        // BPF probes: fentry:bpf can't read args directly (kernel limitation).
        // Bridge: read data from kprobe maps populated by do_enqueue_task
        // which runs on the same tid right before the BPF function.
        let dump_code = if f.is_bpf {
            // Key by task pointer from bridge (unique per task)
            script.push_str("    $tptr = (uint64)@stt_task_ptr[tid];\n");
            script.push_str(&format!("    @fn_{safe}_fired[$tptr] = 1;\n"));
            script.push_str(&format!("    @fn_{safe}_ts[$tptr] = nsecs;\n"));

            // Find the kernel caller for this BPF op
            let op_callers: &[(&str, &str)] = &[
                ("select_cpu", "do_enqueue_task"),
                ("enqueue", "do_enqueue_task"),
                ("dispatch", "balance_one"),
                ("running", "set_next_task_scx"),
                ("stopping", "put_prev_task_scx"),
                ("tick", "task_tick_scx"),
                ("set_cpumask", "set_cpus_allowed_scx"),
                ("init_task", "scx_enable_task"),
                ("enable", "scx_enable_task"),
            ];
            let caller = op_callers
                .iter()
                .find(|(op, _)| f.display_name.contains(op))
                .map(|(_, c)| *c);

            let fields = [
                "pid", "cpus", "dsq", "enqflags", "slice", "vtime", "weight", "sticky", "flags",
            ];

            let mut d = String::new();
            if let Some(caller) = caller {
                let prefix = format!("bpf_{caller}");
                // ENTER — from kprobe on kernel caller
                let mut fmt_parts = vec!["seen=%lu".to_string(), "ts=%lu".to_string()];
                let mut arg_parts = vec![
                    format!("@{prefix}_seen[$crashed_ptr]"),
                    format!("@{prefix}_ts[$crashed_ptr]"),
                ];
                for field in &fields {
                    fmt_parts.push(format!("{field}=%lu"));
                    arg_parts.push(format!("@{prefix}_{field}[$crashed_ptr]"));
                }
                d.push_str(&format!(
                    "    printf(\"  STT_BPF_ENTER {}\\n\", {});\n",
                    fmt_parts.join(" "),
                    arg_parts.join(", ")
                ));
                // EXIT — from kretprobe on kernel caller
                let mut exit_fmt = vec!["seen=%lu".to_string(), "ts=%lu".to_string()];
                let mut exit_args = vec![
                    format!("@{prefix}_exit_seen[$crashed_ptr]"),
                    format!("@{prefix}_exit_ts[$crashed_ptr]"),
                ];
                for field in &fields {
                    exit_fmt.push(format!("{field}=%lu"));
                    exit_args.push(format!("@{prefix}_exit_{field}[$crashed_ptr]"));
                }
                d.push_str(&format!(
                    "    printf(\"  STT_BPF_EXIT {}\\n\", {});\n",
                    exit_fmt.join(" "),
                    exit_args.join(", ")
                ));
            } else {
                // Sub-function: no kernel caller bridge, just show timing
                d.push_str(&format!(
                    "    printf(\"  STT_BPF_ENTER seen=%lu ts=%lu\\n\", @fn_{safe}_fired[$crashed_ptr], @fn_{safe}_ts[$crashed_ptr]);\n"
                ));
            }
            d
        } else {
            // Kernel function: try BTF, fall back to raw args, keyed by tid
            let btf = btf_funcs.iter().find(|b| b.name == f.raw_name);
            if let Some(btf_func) = btf {
                let (capture, dump) = generate_btf_probe(btf_func, &safe);
                script.push_str(&capture);
                dump
            } else {
                for i in 0..4 {
                    script.push_str(&format!("    @fn_{safe}_arg{i}[tid] = (uint64)arg{i};\n"));
                }
                let mut d = String::new();
                d.push_str("    printf(\"  arg0=%lu arg1=%lu arg2=%lu arg3=%lu\\n\",\n");
                d.push_str(&format!(
                    "           @fn_{safe}_arg0[tid], @fn_{safe}_arg1[tid],\n"
                ));
                d.push_str(&format!(
                    "           @fn_{safe}_arg2[tid], @fn_{safe}_arg3[tid]);\n"
                ));
                d
            }
        };

        script.push_str(&format!("    @fn_{safe}_ts[tid] = nsecs;\n"));
        script.push_str("}\n\n");

        probe_infos.push((safe, label, dump_code, f.is_bpf));
    }

    // Trigger: dump on scx_exit
    script.push_str("kprobe:scx_exit {\n");
    script.push_str("    printf(\"VIOLATION: scx_exit fired (auto-probe)\\n\");\n");
    script.push_str("    printf(\"trigger_tid=%d trigger_ts=%lu\\n\", tid, nsecs);\n\n");

    // Get crashed task's pointer for BPF bridge lookup.
    if has_bpf_probes {
        script.push_str("    $crashed_ptr = @stt_crashed_ptr[tid];\n");
    }

    for (safe, label, dump_code, _is_bpf) in &probe_infos {
        script.push_str(&format!("    printf(\"--- {label} ---\\n\");\n"));
        let key = "tid"; // all probes now keyed by tid
        script.push_str(&format!(
            "    printf(\"  ts=%lu\\n\", @fn_{safe}_ts[{key}]);\n"
        ));
        script.push_str(dump_code);
        script.push('\n');
    }

    script.push_str("    printf(\"  call chain:\\n%s\", kstack);\n");
    script.push_str("    printf(\"  ---RAW---\\n%s---ENDRAW---\\n\", kstack(raw));\n");

    // Clear maps and exit.
    let map_names: std::collections::HashSet<String> = script
        .split('@')
        .skip(1)
        .filter_map(|s| {
            let end = s.find('[')?;
            Some(s[..end].to_string())
        })
        .collect();
    for name in &map_names {
        script.push_str(&format!("    clear(@{name});\n"));
    }

    script.push_str("    exit();\n");
    script.push_str("}\n");

    script
}

// ---- Value decoders for enriched output ----

fn decode_dsq_id(id: u64) -> String {
    if id == 0 {
        return "0".into();
    }
    match id >> 62 {
        3 => format!("LOCAL_ON|{}", id & 0xffffffff),
        2 => match id & 0xffffffff {
            0 => "SCX_DSQ_INVALID".into(),
            1 => "GLOBAL".into(),
            2 => "LOCAL".into(),
            3 => "BYPASS".into(),
            v => format!("BUILTIN({v})"),
        },
        _ => format!("DSQ(0x{id:x})"),
    }
}

fn decode_cpumask(bits: u64) -> String {
    if bits == 0 {
        return "none".into();
    }
    let mut cpus = Vec::new();
    for i in 0..64u32 {
        if bits & (1u64 << i) != 0 {
            cpus.push(i);
        }
    }
    let mut ranges = Vec::new();
    let (mut s, mut e) = (cpus[0], cpus[0]);
    for &c in &cpus[1..] {
        if c == e + 1 {
            e = c;
        } else {
            ranges.push(if s == e {
                format!("{s}")
            } else {
                format!("{s}-{e}")
            });
            s = c;
            e = c;
        }
    }
    ranges.push(if s == e {
        format!("{s}")
    } else {
        format!("{s}-{e}")
    });
    ranges.join(",")
}

fn decode_enq_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & 1 != 0 {
        parts.push("WAKEUP");
    }
    if flags & 2 != 0 {
        parts.push("HEAD");
    }
    if flags & (1 << 32) != 0 {
        parts.push("PREEMPT");
    }
    if flags & (1u64 << 40) != 0 {
        parts.push("REENQ");
    }
    if flags & (1u64 << 41) != 0 {
        parts.push("LAST");
    }
    if flags & (1u64 << 56) != 0 {
        parts.push("CLEAR_OPSS");
    }
    if flags & (1u64 << 57) != 0 {
        parts.push("DSQ_PRIQ");
    }
    if flags & (1u64 << 58) != 0 {
        parts.push("NESTED");
    }
    if parts.is_empty() {
        "0".into()
    } else {
        parts.join("|")
    }
}

fn decode_exit_kind(kind: u64) -> String {
    match kind {
        0 => "NONE".into(),
        1 => "DONE".into(),
        64 => "UNREG".into(),
        65 => "UNREG_BPF".into(),
        66 => "UNREG_KERN".into(),
        67 => "SYSRQ".into(),
        1024 => "ERROR".into(),
        1025 => "ERROR_BPF".into(),
        1026 => "ERROR_STALL".into(),
        v => format!("UNKNOWN({v})"),
    }
}

fn decode_kick_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & 1 != 0 {
        parts.push("IDLE");
    }
    if flags & 2 != 0 {
        parts.push("PREEMPT");
    }
    if flags & 4 != 0 {
        parts.push("WAIT");
    }
    if parts.is_empty() {
        "0".into()
    } else {
        parts.join("|")
    }
}

fn decode_ops_state(state: u64) -> String {
    match state & 0xff {
        0 => "NONE".into(),
        1 => "QUEUEING".into(),
        2 => "QUEUED".into(),
        3 => "DISPATCHING".into(),
        v => format!("OPSS({v})"),
    }
}

/// Infer type and format a raw u64 value for unknown function args.
/// Uses type:value format (colon, NOT equals) to distinguish from named args.
fn format_raw_arg(val: u64) -> String {
    if val == 0 {
        "int:0".into()
    } else if val == 0xffffffffffffffff || val == 0xffffffff {
        "int:-1".into()
    } else if val == 1 {
        "bool:true".into()
    } else if (2..=0xff).contains(&val) {
        format!("int:{val}")
    } else if val > 0xff00000000000000 {
        // kernel pointer
        format!("ptr:{:04x}", val & 0xffff)
    } else if val <= 0xffff && val.count_ones() >= 2 && val.count_ones() <= 16 {
        // looks like a cpumask (multiple bits set, small value)
        format!("mask:0x{val:x}({})", decode_cpumask(val))
    } else if val <= 0xffff {
        format!("int:{val}")
    } else if val >> 62 >= 2 {
        // could be a DSQ ID
        format!("dsq:{}", decode_dsq_id(val))
    } else {
        format!("hex:0x{val:x}")
    }
}

/// Post-process auto-probe output: parse structured sections, decode
/// values, add source lines + bootlin links via blazesym.
/// Merge multiple auto-probe bpftrace outputs into one unified block.
/// Deduplicates function sections and call chains.
fn merge_autoprobe_outputs(outputs: &[String]) -> String {
    let mut seen_funcs = std::collections::HashSet::new();
    let mut merged_sections = Vec::new();
    let mut call_chain = String::new();
    let mut raw_section = String::new();
    let mut header = String::new();

    for output in outputs {
        let mut in_chain = false;
        let mut in_raw = false;
        let mut current_section: Option<(String, Vec<String>)> = None;

        for line in output.lines() {
            if line.contains("---RAW---") {
                in_raw = true;
                if let Some(sec) = current_section.take() {
                    if seen_funcs.insert(sec.0.clone()) {
                        merged_sections.push(sec);
                    }
                }
                continue;
            }
            if line.contains("---ENDRAW---") {
                in_raw = false;
                continue;
            }
            if in_raw {
                if raw_section.is_empty() {
                    raw_section = line.to_string();
                } else {
                    raw_section.push('\n');
                    raw_section.push_str(line);
                }
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("call chain:") {
                in_chain = true;
                if let Some(sec) = current_section.take() {
                    if seen_funcs.insert(sec.0.clone()) {
                        merged_sections.push(sec);
                    }
                }
                continue;
            }
            if in_chain {
                if trimmed.starts_with("---") || trimmed.starts_with("VIOLATION") {
                    in_chain = false;
                } else if call_chain.is_empty() || !call_chain.contains(trimmed) {
                    if call_chain.is_empty() {
                        call_chain = trimmed.to_string();
                    } else {
                        call_chain.push('\n');
                        call_chain.push_str(trimmed);
                    }
                    continue;
                } else {
                    continue;
                }
            }
            if trimmed.starts_with("--- ") && trimmed.ends_with(" ---") {
                if let Some(sec) = current_section.take() {
                    if seen_funcs.insert(sec.0.clone()) {
                        merged_sections.push(sec);
                    }
                }
                let name = trimmed.trim_start_matches("--- ").trim_end_matches(" ---");
                current_section = Some((name.to_string(), vec![line.to_string()]));
            } else if trimmed.starts_with("VIOLATION:") || trimmed.starts_with("trigger_") {
                if header.is_empty() {
                    header = line.to_string();
                }
            } else if let Some(ref mut sec) = current_section {
                sec.1.push(line.to_string());
            }
        }
        if let Some(sec) = current_section.take() {
            if seen_funcs.insert(sec.0.clone()) {
                merged_sections.push(sec);
            }
        }
    }

    // Reassemble: header + sections + call chain + RAW
    let mut out = String::new();
    out.push_str(&header);
    out.push('\n');
    for (_, lines) in &merged_sections {
        for line in lines {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str("  call chain:\n");
    for line in call_chain.lines() {
        out.push_str(&format!("        {line}\n"));
    }
    out.push_str("  ---RAW---\n");
    out.push_str(&raw_section);
    out.push_str("\n---ENDRAW---\n");
    out
}

fn postprocess_autoprobe(
    stdout: &str,
    kernel_dir: Option<&str>,
    _no_bootlin: bool,
    verbose: bool,
) -> String {
    use blazesym::symbolize::{self, Symbolizer};

    let raw = extract_section(stdout, "---RAW---", "---ENDRAW---");
    let main = stdout.split("---RAW---").next().unwrap_or(stdout).trim();
    let main = strip_abs_paths(main);

    // Symbolize: both raw kstack addresses AND function names from sections.
    // Collect all function names from "--- funcname ---" headers.
    let section_funcs: Vec<&str> = main
        .lines()
        .filter(|l| l.starts_with("--- ") && l.ends_with(" ---"))
        .filter_map(|l| {
            let f = l.trim_start_matches("--- ").trim_end_matches(" ---");
            Some(f.split(" (").next()?.trim())
        })
        .collect();

    // Look up function addresses from /proc/kallsyms for section funcs
    let kallsyms = std::fs::read_to_string("/proc/kallsyms").unwrap_or_default();
    let mut func_addrs: Vec<(String, u64)> = Vec::new();
    for func in &section_funcs {
        for line in kallsyms.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == *func {
                if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                    func_addrs.push((func.to_string(), addr));
                    break;
                }
            }
        }
    }

    // Combine with raw kstack addresses
    let raw_addrs: Vec<u64> = raw
        .lines()
        .filter_map(|l| u64::from_str_radix(l.trim(), 16).ok())
        .collect();
    let all_addrs: Vec<u64> = func_addrs
        .iter()
        .map(|(_, a)| *a)
        .chain(raw_addrs.iter().copied())
        .collect();

    let mut sym_map: Vec<(String, String, u32)> = Vec::new();
    if !all_addrs.is_empty() {
        let mut ksrc = symbolize::source::Kernel {
            debug_syms: true,
            ..Default::default()
        };
        if let Some(kd) = kernel_dir {
            let vmlinux = std::path::PathBuf::from(kd).join("vmlinux");
            if vmlinux.exists() {
                ksrc.vmlinux = vmlinux.into();
            }
        }
        let symbolizer = Symbolizer::builder().enable_code_info(true).build();
        let src = symbolize::source::Source::Kernel(ksrc);
        if let Ok(results) = symbolizer.symbolize(&src, symbolize::Input::AbsAddr(&all_addrs)) {
            for result in &results {
                if let Some(sym) = result.as_sym() {
                    if let Some(ref ci) = sym.code_info {
                        let path = ci.to_path();
                        let rel = make_relative(&path.to_string_lossy());
                        sym_map.push((sym.name.to_string(), rel, ci.line.unwrap_or(0)));
                    }
                }
            }
        }
    }

    let _version = kernel_version(kernel_dir);
    let mut out = String::new();

    // Parse bpftrace output into sections: header + per-function blocks + call chain
    struct ProbeSection {
        func_name: String,
        is_bpf: bool,
        /// Named key=value pairs (from known funcs)
        named_args: Vec<(String, String)>,
        /// Raw arg0-arg3 values (from unknown funcs)
        raw_args: Vec<u64>,
        ts: u64,
    }

    let mut sections: Vec<ProbeSection> = Vec::new();
    let mut call_chain = String::new();
    let mut current: Option<ProbeSection> = None;

    for line in main.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("--- ") && trimmed.ends_with(" ---") {
            if let Some(s) = current.take() {
                sections.push(s);
            }
            let func = trimmed.trim_start_matches("--- ").trim_end_matches(" ---");
            let is_bpf = func.contains("(BPF)");
            let func_name = func.split(" (").next().unwrap_or(func).trim();
            current = Some(ProbeSection {
                func_name: func_name.to_string(),
                is_bpf,
                named_args: Vec::new(),
                raw_args: Vec::new(),
                ts: 0,
            });
        } else if trimmed.starts_with("call chain:") {
            if let Some(s) = current.take() {
                sections.push(s);
            }
        } else if trimmed.starts_with("VIOLATION:") || trimmed.starts_with("trigger_") {
            // skip header lines
        } else if let Some(ref mut sec) = current {
            // Parse key=value pairs. "STT_BPF_EXIT" separates entry from exit args.
            let (entry_part, exit_part) =
                trimmed.split_once("STT_BPF_EXIT").unwrap_or((trimmed, ""));
            let entry_part = entry_part.replace("STT_BPF_ENTER", "");
            for token in entry_part
                .split_whitespace()
                .chain(if exit_part.is_empty() {
                    None
                } else {
                    Some("STT_BPF_EXIT")
                })
                .chain(exit_part.split_whitespace())
            {
                if token == "STT_BPF_EXIT" {
                    continue;
                }
                if let Some((k, v)) = token.split_once('=') {
                    if k == "ts" {
                        sec.ts = v.parse().unwrap_or(0);
                    } else if k.starts_with("arg") {
                        let val = if let Some(hex) = v.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16).unwrap_or(0)
                        } else {
                            v.parse().unwrap_or(0)
                        };
                        sec.raw_args.push(val);
                    } else {
                        sec.named_args.push((k.to_string(), v.to_string()));
                    }
                }
            }
        } else if !trimmed.is_empty() && !trimmed.starts_with("ts=") {
            call_chain.push_str(trimmed);
            call_chain.push('\n');
        }
    }
    if let Some(s) = current.take() {
        sections.push(s);
    }

    // Skip sections with ts=0 (function never called for this tid)
    sections.retain(|s| s.ts > 0);

    // In brief mode, skip BPF sections where the bridge didn't fire
    // for the crashed task (seen flag not set)
    if !verbose {
        sections.retain(|s| {
            if s.is_bpf {
                s.named_args.iter().any(|(k, v)| k == "seen" && v != "0")
            } else {
                true
            }
        });
    }
    // Strip 'seen' from display — internal flag only
    for sec in &mut sections {
        sec.named_args.retain(|(k, _)| k != "seen");
    }

    // Sort by timestamp — all maps are now keyed by task_struct pointer
    // so timestamps are consistent for the crashed task.
    sections.sort_by_key(|s| s.ts);

    // Build compact output: one line per function
    out.push_str("=== AUTO-PROBE: scx_exit fired ===\n\n");

    let max_name = sections
        .iter()
        .map(|s| s.func_name.len())
        .max()
        .unwrap_or(0);
    for sec in &sections {
        // Source location
        let loc = sym_map.iter().find(|(n, _, _)| n == &sec.func_name);
        let loc_str = loc.map(|(_, f, l)| format!("{f}:{l}")).unwrap_or_default();

        // Format args. For BPF functions, detect entry=>exit transition
        // by finding the first duplicate key.
        let args_str = if !sec.named_args.is_empty() {
            let mut seen = std::collections::HashSet::new();
            let mut entry_parts = Vec::new();
            let mut exit_parts = Vec::new();
            let mut in_exit = false;
            for (k, v) in &sec.named_args {
                if sec.is_bpf && !in_exit && !seen.insert(k.as_str()) {
                    in_exit = true;
                }
                let decoded = decode_named_value(k, v);
                if in_exit {
                    exit_parts.push(format!("{k}={decoded}"));
                } else {
                    entry_parts.push(format!("{k}={decoded}"));
                }
            }
            entry_parts.join(" ")
        } else {
            // Raw args — use type:value inference
            sec.raw_args
                .iter()
                .map(|v| format_raw_arg(*v))
                .collect::<Vec<_>>()
                .join(" ")
        };

        if sec.is_bpf {
            // Sub-functions have no bridge data (few named_args after seen/ts stripped).
            // Indent them to show nesting under parent ops.
            let is_subprog = sec.named_args.len() <= 1; // only ts or empty
            let indent = if is_subprog { "    " } else { "" };

            let mut seen = std::collections::HashSet::new();
            let mut entry_args = Vec::new();
            let mut exit_args = Vec::new();
            let mut in_exit = false;
            for (k, v) in &sec.named_args {
                if !in_exit && !seen.insert(k.as_str()) {
                    in_exit = true;
                }
                let decoded = decode_named_value(k, v);
                if in_exit {
                    exit_args.push(format!("{k}={decoded}"));
                } else {
                    entry_args.push(format!("{k}={decoded}"));
                }
            }

            if is_subprog {
                out.push_str(&format!(
                    "  {indent}{:<nw$}\tSTT_BPF_SUBPROG\n",
                    sec.func_name,
                    nw = max_name
                ));
            } else {
                out.push_str(&format!(
                    "  {indent}{:<nw$}\tSTT_BPF_ENTER\t{}\n",
                    sec.func_name,
                    entry_args.join(" "),
                    nw = max_name
                ));
                if !exit_args.is_empty() {
                    out.push_str(&format!(
                        "  {indent}{:<nw$}\tSTT_BPF_EXIT\t{}\n",
                        sec.func_name,
                        exit_args.join(" "),
                        nw = max_name
                    ));
                }
            }
        } else {
            out.push_str(&format!(
                "  {:<nw$}\tKERNEL\t{:<40}\t{args_str}\n",
                sec.func_name,
                loc_str,
                nw = max_name
            ));
        }
    }

    // Raw call chain (verbose only — enriched data above is sufficient)
    if verbose && !call_chain.is_empty() {
        out.push('\n');
        for line in call_chain.lines() {
            out.push_str(&format!("  {line}\n"));
        }
    }

    out
}

/// Decode a named key=value pair from a known function.
fn decode_named_value(key: &str, val: &str) -> String {
    let as_u64 = || -> u64 {
        if let Some(hex) = val.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).unwrap_or(0)
        } else {
            val.parse().unwrap_or(0)
        }
    };

    match key {
        "dsq_id" | "dsq" => decode_dsq_id(as_u64()),
        "cpus_ptr" | "cpus" => {
            let v = as_u64();
            format!("0x{v:x}({cpus})", cpus = decode_cpumask(v))
        }
        "enforce" => {
            if val == "1" || val == "true" {
                "true".into()
            } else {
                "false".into()
            }
        }
        "enq_flags" | "enq" | "enqflags" => decode_enq_flags(as_u64()),
        "exit_kind" => decode_exit_kind(as_u64()),
        "sticky_cpu" | "sticky" => {
            let v = as_u64();
            if v == 0xffffffff || v == 0xffffffffffffffff {
                "-1".into()
            } else {
                format!("{v}")
            }
        }
        "cpu" | "rq_cpu" | "dst_cpu" | "dest_cpu" => val.to_string(),
        "pid" => val.to_string(),
        "task" => val.to_string(),
        "slice" | "vtime" => {
            let v = as_u64();
            if v == 0 {
                "0".into()
            } else {
                format!("{v}")
            }
        }
        "weight" => val.to_string(),
        "flags" => {
            let v = as_u64();
            let mut parts = Vec::new();
            if v & 1 != 0 {
                parts.push("QUEUED");
            }
            if v & 4 != 0 {
                parts.push("RESET_RUNNABLE_AT");
            }
            if v & 8 != 0 {
                parts.push("DEQD_FOR_SLEEP");
            }
            if parts.is_empty() {
                format!("0x{v:x}")
            } else {
                parts.join("|")
            }
        }
        _ => val.to_string(),
    }
}

/// Enrich a line with decoded dsq_id and cpumask values.
fn enrich_values(line: &str) -> String {
    let mut result = line.to_string();

    // Decode dsq_id=0x... → dsq_id=LOCAL_ON | CPU N (0x...)
    if let Some(idx) = result.find("dsq_id=0x") {
        let start = idx + "dsq_id=".len();
        let hex_str = &result[start..];
        let end = hex_str
            .find(|c: char| !c.is_ascii_hexdigit() && c != 'x')
            .unwrap_or(hex_str.len());
        if let Ok(val) = u64::from_str_radix(hex_str[2..end].trim(), 16) {
            let decoded = decode_dsq_id(val);
            let original = &result[start..start + end];
            result = result.replace(
                &format!("dsq_id={original}"),
                &format!("dsq_id={decoded} ({original})"),
            );
        }
    }

    // Decode cpus_ptr=0x... → cpus_ptr=0x... (CPUs ...)
    for prefix in ["cpus_ptr=0x", "cpus=0x"] {
        if let Some(idx) = result.find(prefix) {
            let val_start = idx + prefix.len() - 2; // include 0x
            let hex_part = &result[val_start + 2..];
            let end = hex_part
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(hex_part.len());
            if let Ok(val) = u64::from_str_radix(&hex_part[..end], 16) {
                let original = &result[val_start..val_start + 2 + end];
                let decoded = decode_cpumask(val);
                result = result.replacen(original, &format!("{original} ({decoded})"), 1);
            }
        }
    }

    result
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

/// Strip bpftrace map dump lines (@ prefix) from output.
fn strip_map_dumps(s: &str) -> String {
    s.lines()
        .filter(|l| !l.starts_with("@"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Run a bpftrace script, return raw stdout (no postprocessing).
fn run_bpftrace_raw(script: &str, stop: &std::sync::atomic::AtomicBool) -> Option<String> {
    use std::sync::atomic::Ordering;

    let script_path = match resolve_assert_script(script) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(%e, "failed to resolve script");
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

    tracing::debug!("bpftrace started");

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut buf = String::new();
                        let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                        buf
                    })
                    .unwrap_or_default();

                let stdout = strip_map_dumps(&stdout);
                if stdout.contains("VIOLATION") || stdout.contains("RACE") {
                    return Some(stdout);
                }
                if !_status.success() {
                    let stderr = child
                        .stderr
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    tracing::warn!(code = _status.code(), %stderr, "bpftrace exited with error");
                }
                return None;
            }
            Ok(None) => {
                if stop.load(Ordering::Relaxed) {
                    for _ in 0..10 {
                        std::thread::sleep(Duration::from_millis(100));
                        if let Ok(Some(_)) = child.try_wait() {
                            let stdout = child
                                .stdout
                                .take()
                                .map(|mut s| {
                                    let mut buf = String::new();
                                    let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                                    buf
                                })
                                .unwrap_or_default();
                            if stdout.contains("VIOLATION") || stdout.contains("RACE") {
                                return Some(stdout);
                            }
                            return None;
                        }
                    }
                    use nix::sys::signal::{kill, Signal};
                    use nix::unistd::Pid;
                    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
                    let _ = child.wait();
                    let stdout = child
                        .stdout
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    if stdout.contains("VIOLATION") || stdout.contains("RACE") {
                        return Some(stdout);
                    }
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

fn run_assert_script(
    script: &str,
    kernel_dir: Option<&str>,
    no_bootlin: bool,
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

    tracing::debug!("bpftrace assertion checker started");

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
                    return Some(if stdout.contains("auto-probe") {
                        postprocess_autoprobe(&stdout, kernel_dir, no_bootlin, false)
                    } else {
                        postprocess_violation(&stdout, kernel_dir, no_bootlin)
                    });
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
                    // Give bpftrace time to drain its perf buffer
                    // before killing — exit() in the kprobe is async.
                    for _ in 0..10 {
                        std::thread::sleep(Duration::from_millis(100));
                        if let Ok(Some(_)) = child.try_wait() {
                            let stdout = child
                                .stdout
                                .take()
                                .map(|mut s| {
                                    let mut buf = String::new();
                                    let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                                    buf
                                })
                                .unwrap_or_default();
                            if stdout.contains("VIOLATION") || stdout.contains("RACE") {
                                tracing::warn!("assertion violated");
                                return Some(if stdout.contains("auto-probe") {
                                    postprocess_autoprobe(&stdout, kernel_dir, no_bootlin, false)
                                } else {
                                    postprocess_violation(&stdout, kernel_dir, no_bootlin)
                                });
                            }
                            return None;
                        }
                    }
                    use nix::sys::signal::{kill, Signal};
                    use nix::unistd::Pid;
                    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
                    let _ = child.wait();
                    // Read stdout even after kill — data may be buffered
                    let stdout = child
                        .stdout
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    if stdout.contains("VIOLATION") || stdout.contains("RACE") {
                        tracing::warn!("assertion violated (caught during drain)");
                        return Some(if stdout.contains("auto-probe") {
                            postprocess_autoprobe(&stdout, kernel_dir, no_bootlin, false)
                        } else {
                            postprocess_violation(&stdout, kernel_dir, no_bootlin)
                        });
                    }
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
fn postprocess_violation(stdout: &str, kernel_dir: Option<&str>, no_bootlin: bool) -> String {
    use blazesym::symbolize::{self, Symbolizer};
    tracing::debug!(?kernel_dir, "postprocessing violation");

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

    let mut ksrc = symbolize::source::Kernel {
        debug_syms: true,
        ..Default::default()
    };
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
        if no_bootlin {
            local_lines.push(format!("    {:<nw$} @ {loc}", f.name, nw = max_name));
        } else {
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
    if let Some(rest) = path.strip_prefix("./") {
        return rest.to_string();
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
