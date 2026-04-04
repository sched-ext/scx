#![allow(dead_code)]

mod cgroup;
mod runner;
mod scenario;
mod topology;
mod verify;
mod vng;
mod workload;

use std::io::Write;

use anyhow::Result;
use clap::Parser;
use console::style;

use runner::{RunConfig, Runner};
use topology::TestTopology;

#[derive(Debug, Parser)]
#[clap(
    name = "stt",
    about = "scx test tools - scheduler fuzzer for sched_ext"
)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Run test scenarios
    Run(RunArgs),
    /// Launch VNG VM(s) and run tests inside
    Vm(VmArgs),
    /// List available scenarios
    List,
    /// Show CPU topology
    Topo,
    /// Clean up test cgroups
    Cleanup(CleanupArgs),
}

#[derive(Debug, Parser)]
struct RunArgs {
    scenarios: Vec<String>,
    #[clap(long)]
    all: bool,
    #[clap(long)]
    mitosis_bin: Option<String>,
    #[clap(long, default_value = "/sys/fs/cgroup/stt")]
    parent_cgroup: String,
    #[clap(long, default_value = "15")]
    duration_s: u64,
    #[clap(long, default_value = "4")]
    workers: usize,
    #[clap(long)]
    json: bool,
    #[clap(long)]
    verbose: bool,
    #[clap(long, conflicts_with = "flags")]
    all_flags: bool,
    #[clap(long, value_delimiter = ',')]
    flags: Vec<String>,
    /// Log unfairness but don't fail on it
    #[clap(long)]
    warn_unfair: bool,
    /// Reproducer mode: extend watchdog, disable dump trigger, run
    /// bpftrace assertion scripts to catch invariant violations.
    #[clap(long)]
    repro: bool,
    /// bpftrace assertion script (name or path). Runs during repro mode;
    /// exits on invariant violation.
    #[clap(long, conflicts_with = "probe_stack")]
    assert_script: Option<String>,
    /// Auto-probe: crash stack trace (file path or comma-separated function
    /// names). Generates a bpftrace script that captures arguments at each
    /// function in the crash chain. Implies --repro.
    #[clap(long, conflicts_with = "assert_script")]
    probe_stack: Option<String>,
    /// Auto-repro: crash once to get the stack, then automatically rerun
    /// with --probe-stack to capture arguments at each function. Implies --repro.
    #[clap(long, conflicts_with_all = ["assert_script", "probe_stack"])]
    auto_repro: bool,
    /// Include bootlin URLs in source line output
    #[clap(long)]
    bootlin: bool,
    /// Path to linux source tree (for VNG kernel boot and symbolization)
    #[clap(long)]
    kernel_dir: Option<String>,
}

#[derive(Debug, Parser)]
struct VmArgs {
    #[clap(long)]
    kernel: Option<String>,
    #[clap(long, default_value = "2")]
    sockets: usize,
    #[clap(long, default_value = "2")]
    cores: usize,
    #[clap(long, default_value = "2")]
    threads: usize,
    #[clap(long, default_value = "4096")]
    memory_mb: usize,
    #[clap(long)]
    gauntlet: bool,
    #[clap(long)]
    parallel: Option<usize>,
    #[clap(long)]
    vng_arg: Vec<String>,
    /// Flags to enable for gauntlet runs (comma-separated short names).
    /// Without this, gauntlet uses each scenario's default profiles.
    #[clap(long, value_delimiter = ',')]
    flags: Vec<String>,
    /// Linux source tree with built kernel (boots this instead of host kernel)
    #[clap(long)]
    kernel_dir: Option<String>,
    #[clap(last = true)]
    run_args: Vec<String>,
}

#[derive(Debug, Parser)]
struct CleanupArgs {
    #[clap(long, default_value = "/sys/fs/cgroup/stt")]
    parent_cgroup: String,
}

fn main() -> Result<()> {
    // Tracing to stderr - inner stt (in VM) uses stdout for JSON/table output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("stt=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();
    vng::install_signal_handler();
    match Cli::parse().command {
        Command::Run(a) => cmd_run(a),
        Command::Vm(a) => {
            if a.gauntlet {
                cmd_gauntlet(&a)
            } else {
                cmd_vm(a)
            }
        }
        Command::List => cmd_list(),
        Command::Topo => cmd_topo(),
        Command::Cleanup(a) => {
            cgroup::CgroupManager::new(&a.parent_cgroup).cleanup_all()?;
            Ok(())
        }
    }
}

fn parse_flags(args: &RunArgs) -> Option<Vec<scenario::Flag>> {
    if args.all_flags {
        return None;
    }
    if args.flags.is_empty() {
        return Some(vec![]);
    }
    Some(
        args.flags
            .iter()
            .map(|s| {
                scenario::Flag::from_short_name(s).unwrap_or_else(|| {
                    let all: Vec<&str> = scenario::Flag::all()
                        .iter()
                        .map(|f| f.short_name())
                        .collect();
                    println!(
                        "{} unknown flag: {s}\navailable: {}",
                        style("error:").red().bold(),
                        all.join(", ")
                    );
                    std::process::exit(1);
                })
            })
            .collect(),
    )
}

fn cmd_run(args: RunArgs) -> Result<()> {
    let topo = TestTopology::from_system()?;
    let scenarios = scenario::all_scenarios();
    let selected: Vec<_> = if args.all || args.scenarios.is_empty() {
        scenarios.iter().collect()
    } else {
        args.scenarios
            .iter()
            .map(|name| {
                scenarios
                    .iter()
                    .find(|s| s.name == name.as_str())
                    .unwrap_or_else(|| {
                        let names: Vec<&str> = scenarios.iter().map(|s| s.name).collect();
                        println!(
                            "{} unknown scenario: {name}\navailable: {}",
                            style("error:").red().bold(),
                            names.join(", ")
                        );
                        std::process::exit(1);
                    })
            })
            .collect()
    };
    let active_flags = parse_flags(&args);
    let mitosis_bin = args.mitosis_bin.unwrap_or_else(default_mitosis_bin);
    if args.warn_unfair {
        verify::set_warn_unfair(true);
    }
    let repro = args.repro || args.probe_stack.is_some() || args.auto_repro;
    if repro {
        workload::set_repro_mode(true);
    }
    let config = RunConfig {
        mitosis_bin,
        parent_cgroup: args.parent_cgroup,
        duration_s: args.duration_s,
        workers_per_cell: args.workers,
        json: args.json,
        verbose: args.verbose,
        active_flags,
        repro,
        assert_script: args.assert_script,
        probe_stack: args.probe_stack,
        auto_repro: args.auto_repro,
        bootlin: args.bootlin,
        kernel_dir: args.kernel_dir,
    };
    let mut results = Runner::new(config.clone(), topo.clone())?.run_scenarios(&selected)?;
    let failed = results.iter().filter(|r| !r.passed).count();

    // Auto-repro: if run 1 crashed, extract function names and rerun with --probe-stack
    if config.auto_repro && failed > 0 && config.probe_stack.is_none() {
        // Look for the suggestion line from run_scenarios, or fall back to stack extraction
        let all_text: String = results
            .iter()
            .flat_map(|r| r.details.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let names: Option<String> = all_text
            .lines()
            .find(|l| l.contains("functions:"))
            .map(|l| {
                l.split("functions:")
                    .nth(1)
                    .unwrap_or("")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .or_else(|| {
                let fns = runner::extract_stack_functions_all_pub(&all_text);
                if fns.is_empty() {
                    None
                } else {
                    Some(fns.join(","))
                }
            });
        if let Some(ref names) = names {
            let fn_count = names.split(',').count();
            println!(
                "\n{} auto-repro: rerunning with --probe-stack ({fn_count} functions)\n",
                style(">>>").cyan().bold(),
            );
            let mut config2 = config;
            config2.probe_stack = Some(names.clone());
            results = Runner::new(config2, topo)?.run_scenarios(&selected)?;
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print_results(&results);
    }
    let failed = results.iter().filter(|r| !r.passed).count();
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_vm(args: VmArgs) -> Result<()> {
    let topo = vng::VngTopology {
        sockets: args.sockets,
        cores_per_socket: args.cores,
        threads_per_core: args.threads,
    };

    // Parse scenario names and options from run_args.
    // Options (--foo bar or --foo=bar) go to extra_args, bare words are scenarios.
    let mut scenario_names = Vec::new();
    let mut extra_args = Vec::new();
    let run_all = args.run_args.is_empty();
    {
        let mut iter = args.run_args.iter().peekable();
        while let Some(a) = iter.next() {
            if a.starts_with('-') {
                extra_args.push(a.clone());
                // --key value (not --key=value): consume the next arg too
                if !a.contains('=') {
                    if let Some(v) = iter.peek() {
                        if !v.starts_with('-') {
                            extra_args.push(iter.next().unwrap().clone());
                        }
                    }
                }
            } else {
                scenario_names.push(a.clone());
            }
        }
    }

    let max_par = args.parallel.unwrap_or(1);
    if max_par > 1 && !scenario_names.is_empty() {
        return cmd_vm_parallel(&args, &topo, &scenario_names, &extra_args, max_par);
    }

    // Single-VM mode (original behavior)
    let cfg = vng::VngConfig {
        kernel: args.kernel,
        memory_mb: args.memory_mb,
        vng_args: args.vng_arg,
        topology: topo,
        timeout: None,
        kernel_dir: args.kernel_dir,
    };
    let t = &cfg.topology;
    println!(
        "{} VM: {} CPUs, {} LLCs",
        style("launching").cyan().bold(),
        t.total_cpus(),
        t.num_llcs()
    );
    let mut stt_args = vec!["run".into(), "--mitosis-bin".into(), default_mitosis_bin()];
    if let Some(ref kd) = cfg.kernel_dir {
        stt_args.push("--kernel-dir".into());
        stt_args.push(kd.clone());
    }
    if run_all {
        stt_args.push("--all".into());
    } else {
        stt_args.extend(args.run_args);
    }
    let r = vng::run_in_vng(&cfg, &stt_args)?;
    if !r.output.is_empty() {
        print!("{}", r.output);
    }
    if !r.stderr.is_empty() {
        eprint!("{}", r.stderr);
    }
    if r.timed_out {
        println!("{} timed out", style("FAIL").red().bold());
        std::process::exit(1);
    }
    if !r.success {
        println!("{} exit {}", style("FAIL").red().bold(), r.exit_code);
        std::process::exit(1);
    }
    println!(
        "{} ({:.1}s)",
        style("PASS").green().bold(),
        r.duration.as_secs_f64()
    );
    Ok(())
}

fn cmd_vm_parallel(
    args: &VmArgs,
    topo: &vng::VngTopology,
    scenarios: &[String],
    extra_args: &[String],
    max_par: usize,
) -> Result<()> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::thread;

    let total = scenarios.len();
    println!(
        "{} {} VMs, {} parallel, {} CPUs, {} LLCs",
        style("launching").cyan().bold(),
        total,
        max_par,
        topo.total_cpus(),
        topo.num_llcs()
    );

    let results: Arc<Mutex<Vec<(String, bool, f64, String, Vec<runner::ScenarioResult>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let fail_count = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for sname in scenarios {
        while in_flight.load(Ordering::Relaxed) >= max_par {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        in_flight.fetch_add(1, Ordering::Relaxed);

        let (kernel, vng_extra) = (args.kernel.clone(), args.vng_arg.clone());
        let kernel_dir = args.kernel_dir.clone();
        let mem = args.memory_mb;
        let topo = topo.clone();
        let sname = sname.clone();
        let extra_args = extra_args.to_vec();
        let results = Arc::clone(&results);
        let completed = Arc::clone(&completed);
        let fail_count = Arc::clone(&fail_count);
        let in_flight = Arc::clone(&in_flight);

        handles.push(thread::spawn(move || {
            let mut stt_args = vec![
                "run".to_string(),
                "--json".to_string(),
                "--mitosis-bin".to_string(),
                default_mitosis_bin(),
                sname.clone(),
            ];
            stt_args.extend(extra_args);

            let mut ok = false;
            let mut dur = 0.0;
            let mut detail = String::new();
            let mut inner_results = vec![];
            let timeout = vng::compute_timeout(1, 20, topo.total_cpus());

            for attempt in 0..3 {
                let cfg = vng::VngConfig {
                    kernel: kernel.clone(),
                    topology: topo.clone(),
                    memory_mb: mem,
                    vng_args: vng_extra.clone(),
                    timeout: Some(timeout),
                    kernel_dir: kernel_dir.clone(),
                };
                let (a_ok, a_dur, a_detail, a_inner) = match vng::run_in_vng(&cfg, &stt_args) {
                    Ok(r) if r.timed_out => {
                        (false, r.duration.as_secs_f64(), "timed out".into(), vec![])
                    }
                    Ok(r) => {
                        let parsed: Vec<runner::ScenarioResult> = extract_json(&r.output);
                        let d = if parsed.is_empty() {
                            let last_err = r
                                .stderr
                                .lines()
                                .rev()
                                .find(|l| !l.trim().is_empty())
                                .unwrap_or("no output");
                            format!("VM failed: {}", &last_err[..last_err.len().min(120)])
                        } else {
                            String::new()
                        };
                        (
                            r.success && !parsed.iter().any(|r| !r.passed),
                            r.duration.as_secs_f64(),
                            d,
                            parsed,
                        )
                    }
                    Err(e) => (false, 0.0, format!("{e:#}"), vec![]),
                };
                ok = a_ok;
                dur = a_dur;
                detail = a_detail.clone();
                inner_results = a_inner;
                if ok || !is_infra_failure(&inner_results, &a_detail) {
                    break;
                }
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }

            let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
            let status = if ok { "PASS" } else { "FAIL" };

            let stats_str = inner_results
                .first()
                .map(format_gauntlet_stats)
                .unwrap_or_default();
            let detail_str = format_gauntlet_detail(ok, &detail, &inner_results);

            println!("[{n}/{total}] {status} {sname} ({dur:.0}s){stats_str}{detail_str}");
            if !ok {
                fail_count.fetch_add(1, Ordering::Relaxed);
                for r in inner_results.iter().filter(|r| !r.passed) {
                    for d in &r.details {
                        println!("  {d}");
                    }
                }
            }

            results
                .lock()
                .unwrap()
                .push((sname, ok, dur, detail, inner_results));
            in_flight.fetch_sub(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let results = results.lock().unwrap();
    let passed = results.iter().filter(|r| r.1).count();
    let failed: Vec<_> = results.iter().filter(|r| !r.1).collect();

    println!("\n=== {}/{} passed ===", passed, results.len());

    if !failed.is_empty() {
        println!("\nFailed:");
        for (name, _, _, d, inner) in &failed {
            println!("\n  {name}:");
            if !d.is_empty() {
                println!("    {d}");
            }
            for r in inner.iter().filter(|r| !r.passed) {
                for detail in &r.details {
                    println!("    {detail}");
                }
            }
        }
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_gauntlet(args: &VmArgs) -> Result<()> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::thread;

    let presets = vng::gauntlet_presets();
    let scenarios = scenario::all_scenarios();
    let max_par = args.parallel.unwrap_or_else(|| (num_cpus() / 8).max(1));

    let gauntlet_flags: Vec<scenario::Flag> = args
        .flags
        .iter()
        .map(|s| {
            scenario::Flag::from_short_name(s).unwrap_or_else(|| {
                let all: Vec<&str> = scenario::Flag::all()
                    .iter()
                    .map(|f| f.short_name())
                    .collect();
                eprintln!("error: unknown flag: {s}\navailable: {}", all.join(", "));
                std::process::exit(1);
            })
        })
        .collect();
    let fixed_profile = if gauntlet_flags.is_empty() {
        None
    } else {
        Some(scenario::FlagProfile {
            flags: gauntlet_flags,
        })
    };

    let mut jobs = Vec::new();
    for p in &presets {
        for s in &scenarios {
            let profiles = if let Some(ref fp) = fixed_profile {
                vec![fp.clone()]
            } else {
                s.profiles_with(&[])
            };
            for prof in profiles {
                let mut stt_args = vec![
                    "run".to_string(),
                    "--json".to_string(),
                    "--mitosis-bin".to_string(),
                    default_mitosis_bin(),
                    "--duration-s".to_string(),
                    "20".to_string(),
                    s.name.to_string(),
                ];
                if !prof.flags.is_empty() {
                    let names: Vec<&str> = prof.flags.iter().map(|f| f.short_name()).collect();
                    stt_args.push(format!("--flags={}", names.join(",")));
                }
                jobs.push((
                    p.name,
                    p.topology.clone(),
                    p.memory_mb,
                    s.name,
                    prof.name(),
                    stt_args,
                ));
            }
        }
    }

    let total = jobs.len();
    let results: Arc<Mutex<Vec<(String, bool, f64, String, Vec<runner::ScenarioResult>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let fail_count = Arc::new(AtomicUsize::new(0));

    println!("gauntlet: {} VMs, {} parallel", total, max_par);

    let in_flight = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for (pname, topo, mem, sname, profname, stt_args) in &jobs {
        // Wait until a slot is free
        while in_flight.load(Ordering::Relaxed) >= max_par {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        in_flight.fetch_add(1, Ordering::Relaxed);

        let (kernel, vng_extra) = (args.kernel.clone(), args.vng_arg.clone());
        let kernel_dir = args.kernel_dir.clone();
        let (results, completed, fail_count) = (
            Arc::clone(&results),
            Arc::clone(&completed),
            Arc::clone(&fail_count),
        );
        let (topo, mem, stt_args) = (topo.clone(), *mem, stt_args.clone());
        let in_flight = Arc::clone(&in_flight);
        let label = format!("{pname}/{sname}/{profname}");
        handles.push(thread::spawn(move || {
            let mut ok = false;
            let mut dur = 0.0;
            let mut detail = String::new();
            let mut inner_results = vec![];
            let timeout = vng::compute_timeout(1, 20, topo.total_cpus());
            for attempt in 0..3 {
                let cfg = vng::VngConfig {
                    kernel: kernel.clone(),
                    topology: topo.clone(),
                    memory_mb: mem,
                    vng_args: vng_extra.clone(),
                    timeout: Some(timeout),
                    kernel_dir: kernel_dir.clone(),
                };
                let (a_ok, a_dur, a_detail, a_inner) = match vng::run_in_vng(&cfg, &stt_args) {
                    Ok(r) if r.timed_out => {
                        (false, r.duration.as_secs_f64(), "timed out".into(), vec![])
                    }
                    Ok(r) => {
                        let parsed: Vec<runner::ScenarioResult> = extract_json(&r.output);
                        let d = if parsed.is_empty() {
                            let last_err = r
                                .stderr
                                .lines()
                                .rev()
                                .find(|l| !l.trim().is_empty())
                                .unwrap_or("no output");
                            format!("VM failed: {}", &last_err[..last_err.len().min(120)])
                        } else {
                            String::new()
                        };
                        (
                            r.success && !parsed.iter().any(|r| !r.passed),
                            r.duration.as_secs_f64(),
                            d,
                            parsed,
                        )
                    }
                    Err(e) => (false, 0.0, format!("{e:#}"), vec![]),
                };
                ok = a_ok;
                dur = a_dur;
                detail = a_detail.clone();
                inner_results = a_inner;
                if ok || !is_infra_failure(&inner_results, &a_detail) {
                    break;
                }
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
            let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
            let is_skip = inner_results
                .iter()
                .any(|r| r.details.iter().any(|d| d.contains("skipped")));
            let status = if is_skip {
                "SKIP"
            } else if ok {
                "PASS"
            } else {
                "FAIL"
            };

            let stats_str = inner_results
                .first()
                .map(format_gauntlet_stats)
                .unwrap_or_default();
            let detail_str = format_gauntlet_detail(ok, &detail, &inner_results);

            // ALL output to stdout
            println!("[{n}/{total}] {status} {label} ({dur:.0}s){stats_str}{detail_str}");
            if !ok {
                fail_count.fetch_add(1, Ordering::Relaxed);
                for r in inner_results.iter().filter(|r| !r.passed) {
                    for d in &r.details {
                        println!("  {d}");
                    }
                }
            }

            results
                .lock()
                .unwrap()
                .push((label, ok, dur, detail, inner_results));
            in_flight.fetch_sub(1, Ordering::Relaxed);
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let results = results.lock().unwrap();
    let passed = results.iter().filter(|r| r.1).count();
    let failed: Vec<_> = results.iter().filter(|r| !r.1).collect();

    println!("\n=== GAUNTLET: {}/{} passed ===", passed, results.len());

    if !failed.is_empty() {
        println!("\nFailed:");
        for (l, _, _, d, inner) in &failed {
            println!("\n  {l}:");
            if !d.is_empty() {
                println!("    {d}");
            }
            for r in inner.iter().filter(|r| !r.passed) {
                for detail in &r.details {
                    println!("    {detail}");
                }
            }
        }
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_list() -> Result<()> {
    let scenarios = scenario::all_scenarios();
    let mut total = 0;
    for s in &scenarios {
        let n = s.profiles().len();
        total += n;
        println!(
            "{:<25} {:<12} {:>3}  {}",
            s.name, s.category, n, s.description
        );
    }
    println!(
        "\n{} scenarios, {} total runs with --all-flags",
        scenarios.len(),
        style(total).cyan().bold()
    );
    Ok(())
}

fn cmd_topo() -> Result<()> {
    let topo = TestTopology::from_system()?;
    println!(
        "{} CPUs, {} LLCs, {} NUMA\n",
        style(topo.total_cpus()).cyan().bold(),
        style(topo.num_llcs()).cyan().bold(),
        style(topo.num_numa_nodes()).cyan().bold()
    );
    for (i, llc) in topo.llcs().iter().enumerate() {
        let cpus = llc
            .cpus
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!("LLC {i} (NUMA {}): {cpus}", llc.numa_node);
    }
    Ok(())
}

fn format_results(results: &[runner::ScenarioResult]) -> String {
    let mut out = String::new();
    for r in results {
        let tag = if r.passed { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "{tag} {} ({:.1}s)\n",
            r.scenario_name, r.duration_s
        ));
        if !r.passed {
            for d in &r.details {
                out.push_str(&format!("  {d}\n"));
            }
        }
    }
    let (p, f) = (
        results.iter().filter(|r| r.passed).count(),
        results.iter().filter(|r| !r.passed).count(),
    );
    out.push('\n');
    if f > 0 {
        out.push_str(&format!("{f} failed, {p} passed\n"));
    } else {
        out.push_str(&format!("{p} passed\n"));
    }
    out
}

fn print_results(results: &[runner::ScenarioResult]) {
    let text = format_results(results);
    // Re-apply color for terminal output
    let mut out = std::io::stdout();
    for line in text.lines() {
        if line.starts_with("PASS ") {
            let _ = writeln!(out, "{} {}", style("PASS").green().bold(), &line[5..]);
        } else if line.starts_with("FAIL ") {
            let _ = writeln!(out, "{} {}", style("FAIL").red().bold(), &line[5..]);
        } else if line.ends_with("passed") && line.contains("failed") {
            let _ = writeln!(out, "{}", style(line).red().bold());
        } else if line.ends_with("passed") {
            let _ = writeln!(out, "{}", style(line).green().bold());
        } else {
            let _ = writeln!(out, "{line}");
        }
    }
}

fn format_gauntlet_stats(r: &runner::ScenarioResult) -> String {
    let s = &r.stats;
    let cells: Vec<String> = s
        .cells
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "c{}:{}w/{}c={:.0}-{:.0}%",
                i, c.num_workers, c.num_cpus, c.min_runnable_pct, c.max_runnable_pct
            )
        })
        .collect();
    let mut extra = String::new();
    if s.worst_spread > 15.0 {
        extra += &format!(" UNFAIR={:.0}%", s.worst_spread);
    }
    if s.worst_gap_ms > 100 {
        extra += &format!(" STUCK={}ms@cpu{}", s.worst_gap_ms, s.worst_gap_cpu);
    }
    format!(" {} mig={}{}", cells.join(" "), s.total_migrations, extra)
}

fn format_gauntlet_detail(
    ok: bool,
    detail: &str,
    inner_results: &[runner::ScenarioResult],
) -> String {
    if !ok && !detail.is_empty() {
        format!(" | {}", &detail[..detail.len().min(120)])
    } else if !ok && inner_results.is_empty() {
        " | VM failed (no results)".to_string()
    } else if !ok {
        let fail_d: Vec<String> = inner_results
            .iter()
            .filter(|r| !r.passed)
            .flat_map(|r| r.details.first().cloned())
            .collect();
        if !fail_d.is_empty() {
            format!(" | {}", &fail_d[0][..fail_d[0].len().min(120)])
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

fn is_infra_failure(inner_results: &[runner::ScenarioResult], detail: &str) -> bool {
    let all_details: String = inner_results
        .iter()
        .flat_map(|r| r.details.iter())
        .chain(std::iter::once(&detail.to_string()))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    all_details.contains("fork failed")
        || all_details.contains("timed out")
        || all_details.contains("no JSON")
        || all_details.contains("spawn")
        || all_details.contains("scheduler died")
        || all_details.contains("VM failed")
}

fn format_gauntlet_summary(failed: &[(String, Vec<String>)]) -> String {
    let mut out = String::new();
    for (label, details) in failed {
        out.push_str(&format!("\n  {label}:\n"));
        for d in details {
            out.push_str(&format!("    {d}\n"));
        }
    }
    out
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn extract_json(output: &str) -> Vec<runner::ScenarioResult> {
    if let Some(start) = output.find('[') {
        if let Some(end) = output.rfind(']') {
            if let Ok(parsed) = serde_json::from_str(&output[start..=end]) {
                return parsed;
            }
        }
    }
    vec![]
}

fn default_mitosis_bin() -> String {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("scx_mitosis");
        if sibling.exists() {
            return sibling.to_string_lossy().into();
        }
    }
    "scx_mitosis".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_valid() {
        let input = r#"[{"scenario_name":"test","passed":true,"duration_s":1.0,"details":[],"stats":{"cells":[],"total_workers":0,"total_cpus":0,"total_migrations":0,"worst_spread":0.0,"worst_gap_ms":0,"worst_gap_cpu":0}}]"#;
        let r = extract_json(input);
        assert_eq!(r.len(), 1);
        assert!(r[0].passed);
    }

    #[test]
    fn extract_json_with_prefix() {
        let input = "boot noise\n[{\"scenario_name\":\"t\",\"passed\":false,\"duration_s\":2.0,\"details\":[\"failed\"],\"stats\":{\"cells\":[],\"total_workers\":0,\"total_cpus\":0,\"total_migrations\":0,\"worst_spread\":0.0,\"worst_gap_ms\":0,\"worst_gap_cpu\":0}}]\nmore";
        let r = extract_json(input);
        assert_eq!(r.len(), 1);
        assert!(!r[0].passed);
    }

    #[test]
    fn extract_json_empty() {
        assert!(extract_json("").is_empty());
    }

    #[test]
    fn extract_json_invalid() {
        assert!(extract_json("[not json]").is_empty());
    }

    #[test]
    fn extract_json_no_brackets() {
        assert!(extract_json("no json here").is_empty());
    }

    #[test]
    fn extract_json_multiple_results() {
        let input = r#"[{"scenario_name":"a","passed":true,"duration_s":1.0,"details":[],"stats":{"cells":[],"total_workers":0,"total_cpus":0,"total_migrations":0,"worst_spread":0.0,"worst_gap_ms":0,"worst_gap_cpu":0}},{"scenario_name":"b","passed":false,"duration_s":2.0,"details":["err"],"stats":{"cells":[],"total_workers":0,"total_cpus":0,"total_migrations":0,"worst_spread":0.0,"worst_gap_ms":0,"worst_gap_cpu":0}}]"#;
        let r = extract_json(input);
        assert_eq!(r.len(), 2);
        assert!(r[0].passed);
        assert!(!r[1].passed);
        assert_eq!(r[1].details, vec!["err"]);
    }

    #[test]
    fn extract_json_empty_array() {
        assert!(extract_json("[]").is_empty());
    }

    #[test]
    fn extract_json_preserves_stats() {
        let input = r#"[{"scenario_name":"t","passed":true,"duration_s":1.0,"details":[],"stats":{"cells":[{"num_workers":4,"num_cpus":2,"avg_runnable_pct":50.0,"min_runnable_pct":40.0,"max_runnable_pct":60.0,"spread":20.0,"max_gap_ms":100,"max_gap_cpu":1,"total_migrations":5}],"total_workers":4,"total_cpus":2,"total_migrations":5,"worst_spread":20.0,"worst_gap_ms":100,"worst_gap_cpu":1}}]"#;
        let r = extract_json(input);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].stats.total_workers, 4);
        assert_eq!(r[0].stats.cells.len(), 1);
        assert_eq!(r[0].stats.cells[0].num_workers, 4);
    }

    fn sr(name: &str, passed: bool, dur: f64, details: Vec<&str>) -> runner::ScenarioResult {
        runner::ScenarioResult {
            scenario_name: name.into(),
            passed,
            duration_s: dur,
            details: details.into_iter().map(|s| s.into()).collect(),
            stats: Default::default(),
        }
    }

    #[test]
    fn format_results_pass_one_line() {
        let out = format_results(&[sr("proportional/default", true, 5.2, vec![])]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "PASS proportional/default (5.2s)");
        // No detail lines for pass
        assert!(!out.contains("  "));
    }

    #[test]
    fn format_results_fail_shows_details() {
        let out = format_results(&[sr(
            "proportional/default",
            false,
            6.7,
            vec![
                "unfair cell: spread=85%",
                "stuck 2448ms on cpu4",
                "sched_ext: mitosis disabled (stall)",
            ],
        )]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "FAIL proportional/default (6.7s)");
        assert_eq!(lines[1], "  unfair cell: spread=85%");
        assert_eq!(lines[2], "  stuck 2448ms on cpu4");
        assert_eq!(lines[3], "  sched_ext: mitosis disabled (stall)");
    }

    #[test]
    fn format_results_no_details_hidden_for_pass() {
        let out = format_results(&[
            sr("a/default", true, 3.0, vec![]),
            sr("b/default", false, 5.0, vec!["broken"]),
        ]);
        assert!(out.contains("PASS a/default (3.0s)"));
        assert!(out.contains("FAIL b/default (5.0s)"));
        assert!(out.contains("  broken"));
        assert!(out.contains("1 failed, 1 passed"));
    }

    #[test]
    fn format_results_all_pass_summary() {
        let out = format_results(&[
            sr("a/default", true, 1.0, vec![]),
            sr("b/default", true, 2.0, vec![]),
        ]);
        assert!(out.contains("2 passed"));
        assert!(!out.contains("failed"));
    }

    #[test]
    fn format_results_dump_lines_raw() {
        let out = format_results(&[sr(
            "test/default",
            false,
            1.0,
            vec![
                "scheduler died",
                "EXIT dump:",
                "cell[0] cpus=0-3 vtime=12345",
                "cell[1] cpus=4-7 vtime=67890",
            ],
        )]);
        // Each detail on its own line, indented, no | joining
        assert!(out.contains("  scheduler died\n"));
        assert!(out.contains("  EXIT dump:\n"));
        assert!(out.contains("  cell[0] cpus=0-3 vtime=12345\n"));
        assert!(out.contains("  cell[1] cpus=4-7 vtime=67890\n"));
        assert!(!out.contains(" | "));
    }

    #[test]
    fn format_results_dmesg_lines_raw() {
        let out = format_results(&[sr(
            "test/default",
            false,
            1.0,
            vec![
                "stuck 3000ms on cpu2",
                "sched_ext: BPF scheduler disabled (runnable task stall)",
                "sched_ext: mitosis: (worker)[42] failed to run for 3.0s",
            ],
        )]);
        assert!(out.contains("  sched_ext: BPF scheduler disabled (runnable task stall)\n"));
        assert!(out.contains("  sched_ext: mitosis: (worker)[42] failed to run for 3.0s\n"));
    }

    // -- gauntlet formatting tests --

    fn sr_with_stats(
        name: &str,
        passed: bool,
        cells: Vec<verify::CellStats>,
        spread: f64,
        gap_ms: u64,
        gap_cpu: usize,
        mig: u64,
    ) -> runner::ScenarioResult {
        runner::ScenarioResult {
            scenario_name: name.into(),
            passed,
            duration_s: 20.0,
            details: if passed { vec![] } else { vec!["stuck".into()] },
            stats: verify::ScenarioStats {
                cells,
                total_workers: 4,
                total_cpus: 4,
                total_migrations: mig,
                worst_spread: spread,
                worst_gap_ms: gap_ms,
                worst_gap_cpu: gap_cpu,
            },
        }
    }

    fn cell(workers: usize, cpus: usize, min: f64, max: f64) -> verify::CellStats {
        verify::CellStats {
            num_workers: workers,
            num_cpus: cpus,
            avg_runnable_pct: (min + max) / 2.0,
            min_runnable_pct: min,
            max_runnable_pct: max,
            spread: max - min,
            max_gap_ms: 0,
            max_gap_cpu: 0,
            total_migrations: 0,
        }
    }

    #[test]
    fn gauntlet_stats_basic() {
        let r = sr_with_stats(
            "test",
            true,
            vec![cell(4, 2, 50.0, 60.0), cell(4, 2, 55.0, 65.0)],
            10.0,
            50,
            0,
            7,
        );
        let s = format_gauntlet_stats(&r);
        assert!(s.contains("c0:4w/2c=50-60%"));
        assert!(s.contains("c1:4w/2c=55-65%"));
        assert!(s.contains("mig=7"));
        assert!(!s.contains("UNFAIR"));
        assert!(!s.contains("STUCK"));
    }

    #[test]
    fn gauntlet_stats_unfair() {
        let r = sr_with_stats("test", false, vec![cell(4, 2, 10.0, 80.0)], 70.0, 50, 0, 3);
        let s = format_gauntlet_stats(&r);
        assert!(s.contains("UNFAIR=70%"));
    }

    #[test]
    fn gauntlet_stats_stuck() {
        let r = sr_with_stats(
            "test",
            false,
            vec![cell(4, 2, 50.0, 60.0)],
            10.0,
            2500,
            3,
            5,
        );
        let s = format_gauntlet_stats(&r);
        assert!(s.contains("STUCK=2500ms@cpu3"));
    }

    #[test]
    fn gauntlet_stats_unfair_and_stuck() {
        let r = sr_with_stats(
            "test",
            false,
            vec![cell(4, 2, 10.0, 90.0)],
            80.0,
            3000,
            1,
            0,
        );
        let s = format_gauntlet_stats(&r);
        assert!(s.contains("UNFAIR=80%"));
        assert!(s.contains("STUCK=3000ms@cpu1"));
    }

    #[test]
    fn gauntlet_detail_vm_error() {
        let d = format_gauntlet_detail(false, "spawn failed", &[]);
        assert_eq!(d, " | spawn failed");
    }

    #[test]
    fn gauntlet_detail_no_results() {
        let d = format_gauntlet_detail(false, "", &[]);
        assert_eq!(d, " | VM failed (no results)");
    }

    #[test]
    fn gauntlet_detail_first_failure() {
        let d = format_gauntlet_detail(
            false,
            "",
            &[sr(
                "test",
                false,
                1.0,
                vec!["unfair cell: spread=85%", "stuck 2000ms"],
            )],
        );
        assert_eq!(d, " | unfair cell: spread=85%");
    }

    #[test]
    fn gauntlet_detail_pass_empty() {
        let d = format_gauntlet_detail(true, "", &[sr("test", true, 1.0, vec![])]);
        assert_eq!(d, "");
    }

    #[test]
    fn gauntlet_detail_truncates_long() {
        let long = "x".repeat(200);
        let d = format_gauntlet_detail(false, &long, &[]);
        assert!(d.len() <= 124); // " | " + 120 chars
    }

    #[test]
    fn is_infra_fork_failed() {
        assert!(is_infra_failure(&[], "fork failed: resource unavailable"));
    }

    #[test]
    fn is_infra_timed_out() {
        assert!(is_infra_failure(&[], "timed out"));
    }

    #[test]
    fn is_infra_vm_failed() {
        assert!(is_infra_failure(&[], "VM failed: no output"));
    }

    #[test]
    fn is_infra_scheduler_died() {
        assert!(is_infra_failure(
            &[sr("test", false, 1.0, vec!["scheduler died"])],
            ""
        ));
    }

    #[test]
    fn not_infra_real_failure() {
        assert!(!is_infra_failure(
            &[sr("test", false, 1.0, vec!["unfair cell: spread=85%"])],
            ""
        ));
    }

    #[test]
    fn not_infra_stuck() {
        assert!(!is_infra_failure(
            &[sr("test", false, 1.0, vec!["stuck 3000ms on cpu2"])],
            ""
        ));
    }

    #[test]
    fn gauntlet_summary_format() {
        let failed = vec![
            (
                "tiny-1llc/proportional/default".to_string(),
                vec![
                    "unfair cell: spread=85%".to_string(),
                    "stuck 2448ms on cpu4".to_string(),
                    "CELL[0] cpus=0-3 vtime=12345".to_string(),
                ],
            ),
            (
                "tiny-2llc/cpuset_aligned/default".to_string(),
                vec!["scheduler died".to_string()],
            ),
        ];
        let out = format_gauntlet_summary(&failed);
        assert!(out.contains("tiny-1llc/proportional/default:"));
        assert!(out.contains("    unfair cell: spread=85%"));
        assert!(out.contains("    stuck 2448ms on cpu4"));
        assert!(out.contains("    CELL[0] cpus=0-3 vtime=12345"));
        assert!(out.contains("tiny-2llc/cpuset_aligned/default:"));
        assert!(out.contains("    scheduler died"));
    }

    #[test]
    fn gauntlet_summary_includes_dumps() {
        let failed = vec![(
            "test/default".to_string(),
            vec![
                "stuck 2700ms on cpu2".to_string(),
                "DEBUG DUMP".to_string(),
                "CELL[0] CPUS=00000007".to_string(),
                "CPU[0] cell=0 vtime=3437274".to_string(),
                "R stt-bin[204] -1278ms".to_string(),
            ],
        )];
        let out = format_gauntlet_summary(&failed);
        assert!(out.contains("    DEBUG DUMP"));
        assert!(out.contains("    CELL[0] CPUS=00000007"));
        assert!(out.contains("    CPU[0] cell=0 vtime=3437274"));
        assert!(out.contains("    R stt-bin[204] -1278ms"));
    }
}
