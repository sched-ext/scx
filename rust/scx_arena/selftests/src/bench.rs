// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! BPF Arena Priority Queue Throughput Benchmark
//!
//! Measures concurrent insert/pop throughput and per-op latency for
//! RPQ (MultiQueue) with configurable (nr_queues, pick-d) parameters,
//! plus ATQ (single-lock rbtree) as a baseline.

mod bpf_skel;
use bpf_skel::*;

use std::ffi::c_ulong;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap::ValueEnum;

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::ProgramInput;

use scx_utils::init_libbpf_logging;
use scx_utils::Core;
use scx_utils::Llc;
use scx_utils::Topology;
use scx_utils::NR_CPU_IDS;

use simplelog::{ColorChoice, Config as SimplelogConfig, LevelFilter, TermLogger, TerminalMode};

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "scx_arena_benchmarks", about = "BPF arena PQ throughput benchmark")]
struct Args {
    /// Number of concurrent threads
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// Operations per thread
    #[arg(long, default_value_t = 100000)]
    ops: u64,

    /// Per-heap capacity
    #[arg(long, default_value_t = 4096)]
    queue_cap: u64,

    /// Pre-fill count before timed phase
    #[arg(long, default_value_t = 10000)]
    prepopulate: u64,

    /// Output format
    #[arg(long, default_value = "text")]
    output: OutputFormat,

    /// Static arena allocation pages
    #[arg(long, default_value_t = 4096)]
    arena_pages: u64,

    /// Benchmark configs to run (comma-separated).
    /// Each config is "name:queues_multiplier:pick_d" e.g. "rpq-2t-k2:2:2".
    /// Special names: "single" (1 queue, pick-2), "atq" (ATQ baseline).
    /// Default runs a standard set of configs.
    #[arg(long, value_delimiter = ',')]
    configs: Option<Vec<String>>,
}

/// Per-thread benchmark results, matching struct bench_run_args in BPF.
#[repr(C)]
#[derive(Debug, Clone, Default)]
struct BenchRunArgs {
    nr_ops: u64,
    bench_id: u64,
    elapsed_ns: u64,
    inserts_ok: u64,
    inserts_fail: u64,
    pops_ok: u64,
    pops_fail: u64,
    max_insert_ns: u64,
    max_pop_ns: u64,
}

/// Aggregated results from all threads.
#[derive(Debug)]
struct BenchResult {
    name: String,
    threads: usize,
    ops_per_thread: u64,
    max_elapsed_ns: u64,
    total_inserts_ok: u64,
    total_inserts_fail: u64,
    total_pops_ok: u64,
    total_pops_fail: u64,
    max_insert_ns: u64,
    max_pop_ns: u64,
}

impl BenchResult {
    fn total_ops(&self) -> u64 {
        self.total_inserts_ok + self.total_inserts_fail + self.total_pops_ok + self.total_pops_fail
    }

    fn mops_per_sec(&self) -> f64 {
        if self.max_elapsed_ns == 0 {
            return 0.0;
        }
        self.total_ops() as f64 / self.max_elapsed_ns as f64 * 1e3
    }

    fn print_text(&self) {
        println!("{} Benchmark", self.name);
        println!("  Threads:         {}", self.threads);
        println!("  Ops/thread:      {}", self.ops_per_thread);
        println!("  Total ops:       {}", self.total_ops());
        println!(
            "  Elapsed:         {:.2} ms",
            self.max_elapsed_ns as f64 / 1e6
        );
        println!("  Throughput:      {:.3} MOps/s", self.mops_per_sec());
        println!("  Inserts OK:      {}", self.total_inserts_ok);
        println!("  Inserts fail:    {}", self.total_inserts_fail);
        println!("  Pops OK:         {}", self.total_pops_ok);
        println!("  Pops fail:       {}", self.total_pops_fail);
        println!(
            "  Max insert lat:  {} ns",
            self.max_insert_ns
        );
        println!(
            "  Max pop lat:     {} ns",
            self.max_pop_ns
        );
        println!();
    }

    fn print_json(&self) {
        println!(
            r#"{{"benchmark":"{}","threads":{},"ops_per_thread":{},"total_ops":{},"elapsed_ns":{},"mops_per_sec":{:.6},"inserts_ok":{},"inserts_fail":{},"pops_ok":{},"pops_fail":{},"max_insert_ns":{},"max_pop_ns":{}}}"#,
            self.name,
            self.threads,
            self.ops_per_thread,
            self.total_ops(),
            self.max_elapsed_ns,
            self.mops_per_sec(),
            self.total_inserts_ok,
            self.total_inserts_fail,
            self.total_pops_ok,
            self.total_pops_fail,
            self.max_insert_ns,
            self.max_pop_ns,
        );
    }
}

/// A benchmark configuration: name + RPQ params + BPF slot.
struct BenchConfig {
    name: String,
    slot: u64,          // bench_id slot in BPF
    nr_queues: u32,     // 0 = ATQ
    d: u32,             // pick-d (0 = ATQ)
    is_atq: bool,
}

fn pin_to_cpu(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
    }
}

fn setup_arenas(skel: &mut BpfSkel<'_>, static_pages: u64) -> Result<()> {
    let mut args = types::arena_init_args {
        static_pages: static_pages as c_ulong,
        task_ctx_size: 42 as c_ulong,
    };

    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut args as *mut _ as *mut u8,
                std::mem::size_of_val(&args),
            )
        }),
        ..Default::default()
    };

    let output = skel.progs.arena_init.test_run(input)?;
    if output.return_value != 0 {
        bail!("arena_init returned {}", output.return_value as i32);
    }
    Ok(())
}

fn setup_topology_node(skel: &mut BpfSkel<'_>, mask: &[u64]) -> Result<()> {
    let mut args = types::arena_alloc_mask_args {
        bitmap: 0 as c_ulong,
    };
    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut args as *mut _ as *mut u8,
                std::mem::size_of_val(&args),
            )
        }),
        ..Default::default()
    };
    let output = skel.progs.arena_alloc_mask.test_run(input)?;
    if output.return_value != 0 {
        bail!("arena_alloc_mask returned {}", output.return_value as i32);
    }
    let ptr = unsafe {
        &mut *std::ptr::with_exposed_provenance_mut::<[u64; 10]>(args.bitmap.try_into().unwrap())
    };
    let (valid_mask, _) = ptr.split_at_mut(mask.len());
    valid_mask.clone_from_slice(mask);

    let mut args = types::arena_topology_node_init_args {
        bitmap: args.bitmap as c_ulong,
        data_size: 0 as c_ulong,
        id: 0 as c_ulong,
    };
    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut args as *mut _ as *mut u8,
                std::mem::size_of_val(&args),
            )
        }),
        ..Default::default()
    };
    let output = skel.progs.arena_topology_node_init.test_run(input)?;
    if output.return_value != 0 {
        bail!("arena_topology_node_init returned {}", output.return_value as i32);
    }
    Ok(())
}

fn setup_topology(skel: &mut BpfSkel<'_>) -> Result<()> {
    let topo = Topology::new().expect("Failed to build host topology");
    setup_topology_node(skel, topo.span.as_raw_slice())?;
    for (_, node) in topo.nodes {
        setup_topology_node(skel, node.span.as_raw_slice())?;
    }
    for (_, llc) in topo.all_llcs {
        setup_topology_node(
            skel,
            Arc::<Llc>::into_inner(llc).expect("missing llc").span.as_raw_slice(),
        )?;
    }
    for (_, core) in topo.all_cores {
        setup_topology_node(
            skel,
            Arc::<Core>::into_inner(core).expect("missing core").span.as_raw_slice(),
        )?;
    }
    for (_, cpu) in topo.all_cpus {
        let mut mask = [0; 9];
        mask[cpu.id.checked_shr(64).unwrap_or(0)] |= 1 << (cpu.id % 64);
        setup_topology_node(skel, &mask)?;
    }
    Ok(())
}

/// Initialize an RPQ at the given slot.
fn init_rpq_slot(
    skel: &mut BpfSkel<'_>,
    slot: u64,
    nr_queues: u32,
    queue_cap: u64,
    d: u32,
    prepopulate: u64,
) -> Result<()> {
    let mut init_args = types::bench_init_args {
        rpq_nr_queues: nr_queues as c_ulong,
        rpq_per_queue_cap: queue_cap as c_ulong,
        rpq_d: d as c_ulong,
        prepopulate_count: prepopulate as c_ulong,
        bench_id: slot as c_ulong,
    };

    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut init_args as *mut _ as *mut u8,
                std::mem::size_of_val(&init_args),
            )
        }),
        ..Default::default()
    };

    let output = skel.progs.bench_init.test_run(input)?;
    if output.return_value != 0 {
        bail!(
            "bench_init slot {} returned {} (BPF error)",
            slot,
            output.return_value as i32
        );
    }
    Ok(())
}

/// Initialize the ATQ.
fn init_atq(skel: &mut BpfSkel<'_>, prepopulate: u64) -> Result<()> {
    let mut atq_args = types::bench_init_args {
        rpq_nr_queues: 0 as c_ulong,
        rpq_per_queue_cap: 0 as c_ulong,
        rpq_d: 0 as c_ulong,
        prepopulate_count: prepopulate as c_ulong,
        bench_id: 0 as c_ulong,
    };

    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut atq_args as *mut _ as *mut u8,
                std::mem::size_of_val(&atq_args),
            )
        }),
        ..Default::default()
    };

    let output = skel.progs.bench_init_atq.test_run(input)?;
    if output.return_value != 0 {
        bail!(
            "bench_init_atq returned {} (BPF error)",
            output.return_value as i32
        );
    }
    Ok(())
}

fn get_online_cpus() -> Result<Vec<usize>> {
    let topo = Topology::new()?;
    let mut cpus: Vec<usize> = topo.all_cpus.keys().copied().collect();
    cpus.sort();
    Ok(cpus)
}

/// Run a benchmark with the given prog_fd across multiple threads.
fn run_benchmark(
    name: &str,
    prog_fd: i32,
    bench_id: u64,
    threads: usize,
    ops_per_thread: u64,
    cpus: &[usize],
) -> Result<BenchResult> {
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let cpu = cpus[t % cpus.len()];
            let fd = prog_fd;
            let ops = ops_per_thread;
            let bid = bench_id;

            thread::spawn(move || -> Result<BenchRunArgs> {
                pin_to_cpu(cpu);

                let mut args = BenchRunArgs {
                    nr_ops: ops,
                    bench_id: bid,
                    ..Default::default()
                };

                let mut opts: libbpf_sys::bpf_test_run_opts =
                    unsafe { std::mem::zeroed() };
                opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as u64;
                opts.ctx_in =
                    &mut args as *mut BenchRunArgs as *const c_void;
                opts.ctx_size_in =
                    std::mem::size_of::<BenchRunArgs>() as u32;

                let ret = unsafe {
                    libbpf_sys::bpf_prog_test_run_opts(fd, &mut opts)
                };
                if ret != 0 {
                    bail!("bpf_prog_test_run_opts failed: {}", ret);
                }
                if opts.retval != 0 {
                    bail!(
                        "BPF program returned error: {}",
                        opts.retval as i32
                    );
                }

                Ok(args)
            })
        })
        .collect();

    let mut max_elapsed_ns = 0u64;
    let mut total_inserts_ok = 0u64;
    let mut total_inserts_fail = 0u64;
    let mut total_pops_ok = 0u64;
    let mut total_pops_fail = 0u64;
    let mut max_insert_ns = 0u64;
    let mut max_pop_ns = 0u64;

    for h in handles {
        let result = h.join().map_err(|_| anyhow::anyhow!("thread panicked"))??;
        max_elapsed_ns = max_elapsed_ns.max(result.elapsed_ns);
        total_inserts_ok += result.inserts_ok;
        total_inserts_fail += result.inserts_fail;
        total_pops_ok += result.pops_ok;
        total_pops_fail += result.pops_fail;
        max_insert_ns = max_insert_ns.max(result.max_insert_ns);
        max_pop_ns = max_pop_ns.max(result.max_pop_ns);
    }

    Ok(BenchResult {
        name: name.to_string(),
        threads,
        ops_per_thread: ops_per_thread,
        max_elapsed_ns,
        total_inserts_ok,
        total_inserts_fail,
        total_pops_ok,
        total_pops_fail,
        max_insert_ns,
        max_pop_ns,
    })
}

/// Parse a config string like "rpq-2t-k3:2:3" into (name, queue_mult, d).
/// Special: "single" -> (single, 0, 0), "atq" -> (atq, 0, 0).
fn parse_config(s: &str, threads: usize) -> (String, u32, u32) {
    if s == "single" {
        return ("single".to_string(), 1, 2); // 1 queue, d=2
    }
    if s == "atq" {
        return ("atq".to_string(), 0, 0);
    }
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() == 3 {
        let name = parts[0].to_string();
        let mult: u32 = parts[1].parse().unwrap_or(2);
        let d: u32 = parts[2].parse().unwrap_or(2);
        (name, mult * threads as u32, d)
    } else {
        (s.to_string(), 2 * threads as u32, 2)
    }
}

fn default_configs(threads: usize) -> Vec<String> {
    vec![
        format!("rpq-2t-k2:2:2"),
        format!("rpq-2t-k3:2:3"),
        format!("rpq-2t-k4:2:4"),
        format!("rpq-1t-k2:1:2"),
        format!("single"),
        format!("atq"),
    ]
}

fn main() -> Result<()> {
    let args = Args::parse();

    TermLogger::init(
        LevelFilter::Warn,
        SimplelogConfig::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let mut open_object = MaybeUninit::uninit();
    let mut builder = BpfSkelBuilder::default();
    builder.obj_builder.debug(false);
    init_libbpf_logging(None);

    let mut skel = builder
        .open(&mut open_object)
        .context("Failed to open BPF program")?;

    skel.maps.rodata_data.as_mut().unwrap().nr_cpu_ids = *NR_CPU_IDS as u32;

    let mut skel = skel.load().context("Failed to load BPF program")?;

    setup_arenas(&mut skel, args.arena_pages)?;
    setup_topology(&mut skel)?;

    let cpus = get_online_cpus()?;
    if cpus.len() < args.threads {
        eprintln!(
            "Warning: {} threads requested but only {} CPUs available",
            args.threads,
            cpus.len()
        );
    }

    // Parse configs
    let config_strs = args.configs.clone().unwrap_or_else(|| default_configs(args.threads));

    let mut configs: Vec<BenchConfig> = Vec::new();
    let mut rpq_slot = 0u64;

    for cs in &config_strs {
        let (name, nr_queues, d) = parse_config(cs, args.threads);
        if name == "atq" {
            configs.push(BenchConfig {
                name,
                slot: 0,
                nr_queues: 0,
                d: 0,
                is_atq: true,
            });
        } else {
            configs.push(BenchConfig {
                name,
                slot: rpq_slot,
                nr_queues,
                d,
                is_atq: false,
            });
            rpq_slot += 1;
        }
    }

    // Initialize all RPQ slots
    for cfg in &configs {
        if cfg.is_atq {
            continue;
        }
        init_rpq_slot(
            &mut skel,
            cfg.slot,
            cfg.nr_queues,
            args.queue_cap,
            cfg.d,
            args.prepopulate,
        )?;
    }

    // Initialize ATQ if needed
    if configs.iter().any(|c| c.is_atq) {
        init_atq(&mut skel, args.prepopulate)?;
    }

    // Run benchmarks
    let rpq_fd = skel.progs.bench_run_rpq.as_fd().as_raw_fd();
    let atq_fd = skel.progs.bench_run_atq.as_fd().as_raw_fd();

    for cfg in &configs {
        let (fd, bid) = if cfg.is_atq {
            (atq_fd, 0u64)
        } else {
            (rpq_fd, cfg.slot)
        };

        let result = run_benchmark(&cfg.name, fd, bid, args.threads, args.ops, &cpus)?;
        match args.output {
            OutputFormat::Text => result.print_text(),
            OutputFormat::Json => result.print_json(),
        }
    }

    Ok(())
}
