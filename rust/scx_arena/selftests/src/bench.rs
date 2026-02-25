// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! BPF Arena Priority Queue Throughput Benchmark
//!
//! Measures concurrent insert/pop throughput for RPQ (MultiQueue) vs
//! single-lock rbtree. Each thread runs a SEC("syscall") BPF program
//! with bpf_ktime_get_ns() timing for precise in-kernel measurement.

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
enum BenchMode {
    Rpq,
    Single,
    Atq,
    All,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "scx_arena_benchmarks", about = "BPF arena PQ throughput benchmark")]
struct Args {
    /// Which data structure to benchmark
    #[arg(long, default_value = "all")]
    bench: BenchMode,

    /// Number of concurrent threads
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// Operations per thread
    #[arg(long, default_value_t = 100000)]
    ops: u64,

    /// RPQ internal heaps (default: 2 * threads)
    #[arg(long)]
    queues: Option<u32>,

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
    #[arg(long, default_value_t = 2048)]
    arena_pages: u64,
}

/// Per-thread benchmark results, matching struct bench_run_args in BPF.
#[repr(C)]
#[derive(Debug, Clone, Default)]
struct BenchRunArgs {
    nr_ops: u64,
    elapsed_ns: u64,
    inserts_ok: u64,
    inserts_fail: u64,
    pops_ok: u64,
    pops_fail: u64,
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
        println!();
    }

    fn print_json(&self) {
        println!(
            r#"{{"benchmark":"{}","threads":{},"ops_per_thread":{},"total_ops":{},"elapsed_ns":{},"mops_per_sec":{:.6},"inserts_ok":{},"inserts_fail":{},"pops_ok":{},"pops_fail":{}}}"#,
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
        );
    }
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
        bail!(
            "arena_init returned {}",
            output.return_value as i32
        );
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
        bail!(
            "arena_alloc_mask returned {}",
            output.return_value as i32
        );
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
        bail!(
            "arena_topology_node_init returned {}",
            output.return_value as i32
        );
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
            Arc::<Llc>::into_inner(llc)
                .expect("missing llc")
                .span
                .as_raw_slice(),
        )?;
    }

    for (_, core) in topo.all_cores {
        setup_topology_node(
            skel,
            Arc::<Core>::into_inner(core)
                .expect("missing core")
                .span
                .as_raw_slice(),
        )?;
    }
    for (_, cpu) in topo.all_cpus {
        let mut mask = [0; 9];
        mask[cpu.id.checked_shr(64).unwrap_or(0)] |= 1 << (cpu.id % 64);
        setup_topology_node(skel, &mask)?;
    }

    Ok(())
}

/// Call bench_init SEC("syscall") to create RPQs and prepopulate.
fn bench_init_bpf(skel: &mut BpfSkel<'_>, args: &Args) -> Result<()> {
    let nr_queues = args.queues.unwrap_or((2 * args.threads) as u32);

    let mut init_args = types::bench_init_args {
        rpq_nr_queues: nr_queues as c_ulong,
        rpq_per_queue_cap: args.queue_cap as c_ulong,
        prepopulate_count: args.prepopulate as c_ulong,
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
            "bench_init returned {} (BPF error)",
            output.return_value as i32
        );
    }

    // ATQ init is in a separate SEC("syscall") to avoid
    // hitting the BPF verifier's jump complexity limit.
    let mut atq_args = types::bench_init_args {
        rpq_nr_queues: 0 as c_ulong,
        rpq_per_queue_cap: 0 as c_ulong,
        prepopulate_count: args.prepopulate as c_ulong,
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

/// Get online CPU IDs for thread pinning.
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
    threads: usize,
    ops_per_thread: u64,
    cpus: &[usize],
) -> Result<BenchResult> {
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let cpu = cpus[t % cpus.len()];
            let fd = prog_fd;
            let ops = ops_per_thread;

            thread::spawn(move || -> Result<BenchRunArgs> {
                pin_to_cpu(cpu);

                let mut args = BenchRunArgs {
                    nr_ops: ops,
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

    for h in handles {
        let result = h.join().map_err(|_| anyhow::anyhow!("thread panicked"))??;
        max_elapsed_ns = max_elapsed_ns.max(result.elapsed_ns);
        total_inserts_ok += result.inserts_ok;
        total_inserts_fail += result.inserts_fail;
        total_pops_ok += result.pops_ok;
        total_pops_fail += result.pops_fail;
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
    })
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

    // Initialize arenas and topology
    setup_arenas(&mut skel, args.arena_pages)?;
    setup_topology(&mut skel)?;

    // Initialize benchmark data structures
    bench_init_bpf(&mut skel, &args)?;

    let cpus = get_online_cpus()?;
    if cpus.len() < args.threads {
        eprintln!(
            "Warning: {} threads requested but only {} CPUs available, some CPUs will be shared",
            args.threads,
            cpus.len()
        );
    }

    let run_rpq = matches!(args.bench, BenchMode::Rpq | BenchMode::All);
    let run_single = matches!(args.bench, BenchMode::Single | BenchMode::All);
    let run_atq = matches!(args.bench, BenchMode::Atq | BenchMode::All);

    if run_rpq {
        let fd = skel.progs.bench_run_rpq.as_fd().as_raw_fd();
        let result = run_benchmark("rpq", fd, args.threads, args.ops, &cpus)?;
        match args.output {
            OutputFormat::Text => result.print_text(),
            OutputFormat::Json => result.print_json(),
        }
    }

    if run_single {
        let fd = skel.progs.bench_run_single.as_fd().as_raw_fd();
        let result = run_benchmark("single", fd, args.threads, args.ops, &cpus)?;
        match args.output {
            OutputFormat::Text => result.print_text(),
            OutputFormat::Json => result.print_json(),
        }
    }

    if run_atq {
        let fd = skel.progs.bench_run_atq.as_fd().as_raw_fd();
        let result = run_benchmark("atq", fd, args.threads, args.ops, &cpus)?;
        match args.output {
            OutputFormat::Text => result.print_text(),
            OutputFormat::Json => result.print_json(),
        }
    }

    Ok(())
}
