// SPDX-License-Identifier: GPL-2.0
//
// scx_cake - A sched_ext scheduler applying CAKE bufferbloat concepts
//
// This is the userspace component that loads the BPF scheduler,
// configures it, and displays statistics.

mod stats;
mod topology;
mod tui;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use log::{info, warn};

// Include the generated interface bindings
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}

// Include the generated BPF skeleton
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

/// scx_cake: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// This scheduler adapts CAKE's DRR++ (Deficit Round Robin++) algorithm
/// for CPU scheduling, providing low-latency scheduling for gaming and
/// interactive workloads while maintaining fairness.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Base scheduling quantum in microseconds
    #[arg(long, default_value_t = 2000)]
    quantum: u64,

    /// Extra time bonus for new flows in microseconds
    #[arg(long, default_value_t = 8000)]
    new_flow_bonus: u64,

    /// CPU usage threshold for sparse flow classification (permille, 0-1000)
    /// Lower values = more tasks classified as sparse
    #[arg(long, default_value_t = 50)]
    sparse_threshold: u64,

    /// Maximum time before forcing preemption (microseconds)
    #[arg(long, default_value_t = 100000)]
    starvation: u64,

    /// Enable verbose debug output
    #[arg(long, short)]
    verbose: bool,

    /// Statistics update interval in seconds
    #[arg(long, default_value_t = 1)]
    interval: u64,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
}

impl<'a> Scheduler<'a> {
    fn new(args: Args, open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>) -> Result<Self> {
        use libbpf_rs::skel::{SkelBuilder, OpenSkel};
        
        // Open and load the BPF skeleton
        let skel_builder = BpfSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Detect system topology (CCDs, P/E cores)
        let topo = topology::detect()?;

        // Configure the scheduler via rodata (read-only data)
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns = args.quantum * 1000;
            rodata.new_flow_bonus_ns = args.new_flow_bonus * 1000;
            rodata.sparse_threshold = args.sparse_threshold;
            rodata.starvation_ns = args.starvation * 1000;
            rodata.enable_stats = args.verbose;  // Only collect stats when --verbose is used
            
            // NOTE: Topology variables removed from BPF code (were never used)
            // Future: Re-add when CCD-local or P-core preference is implemented
        }

        // Load the BPF program
        let skel = open_skel
            .load()
            .context("Failed to load BPF program")?;

        Ok(Self { skel, args, topology: topo })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        // Attach the scheduler
        let _link = self.skel
            .maps
            .cake_ops
            .attach_struct_ops()
            .context("Failed to attach scheduler")?;

        info!("scx_cake scheduler started");
        info!("  Quantum:          {} µs", self.args.quantum);
        info!("  New flow bonus:   {} µs", self.args.new_flow_bonus);
        info!("  Sparse threshold: {}‰", self.args.sparse_threshold);
        info!("  Starvation limit: {} µs", self.args.starvation);

        if self.args.verbose {
            // Run TUI mode
            tui::run_tui(&mut self.skel, shutdown.clone(), self.args.interval, self.topology.clone())?;
        } else {
            // Silent mode - just wait for shutdown
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(self.args.interval));

                // Check for scheduler exit using the UEI
                if scx_utils::uei_exited!(&self.skel, uei) {
                    match scx_utils::uei_report!(&self.skel, uei) {
                        Ok(reason) => {
                            warn!("BPF scheduler exited: {:?}", reason);
                        }
                        Err(e) => {
                            warn!("BPF scheduler exited (failed to get reason: {})", e);
                        }
                    }
                    break;
                }
            }
        }

        info!("scx_cake scheduler shutting down");
        Ok(())
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let args = Args::parse();

    // Set up signal handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    
    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    // Create open object for BPF - needs to outlive scheduler
    let mut open_object = std::mem::MaybeUninit::uninit();

    // Create and run the scheduler
    let mut scheduler = Scheduler::new(args, &mut open_object)?;
    scheduler.run(shutdown)?;

    Ok(())
}
