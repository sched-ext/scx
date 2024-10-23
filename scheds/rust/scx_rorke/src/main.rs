mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod config;
use config::*;

use std::env;
use std::fs;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use libc::{cpu_set_t, pid_t, sched_param, sched_setaffinity, sched_setscheduler, CPU_SET};

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;

use log::debug;
use log::info;

use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const SCHED_EXT: i32 = 7;

lazy_static::lazy_static! {
    static ref NR_POSSIBLE_CPUS: usize = libbpf_rs::num_possible_cpus().unwrap();
}

#[derive(Debug, Parser)]
struct Opts {
    /// Central CPU
    #[clap(short = 'c', long, default_value = "0")]
    central_cpu: u32,

    /// Number of CPUs
    #[clap(short = 'n', long, default_value = "2")]
    num_cpus: u32,

    /// Timer interval in microseconds
    #[clap(short = 't', long, default_value = "100")]
    timer_interval: u64,

    /// Config file
    #[clap(short = 'f', long)]
    config_file: Option<String>,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue, default_value = "true")]
    partial: bool,

    /// Enable verbose output including libbpf details.
    /// Specify multiple times to increase verbosity.
    #[clap(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Print version and exit.
    #[clap(long)]
    version: bool,
}
fn convert_cpu_ctxs(cpu_ctxs: Vec<bpf_intf::cpu_ctx>) -> Vec<Vec<u8>> {
    cpu_ctxs
        .into_iter()
        .map(|cpu_ctx| {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cpu_ctx as *const bpf_intf::cpu_ctx as *const u8,
                    std::mem::size_of::<bpf_intf::cpu_ctx>(),
                )
            };
            bytes.to_vec()
        })
        .collect()
}

fn initialize_cpu_ctxs(skel: &BpfSkel, cpu_allocation: &Vec<u64>) -> Result<()> {
    let key = (0_u32).to_ne_bytes();
    let mut cpu_ctxs: Vec<bpf_intf::cpu_ctx> = vec![];
    let cpu_ctxs_vec = skel
        .maps
        .cpu_ctx_stor
        .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();

    for cpu in 0..*NR_POSSIBLE_CPUS {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }

    for (cpu, vm_id) in cpu_allocation.iter().enumerate() {
        cpu_ctxs[cpu].vm_id = *vm_id;
        info!("cpu - {} assigned to vm - {}", cpu, *vm_id);
    }

    skel.maps
        .cpu_ctx_stor
        .update_percpu(&key, &convert_cpu_ctxs(cpu_ctxs), libbpf_rs::MapFlags::ANY)
        .context("Failed to update cpu_ctx")?;

    Ok(())
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        // Open the eBPF object for verification
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        init_libbpf_logging(None);
        info!(
            "Running scx_rorke (build_id: {})",
            *build_id::SCX_FULL_VERSION
        );
        info!("Opts: {:?}", opts);
        let mut skel = scx_ops_open!(skel_builder, open_object, rorke).unwrap();

        // Parse json config file

        let config_path = match &opts.config_file {
            Some(path) => PathBuf::from(path),
            None => {
                let home_dir = env::var("HOME").expect("Failed to get $HOME env variable");
                PathBuf::from(home_dir).join("config.json")
            }
        };
        let vm_config =
            parse_vm_config(&fs::read_to_string(config_path).context("Failed to find file")?)
                .context("Failed to parse config file")?;
        let cpu_allocation = allocate_cpus_to_vms(&vm_config, opts.num_cpus);
        info!("CPU allocation: {:?}", cpu_allocation);

        // Initialize skel
        skel.maps.rodata_data.central_cpu = opts.central_cpu;
        skel.maps.rodata_data.nr_cpus = opts.num_cpus;
        skel.maps.rodata_data.nr_vms = vm_config.len() as u32;
        skel.maps.rodata_data.timer_interval_ns = opts.timer_interval * 1000;

        for (i, vm) in vm_config.iter().enumerate() {
            skel.maps.rodata_data.vms[i] = vm.vm_id;
        }

        if opts.partial {
            skel.struct_ops.rorke_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }

        skel.maps.rodata_data.debug = opts.verbose as u32;

        // Pin to central CPU before attaching eBPF program
        unsafe {
            let mut cpu_set: cpu_set_t = std::mem::zeroed();
            CPU_SET(opts.central_cpu as usize, &mut cpu_set);

            let tid: pid_t = libc::syscall(libc::SYS_gettid) as pid_t;

            let result = sched_setaffinity(tid, std::mem::size_of_val(&cpu_set), &cpu_set);
            if result != 0 {
                return Err(anyhow!("Failed to pin to central CPU"));
            }
        }
        // Load and verify the eBPF program
        let mut skel = scx_ops_load!(skel, rorke, uei)?;

        // Initialize cpu_ctxs
        initialize_cpu_ctxs(&skel, &cpu_allocation)?;

        let struct_ops = Some(scx_ops_attach!(skel, rorke)?);
        info!("scx_rorke started");

        // Set VMs to sched_ext class

        for vm in vm_config.iter() {
            let vcpus = &vm.vcpus;
            debug!("vm_id: {:?} vcpus: {:?}", vm.vm_id, vcpus);

            for vcpu in vcpus.iter() {
                let param = sched_param { sched_priority: 0 }; // SCHED_BATCH doesn't require a priority
                let result = unsafe {
                    sched_setscheduler(*vcpu as i32, SCHED_EXT, &param as *const sched_param)
                };

                if result == -1 {
                    return Err(anyhow!("Failed to set SCHED_EXT for vcpu: {:?}", vcpu));
                }
                debug!("Set SCHED_EXT for vcpu: {:?}", vcpu);
            }
        }
        Ok(Self { skel, struct_ops })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {}
        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("scx_rorke: {}", *build_id::SCX_FULL_VERSION);
        return Ok(());
    }

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Failed to set Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
