// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

extern crate static_assertions;
extern crate plain;
extern crate libc;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::mem;

use libc::c_char;
use std::ffi::CStr;
use std::str;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use log::info;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use rlimit::{setrlimit, getrlimit, Resource};
use plain::Plain;
use nix::sys::signal;

static RUNNING: AtomicBool = AtomicBool::new(true);

/// scx_lavd: Latency-criticality Aware Virtual Deadline (LAVD) scheduler
///
/// The rust part is minimal. It processes command line options and logs out
/// scheduling statistics. The BPF part makes all the scheduling decisions.
/// See the more detailed overview of the LAVD design at main.bpf.c.
#[derive(Debug, Parser)]
struct Opts {
    /// The number of scheduling samples to be reported every second (default: 0)
    #[clap(short = 's', long, default_value = "0")]
    nr_sched_samples: u64,

    /// PID to be tracked all its scheduling activities if specified
    #[clap(short = 'p', long, default_value = "0")]
    pid_traced: u64,

    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

unsafe impl Plain for msg_task_ctx {}

impl msg_task_ctx {
    fn from_bytes(buf: &[u8]) -> & msg_task_ctx {
        plain::from_bytes(buf)
            .expect("The buffer is either too short or not aligned!")
    }
}

impl introspec {
    fn new() -> Self {
        let intrspc = unsafe {
            mem::MaybeUninit::<introspec>::zeroed().assume_init()
        };
        intrspc
    }

    fn init(opts: &Opts) -> Self {
        let mut intrspc = introspec::new();
        if opts.nr_sched_samples > 0 {
            intrspc.cmd = LAVD_CMD_SCHED_N;
            intrspc.arg = opts.nr_sched_samples;
        }
        else if opts.pid_traced > 0 {
            intrspc.cmd = LAVD_CMD_PID;
            intrspc.arg = opts.pid_traced;
        }
        else {
            intrspc.cmd = LAVD_CMD_NOP;
        }
        intrspc.requested = false as u8;
        intrspc
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    nr_cpus_onln: u64,
    rb_mgr: libbpf_rs::RingBuffer<'static>,
    intrspc: introspec,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts) -> Result<Self> {
        // Increase MEMLOCK size since the BPF scheduler might use
        // more than the current limit
        let (soft_limit, _) = getrlimit(Resource::MEMLOCK).unwrap();
        setrlimit(Resource::MEMLOCK, soft_limit, rlimit::INFINITY).unwrap();

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        let mut skel = skel_builder.open()
                                   .context("Failed to open BPF program")?;

        // Initialize skel according to @opts.
	let nr_cpus_onln = num_cpus::get() as u64;
	skel.bss_mut().nr_cpus_onln = nr_cpus_onln;
	skel.rodata_mut(). verbose = opts.verbose;
        let intrspc = introspec::init(opts);

        // Attach.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        skel.attach().context("Failed to attach BPF program")?;
        let struct_ops = Some(
            skel.maps_mut()
                .lavd_ops()
                .attach_struct_ops()
                .context("Failed to attach scx_lavd struct ops")?,
        );

        // Build a ring buffer for instrumentation
        let mut maps = skel.maps_mut();
        let rb_map = maps.introspec_msg();
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(rb_map, Scheduler::print_bpf_msg).unwrap();
        let rb_mgr = builder.build().unwrap();

        Ok(Self {
            skel,
            struct_ops,
            nr_cpus_onln,
            rb_mgr,
            intrspc,
        })
    }

    fn get_msg_seq_id() -> u64 {
        static mut MSEQ: u64 = 0;
        unsafe {
            MSEQ += 1;
            MSEQ
        }
    }

    fn print_bpf_msg(data: &[u8]) -> i32 {
        let mt = msg_task_ctx::from_bytes(data);
        let tx = mt.taskc_x;
        let tc = mt.taskc;

        // No idea how to print other types than LAVD_MSG_TASKC
        if mt.hdr.kind != LAVD_MSG_TASKC {
            return 0;
        }

        // Print a message from the BPF scheduler
        let mseq = Scheduler::get_msg_seq_id();

        if mseq % 32 == 1 {
            info!("| {:9} | {:8} | {:17} \
                   | {:4} | {:9} | {:9} \
                   | {:10} | {:9} | {:8} \
                   | {:12} | {:7} | {:9} \
                   | {:9} | {:9} | {:9} \
                   | {:9} | {:8} |",
                  "mseq", "pid", "comm",
                  "cpu", "vddln_ns", "elglty_ns",
                  "slice_ns", "grdy_rt", "lat_prio",
                  "static_prio", "lat_bst", "slice_bst",
                  "run_freq", "run_tm_ns", "wait_freq",
                  "wake_freq", "cpu_util");
        }

        let c_tx_cm: *const c_char = (&tx.comm as *const [i8;17]) as *const i8;
        let c_tx_cm_str: &CStr = unsafe { CStr::from_ptr(c_tx_cm) };
        let tx_comm : &str = c_tx_cm_str.to_str().unwrap();

        info!("| {:9} | {:8} | {:17} \
               | {:4} | {:9} | {:9} \
               | {:10} | {:9} | {:8} \
               | {:12} | {:7} | {:9} \
               | {:9} | {:9} | {:9} \
               | {:9} | {:8} | ",
              mseq, tx.pid, tx_comm,
              tx.cpu_id, tc.vdeadline_delta_ns, tc.eligible_delta_ns,
              tc.slice_ns, tc.greedy_ratio, tc.lat_prio,
              tx.static_prio, tc.lat_boost_prio, tc.slice_boost_prio,
              tc.run_freq, tc.run_time_ns, tc.wait_freq,
              tc.wake_freq, tx.cpu_util);

        0
    }

    fn prep_introspec(&mut self) -> u64 {
        let mut interval_ms = 1000;

        if self.intrspc.cmd == LAVD_CMD_SCHED_N && 
            self.intrspc.arg > self.nr_cpus_onln {
		// More samples, shorter sampling interval.
                let f = self.intrspc.arg / self.nr_cpus_onln * 2;
                interval_ms /= f;
        }
	self.intrspc.requested = true as u8;

	self.skel.bss_mut().intrspc.cmd = self.intrspc.cmd;
	self.skel.bss_mut().intrspc.arg = self.intrspc.arg;
	self.skel.bss_mut().intrspc.requested = self.intrspc.requested;

        interval_ms
    }

    fn cleanup_introspec(&mut self) {
        // If not yet requested, do nothing.
        if self.intrspc.requested == false as u8 {
            return;
        }

        // Once dumped, it is done.
        if self.intrspc.cmd == LAVD_CMD_DUMP {
            self.intrspc.cmd = LAVD_CMD_NOP;
	}
    }

    fn running(&mut self) -> bool {
        RUNNING.load(Ordering::Relaxed) && !uei_exited!(&self.skel.bss().uei)
    }

    fn run(&mut self) -> Result<()> {
        while self.running() {
            let interval_ms = self.prep_introspec();
            std::thread::sleep(Duration::from_millis(interval_ms));
            self.rb_mgr.poll(Duration::from_millis(100)).unwrap();
            self.cleanup_introspec();
        }
        self.rb_mgr.consume().unwrap();

	self.struct_ops.take();
	uei_report!(&self.skel.bss().uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn init_log(opts: & Opts) {
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
    ).unwrap();
}

extern "C" fn handle_sigint(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn init_signal_handlers() {
    // Ctrl-c for termination
    unsafe {
        let sigint_action = signal::SigAction::new(
            signal::SigHandler::SigAction(handle_sigint),
            signal::SaFlags::empty(), signal::SigSet::empty());
        signal::sigaction(signal::SIGINT, &sigint_action).unwrap();
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    init_log(&opts);

    let mut sched = Scheduler::init(&opts)?;
    info!("scx_lavd scheduler is initialized");

    init_signal_handlers();

    info!("scx_lavd scheduler starts running.");
    sched.run()
}
