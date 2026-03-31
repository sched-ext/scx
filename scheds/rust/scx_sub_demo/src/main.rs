// SPDX-License-Identifier: GPL-2.0
//
// Rust userspace for scx_qmap demonstrating assoc_struct_ops and sub-scheduling.
// This is a direct port of tools/sched_ext/scx_qmap.c from the sched_ext kernel tree.

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bpf_skel;
use bpf_skel::*;

use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use scx_utils::compat;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;

const HELP: &str = "\
A simple five-level FIFO queue sched_ext scheduler.

See the top-level comment in .bpf.c for more details.

This is the Rust userspace port of scx_qmap, demonstrating
assoc_struct_ops and sub-scheduling support.";

#[derive(Parser, Debug)]
#[command(about = HELP)]
struct Opts {
    /// Override slice duration in microseconds
    #[arg(short = 's', long)]
    slice_us: Option<u64>,

    /// Trigger scx_bpf_error() after COUNT enqueues
    #[arg(short = 'e', long)]
    error_cnt: Option<u32>,

    /// Stall every COUNT'th user thread
    #[arg(short = 't', long)]
    stall_user_nth: Option<u32>,

    /// Stall every COUNT'th kernel thread
    #[arg(short = 'T', long, name = "KCOUNT")]
    stall_kernel_nth: Option<u32>,

    /// Trigger dispatch infinite looping after COUNT dispatches
    #[arg(short = 'l', long)]
    dsp_inf_loop_after: Option<u32>,

    /// Dispatch up to COUNT tasks together
    #[arg(short = 'b', long)]
    dsp_batch: Option<u32>,

    /// Print out DSQ content and event counters to trace_pipe every second
    #[arg(short = 'P', long)]
    print_dsqs: bool,

    /// Print out debug messages to trace_pipe
    #[arg(short = 'M', long)]
    print_msgs: bool,

    /// Boost nice -20 tasks in SHARED_DSQ, use with -b
    #[arg(short = 'H', long)]
    highpri_boosting: bool,

    /// Attach as sub-scheduler to this cgroup path
    #[arg(short = 'c', long)]
    cgroup: Option<String>,

    /// Disallow a process from switching into SCHED_EXT (-1 for self)
    #[arg(short = 'd', long)]
    disallow_pid: Option<i32>,

    /// Set scx_exit_info.dump buffer length
    #[arg(short = 'D', long)]
    dump_len: Option<u32>,

    /// Suppress qmap-specific debug dump
    #[arg(short = 'S', long)]
    suppress_dump: bool,

    /// Switch only tasks on SCHED_EXT policy instead of all
    #[arg(short = 'p', long)]
    partial: bool,

    /// Turn on SCX_OPS_ALWAYS_ENQ_IMMED
    #[arg(short = 'I', long)]
    always_enq_immed: bool,

    /// IMMED stress: force every COUNT'th enqueue to a busy local DSQ (use with -I)
    #[arg(short = 'F', long)]
    immed_stress_nth: Option<u32>,

    /// Print libbpf debug messages
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.verbose {
        simplelog::TermLogger::init(
            simplelog::LevelFilter::Debug,
            simplelog::Config::default(),
            simplelog::TerminalMode::Stderr,
            simplelog::ColorChoice::Auto,
        )?;
    } else {
        simplelog::TermLogger::init(
            simplelog::LevelFilter::Info,
            simplelog::Config::default(),
            simplelog::TerminalMode::Stderr,
            simplelog::ColorChoice::Auto,
        )?;
    }

    let exit_req = Arc::new(AtomicBool::new(false));
    let exit_req_clone = exit_req.clone();
    ctrlc::set_handler(move || {
        exit_req_clone.store(true, Ordering::Relaxed);
    })?;

    // Open
    let mut skel_builder = MainSkelBuilder::default();
    skel_builder.obj_builder.debug(opts.verbose);
    let mut open_object = MaybeUninit::uninit();
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, qmap_ops, None::<libbpf_rs::libbpf_sys::bpf_object_open_opts>)?;

    // Set default slice_ns from kernel enum
    let rodata = skel.maps.rodata_data.as_mut().unwrap();
    rodata.slice_ns = scx_utils::scx_enums.SCX_SLICE_DFL;

    // Apply CLI options to rodata
    if let Some(slice_us) = opts.slice_us {
        rodata.slice_ns = slice_us * 1000;
    }
    if let Some(cnt) = opts.stall_user_nth {
        rodata.stall_user_nth = cnt;
    }
    if let Some(cnt) = opts.stall_kernel_nth {
        rodata.stall_kernel_nth = cnt;
    }
    if let Some(cnt) = opts.dsp_inf_loop_after {
        rodata.dsp_inf_loop_after = cnt;
    }
    if let Some(cnt) = opts.dsp_batch {
        rodata.dsp_batch = cnt;
    }
    if opts.print_dsqs {
        rodata.print_dsqs_and_events = true;
    }
    if opts.print_msgs {
        rodata.print_msgs = true;
    }
    if opts.highpri_boosting {
        rodata.highpri_boosting = true;
    }
    if opts.suppress_dump {
        rodata.suppress_dump = true;
    }
    if opts.always_enq_immed {
        rodata.always_enq_immed = true;
        skel.struct_ops.qmap_ops_mut().flags |= *compat::SCX_OPS_ALWAYS_ENQ_IMMED;
    }
    if let Some(cnt) = opts.immed_stress_nth {
        rodata.immed_stress_nth = cnt;
    }
    if let Some(mut pid) = opts.disallow_pid {
        if pid < 0 {
            pid = std::process::id() as i32;
        }
        rodata.disallow_tgid = pid;
    }

    // Sub-scheduler: set cgroup inode as sub_cgroup_id
    let is_subsched = if let Some(ref cgroup_path) = opts.cgroup {
        let meta = std::fs::metadata(cgroup_path)?;
        let ino = meta.ino();
        skel.struct_ops.qmap_ops_mut().sub_cgroup_id = ino;
        skel.maps.rodata_data.as_mut().unwrap().sub_cgroup_id = ino;
        true
    } else {
        false
    };

    // Apply error count to BSS
    if let Some(cnt) = opts.error_cnt {
        skel.maps.bss_data.as_mut().unwrap().test_error_cnt = cnt;
    }

    // struct_ops settings
    if opts.partial {
        skel.struct_ops.qmap_ops_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
    }
    if let Some(len) = opts.dump_len {
        skel.struct_ops.qmap_ops_mut().exit_dump_len = len;
    }

    // Load (includes assoc_struct_ops for all non-struct_ops programs)
    let mut skel = scx_ops_load!(skel, qmap_ops, uei)?;

    // Attach
    let link = scx_ops_attach!(skel, qmap_ops, is_subsched)?;

    let has_cpuperf = compat::ksym_exists("scx_bpf_cpuperf_cur").unwrap_or(false);

    // Main loop — print stats every second
    while !exit_req.load(Ordering::Relaxed) && !uei_exited!(skel, uei) {
        std::thread::sleep(Duration::from_secs(1));

        let bss = skel.maps.bss_data.as_ref().unwrap();
        let nr_enqueued = bss.nr_enqueued;
        let nr_dispatched = bss.nr_dispatched;

        print!(
            "stats  : enq={} dsp={} delta={} reenq/cpu0={}/{} deq={} core={} enq_ddsp={}\n",
            nr_enqueued,
            nr_dispatched,
            nr_enqueued as i64 - nr_dispatched as i64,
            bss.nr_reenqueued,
            bss.nr_reenqueued_cpu0,
            bss.nr_dequeued,
            bss.nr_core_sched_execed,
            bss.nr_ddsp_from_enq,
        );
        print!(
            "         exp_local={} exp_remote={} exp_timer={} exp_lost={}\n",
            bss.nr_expedited_local,
            bss.nr_expedited_remote,
            bss.nr_expedited_from_timer,
            bss.nr_expedited_lost,
        );
        if has_cpuperf {
            print!(
                "cpuperf: cur min/avg/max={}/{}/{} target min/avg/max={}/{}/{}\n",
                bss.cpuperf_min,
                bss.cpuperf_avg,
                bss.cpuperf_max,
                bss.cpuperf_target_min,
                bss.cpuperf_target_avg,
                bss.cpuperf_target_max,
            );
        }
    }

    drop(link);
    uei_report!(skel, uei)
        .map(|_| ())
        .unwrap_or_else(|e| eprintln!("EXIT: {}", e));

    Ok(())
}
