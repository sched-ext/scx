extern crate libc;

use crate::bpf_skel::*;

use libbpf_rs;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::libbpf_sys;
use std::io;
use std::mem;

// Expanded from systing's code: www.github.com/josefbacik/systing

const PERF_TYPE_HARDWARE: u32 = 0x0;
const PERF_TYPE_SOFTWARE: u32 = 0x1;
const PERF_TYPE_RAW: u32 = 0x3;
const PERF_TYPE_IBS: u32 = 0xb;

const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;

const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

#[repr(C)]
union sample_un {
    pub sample_period: u64,
    pub sample_freq: u64,
}

#[repr(C)]
union wakeup_un {
    pub wakeup_events: u32,
    pub wakeup_atermark: u32,
}

#[repr(C)]
union bp_1_un {
    pub bp_addr: u64,
    pub kprobe_func: u64,
    pub uprobe_path: u64,
    pub config1: u64,
}

#[repr(C)]
union bp_2_un {
    pub bp_len: u64,
    pub kprobe_addr: u64,
    pub probe_offset: u64,
    pub config2: u64,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct perf_event_attr {
    pub _type: u32,
    pub size: u32,
    pub config: u64,
    pub sample: sample_un,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup: wakeup_un,
    pub bp_type: u32,
    pub bp_1: bp_1_un,
    pub bp_2: bp_2_un,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub aux_sample_size: u32,
    pub __reserved_3: u32,
}

extern "C" {
    fn syscall(number: libc::c_long, ...) -> libc::c_long;
}

fn perf_event_open(
    hw_event: &perf_event_attr,
    pid: libc::pid_t,
    cpu: libc::c_int,
    group_fd: libc::c_int,
    flags: libc::c_ulong,
) -> libc::c_long {
    unsafe {
        syscall(
            libc::SYS_perf_event_open,
            hw_event as *const perf_event_attr,
            pid,
            cpu,
            group_fd,
            flags,
        )
    }
}

// XXXETSAL: Comment below is taken verbatim from the original systing code
// We're just doing this until the libbpf-rs crate gets updated with my patch.
trait LibbpfPerfOptions {
    fn attach_perf_event_with_opts(
        &self,
        pefd: i32,
    ) -> Result<libbpf_rs::Link, libbpf_rs::Error>;
}

impl LibbpfPerfOptions for libbpf_rs::ProgramMut<'_> {
    fn attach_perf_event_with_opts(
        &self,
        pefd: i32,
    ) -> Result<libbpf_rs::Link, libbpf_rs::Error> {
        let mut opts = libbpf_sys::bpf_perf_event_opts::default();
        opts.bpf_cookie = 0;
        opts.sz = mem::size_of::<libbpf_sys::bpf_perf_event_opts>() as u64;
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_perf_event_opts(
                self.as_libbpf_object().as_ptr(),
                pefd,
                &opts as *const _ as *const _,
            )
        };
        let ret = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if ret != 0 {
            return Err(libbpf_rs::Error::from_raw_os_error(-ret as i32));
        }
        let ptr = unsafe { std::ptr::NonNull::new_unchecked(ptr) };
        let link = unsafe { libbpf_rs::Link::from_ptr(ptr) };
        Ok(link)
    }
}
pub fn init_perf_counters(skel: &mut BpfSkel, cpu: &i32) -> Result<(i32, libbpf_rs::Link), libbpf_rs::Error> {
    let buf: Vec<u8> = vec![0; mem::size_of::<perf_event_attr>()];
    let mut attr = unsafe {
        Box::<perf_event_attr>::from_raw(
            buf.leak().as_mut_ptr() as *mut perf_event_attr
        )
    };
    
    attr._type = PERF_TYPE_HARDWARE;
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.sample.sample_period = 1000;
    attr.flags = 0;

    let pefd = perf_event_open(attr.as_ref(), -1, *cpu, -1, 0) as i32;
    if pefd == -1 {
        let os_error = io::Error::last_os_error();
        return Err(libbpf_rs::Error::from(os_error));
    }

    let link = skel.progs.drain_counters.attach_perf_event_with_opts(pefd);

    Ok((pefd, link?))
}
