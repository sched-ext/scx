extern crate libc;

use crate::bpf_skel::*;

use libbpf_rs;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::libbpf_sys;
use std::io;
use std::mem;

// Expanded from systing's code: www.github.com/josefbacik/systing

const _PERF_TYPE_HARDWARE: u32 = 0x0;
const _PERF_TYPE_SOFTWARE: u32 = 0x1;
const _PERF_TYPE_RAW: u32 = 0x3;
const _PERF_TYPE_AMD_IBS: u32 = 0xb;

const _PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const _PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const _PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const _PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
const _PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;

const _PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

// WARNING: These are not guaranteed to be correct because the layout of the bitfield
// in the perf_sample_attr C struct that contains them is not guaranteed by the C standard.
const _PERF_SAMPLE_FLAG_DISABLED: u64 = 1 << 0;
const _PERF_SAMPLE_FLAG_INHERIT: u64 = 1 << 1;
const _PERF_SAMPLE_FLAG_PINNED: u64 = 1 << 2;
const _PERF_SAMPLE_FLAG_EXCLUSIVE: u64 = 1 << 3;
const _PERF_SAMPLE_FLAG_EXCLUDE_USER: u64 = 1 << 4;
const _PERF_SAMPLE_FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
const _PERF_SAMPLE_FLAG_EXCLUDE_HV: u64 = 1 << 6;
const _PERF_SAMPLE_FLAG_EXCLUDE_IDLE: u64 = 1 << 7;
const _PERF_SAMPLE_FLAG_MMAP: u64 = 1 << 8;
const _PERF_SAMPLE_FLAG_COMM: u64 = 1 << 9;
const _PERF_SAMPLE_FLAG_FREQ: u64 = 1 << 10;
const _PERF_SAMPLE_FLAG_INHERIT_STAT: u64 = 1 << 11;
const _PERF_SAMPLE_FLAG_ENABLE_ON_EXEC: u64 = 1 << 12;
const _PERF_SAMPLE_FLAG_TASK: u64 = 1 << 13;
const _PERF_SAMPLE_FLAG_WATERMARK: u64 = 1 << 14;
const _PERF_SAMPLE_FLAG_PRECISE_IP: u64 = 1 << 15;
const _PERF_SAMPLE_FLAG_MMAP_DATA: u64 = 1 << 17;
const _PERF_SAMPLE_FLAG_ID_ALL: u64 = 1 << 18;
const _PERF_SAMPLE_FLAG_EXCLUDE_HOST: u64 = 1 << 19;
const _PERF_SAMPLE_FLAG_EXCLUDE_GUEST: u64 = 1 << 20;
const _PERF_SAMPLE_FLAG_EXCLUDE_CALLCHAIN_KERNEL: u64 = 1 << 21;
const _PERF_SAMPLE_FLAG_EXCLUDE_CALLCHAIN_USER: u64 = 1 << 22;
const _PERF_SAMPLE_FLAG_MMAP2: u64 = 1 << 23;
const _PERF_SAMPLE_FLAG_COMM_EXEC: u64 = 1 << 24;
const _PERF_SAMPLE_FLAG_USE_CLOCKID: u64 = 1 << 25;
const _PERF_SAMPLE_FLAG_WRITE_BACKWARD: u64 = 1 << 26;
const _PERF_SAMPLE_FLAG_NAMESPACES: u64 = 1 << 27;
const _PERF_SAMPLE_FLAG_KSYMBOL: u64 = 1 << 28;
const _PERF_SAMPLE_FLAG_BPF_SYMBOL: u64 = 1 << 29;
const _PERF_SAMPLE_FLAG_AUX_OUTPUT: u64 = 1 << 30;
const _PERF_SAMPLE_FLAG_CGROUP: u64 = 1 << 31;
const _PERF_SAMPLE_FLAG_TEXT_POKE: u64 = 1 << 32;
const _PERF_SAMPLE_FLAG_BUILD_ID: u64 = 1 << 33;
const _PERF_SAMPLE_FLAG_INHERIT_THREAD: u64 = 1 << 34;
const _PERF_SAMPLE_FLAG_REMOVE_ON_EXEC: u64 = 1 << 35;
const _PERF_SAMPLE_FLAG_SIGTRAP: u64 = 1 << 36;

const _PERF_SAMPLE_IP: u64 = 1 << 0;
const _PERF_SAMPLE_TID: u64 = 1 << 1;
const _PERF_SAMPLE_TIME: u64 = 1 << 2;
const _PERF_SAMPLE_ADDR: u64 = 1 << 3;
const _PERF_SAMPLE_READ: u64 = 1 << 4;
const _PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
const _PERF_SAMPLE_ID: u64 = 1 << 6;
const _PERF_SAMPLE_CPU: u64 = 1 << 7;
const _PERF_SAMPLE_PERIOD: u64 = 1 << 8;
const _PERF_SAMPLE_STREAM_ID: u64 = 1 << 9;
const _PERF_SAMPLE_RAW: u64 = 1 << 10;
const _PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;
const _PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
const _PERF_SAMPLE_STACK_USER: u64 = 1 << 13;
const _PERF_SAMPLE_WEIGHT: u64 = 1 << 14;
const _PERF_SAMPLE_DATA_SRC: u64 = 1 << 15;
const _PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;
const _PERF_SAMPLE_TRANSACTION: u64 = 1 << 17;
const _PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
const _PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
const _PERF_SAMPLE_PHYS_AUX: u64 = 1 << 20;
const _PERF_SAMPLE_PHYS_CGROUP: u64 = 1 << 21;
const _PERF_SAMPLE_DATA_PAGE_SIZE: u64 = 1 << 22;
const _PERF_SAMPLE_CODE_PAGE_SIZE: u64 = 1 << 23;
const _PERF_SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;

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
    
    /* 
     * XXX Discover the counter instead of hardcoding it.
     * Afterwards we can use any counter we care for.
     */
    attr._type = _PERF_TYPE_AMD_IBS;
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.config = 0;
    attr.sample_type = _PERF_SAMPLE_CPU | _PERF_SAMPLE_IP | _PERF_SAMPLE_TID | _PERF_SAMPLE_DATA_SRC | _PERF_SAMPLE_PHYS_ADDR | _PERF_SAMPLE_ADDR;
    attr.sample.sample_period = 1000;
    attr.flags = 3 * _PERF_SAMPLE_FLAG_PRECISE_IP;

    let pefd = perf_event_open(attr.as_ref(), -1, *cpu, -1, 0) as i32;
    if pefd == -1 {
        let os_error = io::Error::last_os_error();
        return Err(libbpf_rs::Error::from(os_error));
    }

    let link = skel.progs.read_sample.attach_perf_event_with_opts(pefd);

    Ok((pefd, link?))
}
