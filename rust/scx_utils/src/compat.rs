// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::libbpf_sys::*;
use libbpf_rs::{AsRawLibbpf, OpenProgramImpl, ProgramImpl};
use log::warn;
use std::env;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::mem::size_of;
use std::slice::from_raw_parts;

const PROCFS_MOUNTS: &str = "/proc/mounts";
const TRACEFS: &str = "tracefs";
const DEBUGFS: &str = "debugfs";

lazy_static::lazy_static! {
    pub static ref SCX_OPS_KEEP_BUILTIN_IDLE: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_KEEP_BUILTIN_IDLE").unwrap_or(0);
    pub static ref SCX_OPS_ENQ_LAST: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_ENQ_LAST").unwrap_or(0);
    pub static ref SCX_OPS_ENQ_EXITING: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_ENQ_EXITING").unwrap_or(0);
    pub static ref SCX_OPS_SWITCH_PARTIAL: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_SWITCH_PARTIAL").unwrap_or(0);
    pub static ref SCX_OPS_ENQ_MIGRATION_DISABLED: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_ENQ_MIGRATION_DISABLED").unwrap_or(0);
    pub static ref SCX_OPS_ALLOW_QUEUED_WAKEUP: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_ALLOW_QUEUED_WAKEUP").unwrap_or(0);
    pub static ref SCX_OPS_BUILTIN_IDLE_PER_NODE: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_BUILTIN_IDLE_PER_NODE").unwrap_or(0);

    pub static ref SCX_PICK_IDLE_CORE: u64 =
        read_enum("scx_pick_idle_cpu_flags", "SCX_PICK_IDLE_CORE").unwrap_or(0);
    pub static ref SCX_PICK_IDLE_IN_NODE: u64 =
        read_enum("scx_pick_idle_cpu_flags", "SCX_PICK_IDLE_IN_NODE").unwrap_or(0);

    pub static ref ROOT_PREFIX: String =
        env::var("SCX_SYSFS_PREFIX").unwrap_or("".to_string());
}

fn load_vmlinux_btf() -> &'static mut btf {
    let btf = unsafe { btf__load_vmlinux_btf() };
    if btf.is_null() {
        panic!("btf__load_vmlinux_btf() returned NULL, was CONFIG_DEBUG_INFO_BTF enabled?")
    }
    unsafe { &mut *btf }
}

lazy_static::lazy_static! {
    static ref VMLINUX_BTF: &'static mut btf = load_vmlinux_btf();
}

fn btf_kind(t: &btf_type) -> u32 {
    (t.info >> 24) & 0x1f
}

fn btf_vlen(t: &btf_type) -> u32 {
    t.info & 0xffff
}

fn btf_type_plus_1(t: &btf_type) -> *const c_void {
    let ptr_val = t as *const btf_type as usize;
    (ptr_val + size_of::<btf_type>()) as *const c_void
}

fn btf_enum(t: &btf_type) -> &[btf_enum] {
    let ptr = btf_type_plus_1(t);
    unsafe { from_raw_parts(ptr as *const btf_enum, btf_vlen(t) as usize) }
}

fn btf_enum64(t: &btf_type) -> &[btf_enum64] {
    let ptr = btf_type_plus_1(t);
    unsafe { from_raw_parts(ptr as *const btf_enum64, btf_vlen(t) as usize) }
}

fn btf_members(t: &btf_type) -> &[btf_member] {
    let ptr = btf_type_plus_1(t);
    unsafe { from_raw_parts(ptr as *const btf_member, btf_vlen(t) as usize) }
}

fn btf_name_str_by_offset(btf: &btf, name_off: u32) -> Result<&str> {
    let n = unsafe { btf__name_by_offset(btf, name_off) };
    if n.is_null() {
        bail!("btf__name_by_offset() returned NULL");
    }
    Ok(unsafe { CStr::from_ptr(n) }
        .to_str()
        .with_context(|| format!("Failed to convert {:?} to string", n))?)
}

pub fn read_enum(type_name: &str, name: &str) -> Result<u64> {
    let btf: &btf = *VMLINUX_BTF;

    let type_name = CString::new(type_name).unwrap();
    let tid = unsafe { btf__find_by_name(btf, type_name.as_ptr()) };
    if tid < 0 {
        bail!("type {:?} doesn't exist, ret={}", type_name, tid);
    }

    let t = unsafe { btf__type_by_id(btf, tid as _) };
    if t.is_null() {
        bail!("btf__type_by_id({}) returned NULL", tid);
    }
    let t = unsafe { &*t };

    match btf_kind(t) {
        BTF_KIND_ENUM => {
            for e in btf_enum(t).iter() {
                if btf_name_str_by_offset(btf, e.name_off)? == name {
                    return Ok(e.val as u64);
                }
            }
        }
        BTF_KIND_ENUM64 => {
            for e in btf_enum64(t).iter() {
                if btf_name_str_by_offset(btf, e.name_off)? == name {
                    return Ok(((e.val_hi32 as u64) << 32) | (e.val_lo32) as u64);
                }
            }
        }
        _ => (),
    }

    Err(anyhow!("{:?} doesn't exist in {:?}", name, type_name))
}

pub fn struct_has_field(type_name: &str, field: &str) -> Result<bool> {
    let btf: &btf = *VMLINUX_BTF;

    let type_name = CString::new(type_name).unwrap();
    let tid = unsafe { btf__find_by_name_kind(btf, type_name.as_ptr(), BTF_KIND_STRUCT) };
    if tid < 0 {
        bail!("type {:?} doesn't exist, ret={}", type_name, tid);
    }

    let t = unsafe { btf__type_by_id(btf, tid as _) };
    if t.is_null() {
        bail!("btf__type_by_id({}) returned NULL", tid);
    }
    let t = unsafe { &*t };

    for m in btf_members(t).iter() {
        if btf_name_str_by_offset(btf, m.name_off)? == field {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn ksym_exists(ksym: &str) -> Result<bool> {
    let btf: &btf = *VMLINUX_BTF;

    let ksym_name = CString::new(ksym).unwrap();
    let tid = unsafe { btf__find_by_name(btf, ksym_name.as_ptr()) };
    Ok(tid >= 0)
}

pub fn in_kallsyms(ksym: &str) -> Result<bool> {
    let file = std::fs::File::open("/proc/kallsyms")?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        for sym in line.unwrap().split_whitespace() {
            if ksym == sym {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Returns the mount point for a filesystem type.
pub fn get_fs_mount(mount_type: &str) -> Result<Vec<std::path::PathBuf>> {
    let proc_mounts_path = std::path::Path::new(PROCFS_MOUNTS);

    let file = std::fs::File::open(proc_mounts_path)
        .with_context(|| format!("Failed to open {}", proc_mounts_path.display()))?;

    let reader = BufReader::new(file);

    let mut mounts = Vec::new();
    for line in reader.lines() {
        let line = line.context("Failed to read line from /proc/mounts")?;
        let mount_info: Vec<&str> = line.split_whitespace().collect();

        if mount_info.len() > 3 && mount_info[2] == mount_type {
            let mount_path = std::path::PathBuf::from(mount_info[1]);
            mounts.push(mount_path);
        }
    }

    Ok(mounts)
}

/// Returns the tracefs mount point.
pub fn tracefs_mount() -> Result<std::path::PathBuf> {
    let mounts = get_fs_mount(TRACEFS)?;
    mounts.into_iter().next().context("No tracefs mount found")
}

/// Returns the debugfs mount point.
pub fn debugfs_mount() -> Result<std::path::PathBuf> {
    let mounts = get_fs_mount(DEBUGFS)?;
    mounts.into_iter().next().context("No debugfs mount found")
}

pub fn tracer_available(tracer: &str) -> Result<bool> {
    let base_path = tracefs_mount().unwrap_or_else(|_| debugfs_mount().unwrap().join("tracing"));
    let file = match std::fs::File::open(base_path.join("available_tracers")) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        for tc in line.unwrap().split_whitespace() {
            if tracer == tc {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub fn tracepoint_exists(tracepoint: &str) -> Result<bool> {
    let base_path = tracefs_mount().unwrap_or_else(|_| debugfs_mount().unwrap().join("tracing"));
    let file = match std::fs::File::open(base_path.join("available_events")) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        for tp in line.unwrap().split_whitespace() {
            if tracepoint == tp {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub fn cond_kprobe_enable<T>(sym: &str, prog_ptr: &OpenProgramImpl<T>) -> Result<bool> {
    if in_kallsyms(sym)? {
        unsafe {
            bpf_program__set_autoload(prog_ptr.as_libbpf_object().as_ptr(), true);
        }
        return Ok(true);
    } else {
        warn!("symbol {sym} is missing, kprobe not loaded");
    }

    Ok(false)
}

pub fn cond_kprobes_enable<T>(kprobes: Vec<(&str, &OpenProgramImpl<T>)>) -> Result<bool> {
    // Check if all the symbols exist.
    for (sym, _) in kprobes.iter() {
        if in_kallsyms(sym)? == false {
            warn!("symbol {sym} is missing, kprobe not loaded");
            return Ok(false);
        }
    }

    // Enable all the tracepoints.
    for (_, ptr) in kprobes.iter() {
        unsafe {
            bpf_program__set_autoload(ptr.as_libbpf_object().as_ptr(), true);
        }
    }

    Ok(true)
}

pub fn cond_kprobe_load<T>(sym: &str, prog_ptr: &OpenProgramImpl<T>) -> Result<bool> {
    if in_kallsyms(sym)? {
        unsafe {
            bpf_program__set_autoload(prog_ptr.as_libbpf_object().as_ptr(), true);
            bpf_program__set_autoattach(prog_ptr.as_libbpf_object().as_ptr(), false);
        }
        return Ok(true);
    } else {
        warn!("symbol {sym} is missing, kprobe not loaded");
    }

    Ok(false)
}

pub fn cond_kprobe_attach<T>(sym: &str, prog_ptr: &ProgramImpl<T>) -> Result<bool> {
    if in_kallsyms(sym)? {
        unsafe {
            bpf_program__attach(prog_ptr.as_libbpf_object().as_ptr());
        }
        return Ok(true);
    } else {
        warn!("symbol {sym} is missing, kprobe not loaded");
    }

    Ok(false)
}

pub fn cond_tracepoint_enable<T>(tracepoint: &str, prog_ptr: &OpenProgramImpl<T>) -> Result<bool> {
    if tracepoint_exists(tracepoint)? {
        unsafe {
            bpf_program__set_autoload(prog_ptr.as_libbpf_object().as_ptr(), true);
        }
        return Ok(true);
    } else {
        warn!("tracepoint {tracepoint} is missing, tracepoint not loaded");
    }

    Ok(false)
}

pub fn cond_tracepoints_enable<T>(tracepoints: Vec<(&str, &OpenProgramImpl<T>)>) -> Result<bool> {
    // Check if all the tracepoints exist.
    for (tp, _) in tracepoints.iter() {
        if tracepoint_exists(tp)? == false {
            warn!("tracepoint {tp} is missing, tracepoint not loaded");
            return Ok(false);
        }
    }

    // Enable all the tracepoints.
    for (_, ptr) in tracepoints.iter() {
        unsafe {
            bpf_program__set_autoload(ptr.as_libbpf_object().as_ptr(), true);
        }
    }

    Ok(true)
}

pub fn is_sched_ext_enabled() -> io::Result<bool> {
    let content = std::fs::read_to_string("/sys/kernel/sched_ext/state")?;

    match content.trim() {
        "enabled" => Ok(true),
        "disabled" => Ok(false),
        _ => {
            // Error if the content is neither "enabled" nor "disabled"
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected content in /sys/kernel/sched_ext/state",
            ))
        }
    }
}

#[macro_export]
macro_rules! unwrap_or_break {
    ($expr: expr, $label: lifetime) => {{
        match $expr {
            Ok(val) => val,
            Err(e) => break $label Err(e),
        }
    }};
}

pub fn check_min_requirements() -> Result<()> {
    // ec7e3b0463e1 ("implement-ops") in https://github.com/sched-ext/sched_ext
    // is the current minimum required kernel version.
    if let Ok(false) | Err(_) = struct_has_field("sched_ext_ops", "dump") {
        bail!("sched_ext_ops.dump() missing, kernel too old?");
    }
    Ok(())
}

/// struct sched_ext_ops can change over time. If compat.bpf.h::SCX_OPS_DEFINE()
/// is used to define ops, and scx_ops_open!(), scx_ops_load!(), and
/// scx_ops_attach!() are used to open, load and attach it, backward
/// compatibility is automatically maintained where reasonable.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_open {
    ($builder: expr, $obj_ref: expr, $ops: ident, $open_opts: expr) => { 'block: {
        scx_utils::paste! {
        scx_utils::unwrap_or_break!(scx_utils::compat::check_min_requirements(), 'block);
            use ::anyhow::Context;
            use ::libbpf_rs::skel::SkelBuilder;

            let mut skel = match $open_opts {
                Some(opts_ref) => { // Match a reference directly
                    match $builder.open_opts(opts_ref, $obj_ref).context("Failed to open BPF program with options") {
                        Ok(val) => val,
                        Err(e) => break 'block Err(e),
                    }
                }
                None => {
                    match $builder.open($obj_ref).context("Failed to open BPF program") {
                        Ok(val) => val,
                        Err(e) => break 'block Err(e),
                    }
                }
            };

            let ops = skel.struct_ops.[<$ops _mut>]();
            let path = std::path::Path::new("/sys/kernel/sched_ext/hotplug_seq");

            let val = match std::fs::read_to_string(&path) {
                Ok(val) => val,
                Err(_) => {
                    break 'block Err(anyhow::anyhow!("Failed to open or read file {:?}", path));
                }
            };

            ops.hotplug_seq = match val.trim().parse::<u64>() {
                Ok(parsed) => parsed,
                Err(_) => {
                    break 'block Err(anyhow::anyhow!("Failed to parse hotplug seq {}", val));
                }
            };

            if let Ok(s) = ::std::env::var("SCX_TIMEOUT_MS") {
                skel.struct_ops.[<$ops _mut>]().timeout_ms = match s.parse::<u32>() {
                    Ok(ms) => {
                        ::scx_utils::info!("Setting timeout_ms to {} based on environment", ms);
                        ms
                    },
                    Err(e) => {
                        break 'block anyhow::Result::Err(e).context("SCX_TIMEOUT_MS has invalid value");
                    },
                };
            }

            {
                let ops = skel.struct_ops.[<$ops _mut>]();

                let name_field = &mut ops.name;

                let version_suffix = ::scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));
                let bytes = version_suffix.as_bytes();
                let mut i = 0;
                let mut bytes_idx = 0;
                let mut found_null = false;

                while i < name_field.len() - 1 {
                    found_null |= name_field[i] == 0;
                    if !found_null {
                        i += 1;
                        continue;
                    }

                    if bytes_idx < bytes.len() {
                        name_field[i] = bytes[bytes_idx] as i8;
                        bytes_idx += 1;
                    } else {
                        break;
                    }
                    i += 1;
                }
                name_field[i] = 0;
            }

            $crate::import_enums!(skel);

            let result = ::anyhow::Result::Ok(skel);

            result
        }
    }};
}

/// struct sched_ext_ops can change over time. If compat.bpf.h::SCX_OPS_DEFINE()
/// is used to define ops, and scx_ops_open!(), scx_ops_load!(), and
/// scx_ops_attach!() are used to open, load and attach it, backward
/// compatibility is automatically maintained where reasonable.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_load {
    ($skel: expr, $ops: ident, $uei: ident) => { 'block: {
        scx_utils::paste! {
            use ::anyhow::Context;
            use ::libbpf_rs::skel::OpenSkel;

            scx_utils::uei_set_size!($skel, $ops, $uei);
            $skel.load().context("Failed to load BPF program")
        }
    }};
}

/// Must be used together with scx_ops_load!(). See there.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_attach {
    ($skel: expr, $ops: ident) => { 'block: {
        use ::anyhow::Context;
        use ::libbpf_rs::skel::Skel;

        if scx_utils::compat::is_sched_ext_enabled().unwrap_or(false) {
            break 'block Err(anyhow::anyhow!(
                "another sched_ext scheduler is already running"
            ));
        }
        $skel
            .attach()
            .context("Failed to attach non-struct_ops BPF programs")
            .and_then(|_| {
                $skel
                    .maps
                    .$ops
                    .attach_struct_ops()
                    .context("Failed to attach struct_ops BPF programs")
            })
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_enum() {
        assert_eq!(super::read_enum("pid_type", "PIDTYPE_TGID").unwrap(), 1);
    }

    #[test]
    fn test_struct_has_field() {
        assert!(super::struct_has_field("task_struct", "flags").unwrap());
        assert!(!super::struct_has_field("task_struct", "NO_SUCH_FIELD").unwrap());
        assert!(super::struct_has_field("NO_SUCH_STRUCT", "NO_SUCH_FIELD").is_err());
    }

    #[test]
    fn test_ksym_exists() {
        assert!(super::ksym_exists("bpf_task_acquire").unwrap());
        assert!(!super::ksym_exists("NO_SUCH_KFUNC").unwrap());
    }
}
