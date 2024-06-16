// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::libbpf_sys::*;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::slice::from_raw_parts;

lazy_static::lazy_static! {
    pub static ref SCX_OPS_SWITCH_PARTIAL: u64 =
    read_enum("scx_ops_flags", "SCX_OPS_SWITCH_PARTIAL").unwrap_or(0);
}

fn load_vmlinux_btf() -> &'static mut btf {
    let btf = unsafe { btf__load_vmlinux_btf() };
    if btf.is_null() {
        panic!("btf__load_vmlinux_btf() returned NULL");
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

    return Ok(false);
}

pub fn ksym_exists(ksym: &str) -> Result<bool> {
    let btf: &btf = *VMLINUX_BTF;

    let ksym_name = CString::new(ksym).unwrap();
    let tid = unsafe { btf__find_by_name(btf, ksym_name.as_ptr()) };
    Ok(tid >= 0)
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
    if let Ok(false) | Err(_) = ksym_exists("scx_bpf_cpuperf_cap") {
	bail!("scx_bpf_cpuperf_*() missing, kernel too old?");
    }
    if let Ok(false) | Err(_) = ksym_exists("scx_bpf_nr_cpu_ids") {
	bail!("scx_bpf_nr_cpu_ids() missing, kernel too old?");
    }
    if let Ok(false) | Err(_) = ksym_exists("scx_bpf_dump_bstr") {
	bail!("scx_bpf_dump() missing, kernel too old?");
    }
    if let Ok(false) | Err(_) = ksym_exists("scx_bpf_exit_bstr") {
	bail!("scx_bpf_exit() missing, kernel too old?");
    }
    if let Err(_) = read_enum("scx_kick_flags", "SCX_KICK_IDLE") {
	bail!("SCX_KICK_IDLE missing, kernel too old?");
    }
    if *SCX_OPS_SWITCH_PARTIAL == 0 {
	bail!("SCX_OPS_SWITCH_PARTIAL missing, kernel too old?");
    }
    Ok(())
}

/// struct sched_ext_ops can change over time. If compat.bpf.h::SCX_OPS_DEFINE()
/// is used to define ops, and scx_ops_open!(), scx_ops_load!(), and
/// scx_ops_attach!() are used to open, load and attach it, backward
/// compatibility is automatically maintained where reasonable.
///
/// - sched_ext_ops.hotplug_seq was added later. On kernels which support it,
/// set the value to a nonzero value to trigger an exit in the scheduler when
/// a hotplug event occurs between opening and attaching the scheduler.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_open {
    ($builder: expr, $ops: ident) => { 'block: {
        scx_utils::paste! {
	    scx_utils::unwrap_or_break!(scx_utils::compat::check_min_requirements(), 'block);

            let mut skel = match $builder.open().context("Failed to open BPF program") {
                Ok(val) => val,
                Err(e) => break 'block Err(e),
            };

            let ops = skel.struct_ops.[<$ops _mut>]();
            let has_field = scx_utils::unwrap_or_break!(
                scx_utils::compat::struct_has_field("sched_ext_ops", "hotplug_seq"), 'block);

            if has_field {
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
            }

            let result : Result<OpenBpfSkel<'_>, anyhow::Error> = Ok(skel);
            result
        }
    }};
}

/// struct sched_ext_ops can change over time. If compat.bpf.h::SCX_OPS_DEFINE()
/// is used to define ops, and scx_ops_open!(), scx_ops_load!(), and
/// scx_ops_attach!() are used to open, load and attach it, backward
/// compatibility is automatically maintained where reasonable.
///
/// - sched_ext_ops.exit_dump_len was added later. On kernels which don't
/// support it, the value is ignored and a warning is triggered if the value
/// is requested to be non-zero.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_load {
    ($skel: expr, $ops: ident, $uei: ident) => { 'block: {
        scx_utils::paste! {
            scx_utils::uei_set_size!($skel, $ops, $uei);

            let ops = $skel.struct_ops.[<$ops _mut>]();

            let has_field = scx_utils::unwrap_or_break!(
                scx_utils::compat::struct_has_field("sched_ext_ops", "exit_dump_len"), 'block);
            if !has_field && ops.exit_dump_len != 0 {
                scx_utils::warn!("Kernel doesn't support setting exit dump len");
                ops.exit_dump_len = 0;
            }

            let has_field = scx_utils::unwrap_or_break!(
                scx_utils::compat::struct_has_field("sched_ext_ops", "tick"), 'block);
            if !has_field && ops.tick != std::ptr::null_mut() {
                scx_utils::warn!("Kernel doesn't support ops.tick()");
                ops.tick = std::ptr::null_mut();
            }

            let has_field = scx_utils::unwrap_or_break!(
                scx_utils::compat::struct_has_field("sched_ext_ops", "dump"), 'block);
            if !has_field && (ops.dump != std::ptr::null_mut() ||
                              ops.dump_cpu != std::ptr::null_mut() ||
                              ops.dump_task != std::ptr::null_mut()) {
                scx_utils::warn!("Kernel doesn't support ops.dump*()");
                ops.dump = std::ptr::null_mut();
                ops.dump_cpu = std::ptr::null_mut();
                ops.dump_task = std::ptr::null_mut();
            }

            $skel.load().context("Failed to load BPF program")
        }
    }};
}

/// Must be used together with scx_ops_load!(). See there.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_attach {
    ($skel: expr, $ops: ident) => { 'block: {
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
                    .maps_mut()
                    .$ops()
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
        assert!(super::ksym_exists("scx_bpf_consume").unwrap());
        assert!(!super::ksym_exists("NO_SUCH_KFUNC").unwrap());
    }
}
