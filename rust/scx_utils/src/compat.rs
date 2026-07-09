// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::libbpf_sys::*;
use libbpf_rs::{AsRawLibbpf, OpenProgramImpl, ProgramImpl};
use log::{error, warn};
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

mod enums_abi {
    include!("enums_abi.autogen.rs");
}

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
    pub static ref SCX_OPS_ALWAYS_ENQ_IMMED: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_ALWAYS_ENQ_IMMED").unwrap_or(0);
    pub static ref SCX_OPS_ENQ_BLOCKED: u64 =
        read_enum("scx_ops_flags", "SCX_OPS_ENQ_BLOCKED").unwrap_or(0);

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

fn btf_params(t: &btf_type) -> &[btf_param] {
    let ptr = btf_type_plus_1(t);
    unsafe { from_raw_parts(ptr as *const btf_param, btf_vlen(t) as usize) }
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

/// Recover the true value of a 64-bit enum enumerator whose kernel BTF entry
/// was truncated to its low 32 bits.
///
/// Kernels whose BTF was generated without BTF_KIND_ENUM64 support encode
/// 64-bit enums as 8-byte BTF_KIND_ENUM entries whose enumerator values only
/// carry the low 32 bits. This happens with pahole < 1.24, which predates
/// ENUM64, and with pahole passing --skip_encoding_btf_enum64 (e.g. Google's
/// Container-Optimized OS / GKE kernels deliberately pass it for backward
/// compatibility with older BTF consumers). The high bits
/// can't be recovered from kernel BTF, so substitute the value from the
/// vmlinux.h this tree was built against, cross-checked against the low 32
/// bits the kernel did provide.
///
/// Note that this is a best-effort recovery, not a ground truth. The
/// substitution assumes the running kernel agrees with this tree's vmlinux.h
/// on the high 32 bits, but only the low 32 bits can actually be verified.
/// The cross-check is vacuous for enumerators whose value has no low bits
/// set (e.g. SCX_DSQ_FLAG_BUILTIN, __SCX_ENQ_INTERNAL_MASK,
/// SCX_ENQ_CLEAR_OPSS, SCX_ECODE_*): their lo32 is 0 and matches anything,
/// so those substitutions rest entirely on the high bits never moving. An
/// enumerator missing from the table (a kernel newer than this tree's
/// vmlinux.h, or a stale autogen table) can't be recovered at all. If a
/// substitution is ever wrong, the scheduler operates on bogus values (e.g.
/// dispatching to nonexistent DSQ ids or silently dropping flags) and can
/// wildly malfunction, which is why the mismatch and table-miss paths refuse
/// instead of guessing.
fn recover_truncated_enum64_from(
    table: &[(&str, &str, u64)],
    type_name: &str,
    name: &str,
    lo32: u32,
) -> Result<u64> {
    static WARN_ONCE: std::sync::Once = std::sync::Once::new();

    let Some(&(_, _, abi_val)) = table.iter().find(|(t, n, _)| *t == type_name && *n == name)
    else {
        // Unknown enumerator (likely a stale autogen table). Fail
        // pessimistically to avoid returning an invalid value. Log too, as
        // callers commonly swallow the error with .unwrap_or(0).
        let msg = format!(
            "kernel BTF truncates 64-bit enum {}::{} to 0x{:x}; 64-bit \
             variant not found in vmlinux.h",
            type_name, name, lo32
        );
        error!("{}", msg);
        bail!(msg);
    };

    if abi_val <= u32::MAX as u64 {
        return Ok(lo32 as u64);
    }

    if abi_val as u32 != lo32 {
        // Log too, as callers commonly swallow the error with .unwrap_or(0).
        let msg = format!(
            "kernel BTF value of {}::{} (0x{:x}) doesn't match the low 32 bits \
             of the vmlinux.h value (0x{:x}); refusing to substitute",
            type_name, name, lo32, abi_val
        );
        error!("{}", msg);
        bail!(msg);
    }

    WARN_ONCE.call_once(|| {
        warn!(
            "kernel BTF lacks BTF_KIND_ENUM64 encoding (generated by \
             pahole < 1.24 or with --skip_encoding_btf_enum64), so 64-bit \
             scx enum values are truncated to their low 32 bits in kernel \
             BTF. Substituting the full 64-bit values from the vmlinux.h \
             this binary was built against, cross-checked against the low \
             32 bits the kernel does provide. The high 32 bits cannot be \
             verified: if the running kernel's actual values differ from \
             the build-time vmlinux.h (e.g. an enum that moved in a newer \
             kernel), the scheduler will operate on bogus values, such as \
             dispatching to nonexistent DSQ ids, and can wildly malfunction."
        );
    });
    Ok(abi_val)
}

fn recover_truncated_enum64(type_name: &str, name: &str, lo32: u32) -> Result<u64> {
    recover_truncated_enum64_from(enums_abi::ENUM_ABI_VALUES, type_name, name, lo32)
}

pub fn read_enum(type_name: &str, name: &str) -> Result<u64> {
    let btf: &btf = *VMLINUX_BTF;

    let c_type_name = CString::new(type_name).unwrap();
    let tid = unsafe { btf__find_by_name(btf, c_type_name.as_ptr()) };
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
                    // Try to recover a 64-bit enum from an 8-byte BTF_KIND_ENUM that was encoded
                    // without ENUM64 support (old pahole or --skip_encoding_btf_enum64). Only
                    // scx_* types are covered by the substitution table; non-scx types fall
                    // through to the raw value so this generic utility keeps working for them.
                    if unsafe { t.__bindgen_anon_1.size } == 8 && type_name.starts_with("scx_") {
                        return recover_truncated_enum64(type_name, name, e.val as u32);
                    }
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

/// Read an enum value from the first BTF enum type that contains it.
pub fn read_enum_any(type_names: &[&str], name: &str) -> Result<u64> {
    let mut errors = Vec::new();

    for type_name in type_names {
        match read_enum(type_name, name) {
            Ok(val) => return Ok(val),
            Err(err) => errors.push(format!("{}: {:#}", type_name, err)),
        }
    }

    bail!(
        "{:?} doesn't exist in any of {:?}: {}",
        name,
        type_names,
        errors.join("; ")
    )
}

pub fn struct_has_field(type_name: &str, field: &str) -> Result<bool> {
    let btf: &btf = *VMLINUX_BTF;

    let c_type_name = CString::new(type_name).unwrap();
    let tid = unsafe { btf__find_by_name_kind(btf, c_type_name.as_ptr(), BTF_KIND_STRUCT) };
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

/// Scan the running kernel's vmlinux BTF for scx kfuncs whose public-facing
/// prototype still carries the implicit `aux` (struct bpf_prog_aux *) argument.
///
/// This is the KF_IMPLICIT_ARGS-on-pahole-<1.26 bug: pahole < 1.26 fails to
/// split such kfuncs into a public prototype (without `aux`) and an `_impl`
/// variant (with it), so the visible prototype keeps `aux`. BPF programs that
/// declare the kfunc without it then fail to load with the confusing
/// 'func_proto incompatible with vmlinux' error. Returns the names of the
/// affected kfuncs, so a clear diagnostic can be produced on load failure.
pub fn malformed_scx_kfuncs() -> Vec<String> {
    let btf: &btf = *VMLINUX_BTF;
    let mut bad = Vec::new();
    let cnt = unsafe { btf__type_cnt(btf) };

    for id in 1..cnt {
        let t = unsafe { btf__type_by_id(btf, id) };
        if t.is_null() {
            continue;
        }
        let t = unsafe { &*t };
        if btf_kind(t) != BTF_KIND_FUNC {
            continue;
        }

        let Ok(name) = btf_name_str_by_offset(btf, t.name_off) else {
            continue;
        };
        if !(name.starts_with("scx_bpf_") || name.starts_with("__scx_bpf_")) {
            continue;
        }
        // The implicit `aux` argument legitimately appears on the `_impl`
        // variant that resolve_btfids splits off; only the public-facing name
        // (without the `_impl` suffix) should be free of it. On a broken kernel
        // the split never happens, so there is no `_impl` variant and the
        // public name itself keeps `aux`.
        if name.ends_with("_impl") {
            continue;
        }

        // FUNC -> FUNC_PROTO
        let proto_id = unsafe { t.__bindgen_anon_1.type_ };
        let pt = unsafe { btf__type_by_id(btf, proto_id) };
        if pt.is_null() {
            continue;
        }
        let pt = unsafe { &*pt };
        if btf_kind(pt) != BTF_KIND_FUNC_PROTO {
            continue;
        }

        if btf_params(pt).iter().any(|p| {
            p.name_off != 0 && matches!(btf_name_str_by_offset(btf, p.name_off), Ok("aux"))
        }) {
            bad.push(name.to_string());
        }
    }

    bad
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

            {
                let ops = $skel.struct_ops.[<$ops _mut>]();
                if ops.sub_cgroup_id > 0 {
                    if let Ok(false) | Err(_) = scx_utils::compat::struct_has_field("sched_ext_ops", "sub_cgroup_id") {
                        ::scx_utils::warn!("kernel doesn't support ops.sub_cgroup_id");
                        ops.sub_cgroup_id = 0;
                    }
                }
            }

            scx_utils::uei_set_size!($skel, $ops, $uei);
            $skel.load().context("Failed to load BPF program").map_err(|e| {
                let bad = scx_utils::compat::malformed_scx_kfuncs();
                if bad.is_empty() {
                    e
                } else {
                    e.context(format!(
                        "the running kernel's BTF has malformed scx kfunc prototype(s): {}.\n\
                         \n\
                         These kfuncs are KF_IMPLICIT_ARGS but their public BTF prototype\n\
                         still carries the implicit 'struct bpf_prog_aux *' argument, which\n\
                         makes BPF programs fail to load with 'func_proto incompatible with\n\
                         vmlinux'. This happens when the kernel was built with pahole < 1.26.\n\
                         \n\
                         Fix: boot a kernel whose BTF was generated with pahole >= 1.26.\n\
                         Affected distros include Ubuntu 24.04 LTS. See kernel commit\n\
                         9edd04c4189e (\"docs: Raise minimum pahole version to 1.26 for\n\
                         KF_IMPLICIT_ARGS kfuncs\").",
                        bad.join(", ")
                    ))
                }
            })
        }
    }};
}

/// Must be used together with scx_ops_load!(). See there.
#[rustfmt::skip]
#[macro_export]
macro_rules! scx_ops_attach {
    ($skel: expr, $ops: ident) => {
        scx_ops_attach!($skel, $ops, false)
    };
    ($skel: expr, $ops: ident, $is_subsched: expr) => { 'block: {
        use ::anyhow::Context;
        use ::libbpf_rs::skel::Skel;

        if !$is_subsched && scx_utils::compat::is_sched_ext_enabled().unwrap_or(false) {
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
    fn test_read_enum_any() {
        assert_eq!(
            super::read_enum_any(&["NO_SUCH_TYPE", "pid_type"], "PIDTYPE_TGID").unwrap(),
            1
        );
        assert!(super::read_enum_any(&["NO_SUCH_TYPE", "pid_type"], "NO_SUCH_ENUM").is_err());
    }

    #[test]
    fn test_recover_truncated_enum64() {
        let table: &[(&str, &str, u64)] = &[
            ("scx_dsq_id_flags", "SCX_DSQ_LOCAL", 0x8000000000000002),
            ("scx_enq_flags", "SCX_ENQ_PREEMPT", 0x100000000),
            ("scx_enq_flags", "SCX_ENQ_HEAD", 0x10000),
        ];

        // >32-bit values with matching low bits get substituted.
        assert_eq!(
            super::recover_truncated_enum64_from(table, "scx_dsq_id_flags", "SCX_DSQ_LOCAL", 2)
                .unwrap(),
            0x8000000000000002
        );
        assert_eq!(
            super::recover_truncated_enum64_from(table, "scx_enq_flags", "SCX_ENQ_PREEMPT", 0)
                .unwrap(),
            0x100000000
        );
        // Sub-32-bit values truncate losslessly, so the kernel's value stays
        // authoritative even when it disagrees with the table.
        assert_eq!(
            super::recover_truncated_enum64_from(table, "scx_enq_flags", "SCX_ENQ_HEAD", 0x20000)
                .unwrap(),
            0x20000
        );
        // A low-32 mismatch on a >32-bit value is ABI drift; refuse.
        assert!(super::recover_truncated_enum64_from(
            table,
            "scx_dsq_id_flags",
            "SCX_DSQ_LOCAL",
            3
        )
        .is_err());
        // Unknown enumerators fail pessimistically (stale autogen table).
        assert!(
            super::recover_truncated_enum64_from(table, "scx_enq_flags", "SCX_ENQ_NEW", 7).is_err()
        );
    }

    #[test]
    fn test_enum_abi_table() {
        // Spot-check the autogenerated table against ABI values that have
        // been stable on every kernel that ships sched_ext.
        let find = |t: &str, n: &str| {
            super::enums_abi::ENUM_ABI_VALUES
                .iter()
                .find(|(ty, na, _)| *ty == t && *na == n)
                .map(|&(_, _, v)| v)
        };
        assert_eq!(
            find("scx_dsq_id_flags", "SCX_DSQ_FLAG_BUILTIN"),
            Some(1 << 63)
        );
        assert_eq!(
            find("scx_dsq_id_flags", "SCX_DSQ_LOCAL"),
            Some((1 << 63) | 2)
        );
        assert_eq!(
            find("scx_dsq_id_flags", "SCX_DSQ_LOCAL_ON"),
            Some((1 << 63) | (1 << 62))
        );
        assert_eq!(find("scx_public_consts", "SCX_SLICE_INF"), Some(u64::MAX));
        assert_eq!(find("scx_enq_flags", "SCX_ENQ_PREEMPT"), Some(1 << 32));
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

    #[test]
    fn test_malformed_scx_kfuncs() {
        // Just exercise the BTF walk; a correctly built running kernel reports
        // no malformed kfuncs, but we don't assert emptiness since the test may
        // run on an affected kernel.
        let bad = super::malformed_scx_kfuncs();
        assert!(bad.iter().all(|n| !n.ends_with("_impl")));
    }
}
