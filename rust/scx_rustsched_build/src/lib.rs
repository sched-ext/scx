// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Build script support for a Rust BPF sched_ext scheduler: build its
//! no_std BPF crate for the BPF target with the toolchain that builds the
//! scheduler, and add to each object's BTF what the Rust toolchain does
//! not emit. A scheduler's build.rs fills a Spec and calls build().

use std::{env, ffi::CString, fs, path::PathBuf, process::Command};

use libbpf_rs::libbpf_sys;

/// A kfunc of the catalog in scx_rustsched's kfuncs.rs: its name, parameters and
/// return type, whether a kernel may lack it, and whether it takes a
/// trailing size parameter on kernels that pass the structure's size.
pub struct Kfunc {
    pub name: &'static str,
    pub params: &'static [(&'static str, Ty)],
    pub ret: Ty,
    pub weak: bool,
    pub sized: bool,
}

/// The parameter and return types the catalog names, see the BPF side's
/// aliases in scx_rustsched's src/kfuncs.rs.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Ty {
    Void,
    I32,
    U32,
    U64,
    Bool,
    TaskPtr,
    VoidPtr,
    CpumaskPtr,
    TopoPtr,
    CgroupPtr,
    BytePtr,
    U64Ptr,
}

#[doc(hidden)]
#[macro_export]
macro_rules! kfunc_ret {
    () => {
        $crate::Ty::Void
    };
    ($ret:ident) => {
        $crate::Ty::$ret
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! kfunc_attr {
    ($want:ident) => {
        false
    };
    ($want:ident $attr:ident $($rest:ident)*) => {
        stringify!($want) == stringify!($attr) || $crate::kfunc_attr!($want $($rest)*)
    };
}

/// Expand a kfunc catalog, see scx_rustsched's kfuncs.rs, into a
/// `kfuncs()` function listing it for Spec.
#[macro_export]
macro_rules! kfuncs {
    ($( $(#[$attr:ident])* fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ; )*) => {
        fn kfuncs() -> Vec<$crate::Kfunc> {
            vec![$($crate::Kfunc {
                name: stringify!($name),
                params: &[$((stringify!($param), $crate::Ty::$type)),*],
                ret: $crate::kfunc_ret!($($ret)?),
                weak: $crate::kfunc_attr!(weak $($attr)*),
                sized: $crate::kfunc_attr!(sized $($attr)*),
            },)*]
        }
    };
}

/// What a Rust BPF scheduler hands the build: where its BPF crate is, what
/// it calls and reads from the kernel, and the object variants to build.
pub struct Spec<'a> {
    /// The package, for the warning on a host without the toolchain.
    pub package: &'a str,
    /// The BPF crate's manifest, catalog and binary name.
    pub manifest: &'a str,
    pub catalog: &'a str,
    pub crate_name: &'a str,
    pub kfuncs: Vec<Kfunc>,
    /// Per-CPU kernel variables read as ksyms: the name, its type and the
    /// size. They are weak, since not every kernel has every one.
    pub ksyms: &'a [(&'a std::ffi::CStr, u8, u32)],
    /// The objects to build, by name, and whether each is for a kernel
    /// whose scx_bpf_cid_topo() takes the structure's size.
    pub variants: &'a [(&'a str, bool)],
}

/// The kinds of per-CPU kernel variables, see Spec: an int, a struct
/// sched_domain pointer or a struct rq.
pub const KSYM_INT: u8 = 0;
pub const KSYM_DOMAIN_POINTER: u8 = 1;
pub const KSYM_RQ: u8 = 2;
/// The per-CPU kernel variables scx_rustsched reads.
pub const RUNTIME_KSYMS: [(&std::ffi::CStr, u8, u32); 6] = [
    (c"sched_core_priority", KSYM_INT, 4),
    (c"sd_asym_packing", KSYM_DOMAIN_POINTER, 8),
    (c"runqueues", KSYM_RQ, 0),
    (c"sd_llc", KSYM_DOMAIN_POINTER, 8),
    (c"sd_llc_id", KSYM_INT, 4),
    (c"sd_share_id", KSYM_INT, 4),
];

mod catalog {
    include!("../../scx_rustsched/kfuncs.rs");

    pub fn runtime() -> Vec<crate::Kfunc> {
        kfuncs()
    }
}

/// The kfuncs of scx_rustsched's catalog.
pub fn runtime_kfuncs() -> Vec<Kfunc> {
    catalog::runtime()
}

/// Build the BPF crate in bpf/ beside the build script, for a scheduler
/// that calls and reads nothing from the kernel but through scx_rustsched: the
/// runtime's kfuncs, kernel variables and global functions, and an object
/// for each kind of kernel. The whole build script of such a scheduler is
/// `fn main() { scx_rustsched_build::build_default(); }`.
pub fn build_default() {
    let catalog =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scx_rustsched/kfuncs.rs");
    let package = env::var("CARGO_PKG_NAME").expect("run from a build script");
    // The BPF crate's name, which is its binary's: the first `name` of
    // its manifest, the package's.
    let manifest = fs::read_to_string("bpf/Cargo.toml").expect("read bpf/Cargo.toml");
    let crate_name = manifest
        .lines()
        .find_map(|line| {
            let value = line.trim().strip_prefix("name")?.trim_start();
            Some(value.strip_prefix('=')?.trim().trim_matches('"').to_owned())
        })
        .expect("find the BPF crate's name in bpf/Cargo.toml");
    build(&Spec {
        package: &package,
        manifest: "bpf/Cargo.toml",
        catalog: catalog.to_str().unwrap(),
        crate_name: &crate_name,
        kfuncs: runtime_kfuncs(),
        ksyms: &RUNTIME_KSYMS,
        variants: &[("legacy", false), ("sized", true)],
    });
}

fn undefined_symbols(object: &std::path::Path) -> std::collections::HashSet<String> {
    let output = Command::new("llvm-nm")
        .args(["--undefined-only", "--format=just-symbols"])
        .arg(object)
        .output()
        .expect("run llvm-nm on the Rust BPF object");
    assert!(output.status.success(), "list Rust BPF object symbols");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().to_owned())
        .collect()
}

/// The type `id` names once its typedefs and qualifiers are peeled off.
unsafe fn resolved(btf: *const libbpf_sys::btf, mut id: u32) -> (u32, *const libbpf_sys::btf_type) {
    loop {
        let ty = unsafe { libbpf_sys::btf__type_by_id(btf, id) };
        assert!(!ty.is_null(), "resolve BTF type");
        let kind = unsafe { (*ty).info >> 24 & 0x1f };
        if !matches!(
            kind,
            libbpf_sys::BTF_KIND_TYPEDEF
                | libbpf_sys::BTF_KIND_CONST
                | libbpf_sys::BTF_KIND_VOLATILE
                | libbpf_sys::BTF_KIND_RESTRICT
        ) {
            return (kind, ty);
        }
        id = unsafe { (*ty).__bindgen_anon_1.type_ };
    }
}

/// The parameters of the object's global functions that are a pointer to
/// a task_struct, as (function, parameter index).
///
/// The verifier checks a global function once, from its prototype alone,
/// and takes a kernel pointer there only under an `arg:trusted`
/// declaration tag, C's `__arg_trusted`, which Rust cannot express. Every
/// caller passes a task the kernel handed to a callback, so each such
/// parameter gets the tag.
unsafe fn trusted_arguments(btf: *const libbpf_sys::btf) -> Vec<(i32, i32)> {
    let mut arguments = Vec::new();
    unsafe {
        for id in 1..libbpf_sys::btf__type_cnt(btf) {
            let function = libbpf_sys::btf__type_by_id(btf, id);
            if (*function).info >> 24 & 0x1f != libbpf_sys::BTF_KIND_FUNC
                || (*function).info & 0xffff != libbpf_sys::BTF_FUNC_GLOBAL
            {
                continue;
            }
            let (kind, prototype) = resolved(btf, (*function).__bindgen_anon_1.type_);
            if kind != libbpf_sys::BTF_KIND_FUNC_PROTO {
                continue;
            }
            let parameters = std::slice::from_raw_parts(
                prototype.add(1).cast::<libbpf_sys::btf_param>(),
                ((*prototype).info & 0xffff) as usize,
            );
            for (index, parameter) in parameters.iter().enumerate() {
                let (kind, pointer) = resolved(btf, parameter.type_);
                if kind != libbpf_sys::BTF_KIND_PTR {
                    continue;
                }
                let (kind, target) = resolved(btf, (*pointer).__bindgen_anon_1.type_);
                if kind == libbpf_sys::BTF_KIND_STRUCT
                    && std::ffi::CStr::from_ptr(libbpf_sys::btf__name_by_offset(
                        btf,
                        (*target).name_off,
                    )) == c"task_struct"
                {
                    arguments.push((id as i32, index as i32));
                }
            }
        }
    }
    arguments
}

fn checked(result: i32) -> i32 {
    assert!(result >= 0, "BTF operation failed: {result}");
    result
}

/// Add to the BTF of `object` what the Rust toolchain does not emit: the
/// kfuncs' prototypes and `.ksyms` entries, the ksym variables, and the
/// `arg:trusted` tags, and replace the object's `.BTF` section with it.
fn add_btf(spec: &Spec, object: &std::path::Path, output: &std::path::Path, sized_topology: bool) {
    let path = CString::new(object.as_os_str().as_encoded_bytes()).unwrap();
    // libbpf refuses an object whose BTF declares an extern the code never
    // references, and a scheduler uses only part of the runtime: declare
    // the kfuncs and kernel variables its object has undefined symbols for.
    let referenced = undefined_symbols(object);
    unsafe {
        let btf = libbpf_sys::btf__parse_elf(path.as_ptr(), std::ptr::null_mut());
        assert!(!btf.is_null(), "parse Rust BPF BTF");
        let task = checked(libbpf_sys::btf__find_by_name_kind(
            btf,
            c"task_struct".as_ptr(),
            libbpf_sys::BTF_KIND_STRUCT,
        ));
        let task_pointer = checked(libbpf_sys::btf__add_ptr(btf, task));
        let cpumask = checked(libbpf_sys::btf__add_struct(btf, c"cpumask".as_ptr(), 1024));
        let cpumask_pointer = checked(libbpf_sys::btf__add_ptr(btf, cpumask));
        let integer = checked(libbpf_sys::btf__find_by_name_kind(
            btf,
            c"u64".as_ptr(),
            libbpf_sys::BTF_KIND_INT,
        ));
        let signed = checked(libbpf_sys::btf__find_by_name_kind(
            btf,
            c"i32".as_ptr(),
            libbpf_sys::BTF_KIND_INT,
        ));
        let topology = checked(libbpf_sys::btf__add_struct(
            btf,
            c"scx_cid_topo".as_ptr(),
            if sized_topology { 40 } else { 32 },
        ));
        for (index, name) in [
            c"core_cid",
            c"core_idx",
            c"llc_cid",
            c"llc_idx",
            c"node_cid",
            c"node_idx",
            c"shard_cid",
            c"shard_idx",
            c"cluster_cid",
            c"cluster_idx",
        ]
        .into_iter()
        .take(if sized_topology { 10 } else { 8 })
        .enumerate()
        {
            checked(libbpf_sys::btf__add_field(
                btf,
                name.as_ptr(),
                signed,
                (index * 32) as u32,
                0,
            ));
        }
        let topology_pointer = checked(libbpf_sys::btf__add_ptr(btf, topology));
        let boolean = checked(libbpf_sys::btf__find_by_name_kind(
            btf,
            c"bool".as_ptr(),
            libbpf_sys::BTF_KIND_INT,
        ));
        let void_pointer = checked(libbpf_sys::btf__add_ptr(btf, 0));
        let unsigned = checked(libbpf_sys::btf__find_by_name_kind(
            btf,
            c"u32".as_ptr(),
            libbpf_sys::BTF_KIND_INT,
        ));
        // The cgroup kfuncs take and return the kernel's struct cgroup,
        // matched by name like task_struct.
        let cgroup = match libbpf_sys::btf__find_by_name_kind(
            btf,
            c"cgroup".as_ptr(),
            libbpf_sys::BTF_KIND_STRUCT,
        ) {
            id if id > 0 => id,
            _ => checked(libbpf_sys::btf__add_struct(btf, c"cgroup".as_ptr(), 0)),
        };
        let cgroup_pointer = checked(libbpf_sys::btf__add_ptr(btf, cgroup));
        // scx_bpf_dump_bstr() takes a format string and an array of u64.
        let byte =
            match libbpf_sys::btf__find_by_name_kind(btf, c"u8".as_ptr(), libbpf_sys::BTF_KIND_INT)
            {
                id if id > 0 => id,
                _ => checked(libbpf_sys::btf__add_int(btf, c"char".as_ptr(), 1, 0)),
            };
        let byte_pointer = checked(libbpf_sys::btf__add_ptr(btf, byte));
        let integer_pointer = checked(libbpf_sys::btf__add_ptr(btf, integer));
        let id = |ty: Ty| match ty {
            Ty::Void => 0,
            Ty::I32 => signed,
            Ty::U32 => unsigned,
            Ty::U64 => integer,
            Ty::Bool => boolean,
            Ty::TaskPtr => task_pointer,
            Ty::VoidPtr => void_pointer,
            Ty::CpumaskPtr => cpumask_pointer,
            Ty::TopoPtr => topology_pointer,
            Ty::CgroupPtr => cgroup_pointer,
            Ty::BytePtr => byte_pointer,
            Ty::U64Ptr => integer_pointer,
        };
        let mut functions = Vec::new();
        for kfunc in spec
            .kfuncs
            .iter()
            .filter(|kfunc| referenced.contains(kfunc.name))
        {
            let prototype = checked(libbpf_sys::btf__add_func_proto(btf, id(kfunc.ret)));
            for (parameter, ty) in kfunc.params {
                let parameter = CString::new(*parameter).unwrap();
                checked(libbpf_sys::btf__add_func_param(
                    btf,
                    parameter.as_ptr(),
                    id(*ty),
                ));
            }
            if kfunc.sized && sized_topology {
                checked(libbpf_sys::btf__add_func_param(
                    btf,
                    c"size".as_ptr(),
                    integer,
                ));
            }
            let name = CString::new(kfunc.name).unwrap();
            functions.push(checked(libbpf_sys::btf__add_func(
                btf,
                name.as_ptr(),
                libbpf_sys::BTF_FUNC_EXTERN,
                prototype,
            )));
        }
        // The per-CPU kernel variables bpf/src/topology.rs reads, typed so
        // that libbpf resolves them through kernel BTF. A struct is
        // compatible with the kernel's by name, whatever its size.
        let domain = checked(libbpf_sys::btf__add_struct(
            btf,
            c"sched_domain".as_ptr(),
            0,
        ));
        let domain_pointer = checked(libbpf_sys::btf__add_ptr(btf, domain));
        let runqueue = checked(libbpf_sys::btf__add_struct(btf, c"rq".as_ptr(), 0));
        let mut variables = Vec::new();
        for (name, kind, size) in spec
            .ksyms
            .iter()
            .copied()
            .filter(|(name, _, _)| referenced.contains(name.to_str().unwrap()))
        {
            let kind = match kind {
                KSYM_DOMAIN_POINTER => domain_pointer,
                KSYM_RQ => runqueue,
                _ => signed,
            };
            variables.push((
                checked(libbpf_sys::btf__add_var(
                    btf,
                    name.as_ptr(),
                    libbpf_sys::BTF_VAR_GLOBAL_EXTERN as i32,
                    kind,
                )),
                size,
            ));
        }
        checked(libbpf_sys::btf__add_datasec(btf, c".ksyms".as_ptr(), 0));
        for function in functions {
            checked(libbpf_sys::btf__add_datasec_var_info(btf, function, 0, 0));
        }
        for (variable, size) in variables {
            checked(libbpf_sys::btf__add_datasec_var_info(
                btf, variable, 0, size,
            ));
        }
        for (function, argument) in trusted_arguments(btf) {
            checked(libbpf_sys::btf__add_decl_tag(
                btf,
                c"arg:trusted".as_ptr(),
                function,
                argument,
            ));
        }
        let mut size = 0;
        let data = libbpf_sys::btf__raw_data(btf, &mut size);
        assert!(!data.is_null(), "serialize BTF");
        fs::write(
            output,
            std::slice::from_raw_parts(data.cast::<u8>(), size as usize),
        )
        .expect("write kfunc BTF");
        libbpf_sys::btf__free(btf);
    }
    let status = Command::new("llvm-objcopy")
        .args(
            spec.ksyms
                .iter()
                .map(|(name, _, _)| name.to_str().unwrap())
                .chain(
                    spec.kfuncs
                        .iter()
                        .filter(|kfunc| kfunc.weak)
                        .map(|kfunc| kfunc.name),
                )
                .map(|name| format!("--weaken-symbol={name}")),
        )
        .arg("--update-section")
        .arg(format!(".BTF={}", output.display()))
        .arg(object)
        .status()
        .expect("run llvm-objcopy to update BTF");
    assert!(status.success(), "update Rust BPF BTF");
}

/// Whether `program` runs with `args`.
fn runs(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// What the Rust BPF build needs that this host lacks: the toolchain with
/// rust-src, bpf-linker and llvm-objcopy.
fn missing_tools(toolchain: &Option<String>) -> Vec<String> {
    let mut missing = Vec::new();
    let sysroot = match toolchain {
        Some(toolchain) => Command::new("rustup")
            .args(["run", toolchain, "rustc", "--print", "sysroot"])
            .output(),
        None => Command::new("rustc").args(["--print", "sysroot"]).output(),
    };
    match sysroot {
        Ok(output) if output.status.success() => {
            let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
            if !sysroot.join("lib/rustlib/src/rust/library/core").is_dir() {
                missing.push("rust-src".into());
            }
        }
        _ => missing.push(format!(
            "the {} toolchain",
            toolchain.as_deref().unwrap_or("Rust")
        )),
    }
    for tool in ["bpf-linker", "llvm-objcopy", "llvm-nm"] {
        if !runs(tool, &["--version"]) {
            missing.push(tool.into());
        }
    }
    missing
}

/// Build the BPF crate of `spec` for each of its variants, with the
/// toolchain that builds the scheduler or the rustup toolchain
/// BPF_RUST_TOOLCHAIN names, and patch each object's BTF.
pub fn build(spec: &Spec) {
    let bpf = std::path::Path::new(spec.manifest).parent().unwrap();
    println!("cargo:rerun-if-changed={}", spec.manifest);
    println!(
        "cargo:rerun-if-changed={}",
        bpf.join("Cargo.lock").display()
    );
    println!("cargo:rerun-if-changed={}", bpf.join("src").display());
    // The loader's source: opts!() declares the tunables from its options.
    if let Some(scheduler) = bpf.parent() {
        println!("cargo:rerun-if-changed={}", scheduler.join("src").display());
    }
    println!("cargo:rerun-if-changed={}", spec.catalog);
    // The BPF crate's own build tracks the runtime it depends on, but
    // cargo runs this script, and so that build, only when a path named
    // here changes.
    for runtime in ["scx_rustsched", "scx_rustsched_abi", "scx_rustsched_macros"] {
        let runtime = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(runtime);
        for path in ["Cargo.toml", "src"] {
            println!("cargo:rerun-if-changed={}", runtime.join(path).display());
        }
    }
    println!("cargo:rerun-if-env-changed=BPF_RUST_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=PATH");
    // The toolchain that builds the scheduler builds its BPF side too, with
    // the unstable features enabled. It needs rust-src, and an LLVM that
    // bpf-linker can read the bitcode of: the same one, as a distribution
    // builds both against. BPF_RUST_TOOLCHAIN names a rustup toolchain to
    // use instead.
    let toolchain = env::var("BPF_RUST_TOOLCHAIN").ok();
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // A workspace build on a host without the Rust BPF toolchain, CI's
    // among them, still builds: the objects are left empty, and the
    // scheduler refuses to start.
    let missing = missing_tools(&toolchain);
    if !missing.is_empty() {
        println!(
            "cargo:warning={}: no Rust BPF toolchain ({} missing), \
             building a binary that cannot load the scheduler",
            spec.package,
            missing.join(", ")
        );
        for (variant, _) in spec.variants {
            fs::write(output.join(format!("scheduler-{variant}.bpf.o")), [])
                .expect("write empty BPF object");
        }
        return;
    }
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").unwrap().as_str() {
        "little" => "bpfel-unknown-none",
        "big" => "bpfeb-unknown-none",
        other => panic!("unsupported endianness: {other}"),
    };
    for (variant, sized_topology) in spec.variants.iter().copied() {
        let mut command = match &toolchain {
            Some(toolchain) => {
                let mut command = Command::new("rustup");
                command.args(["run", toolchain, "cargo"]);
                command
            }
            None => Command::new(env::var_os("CARGO").unwrap_or("cargo".into())),
        };
        // build-std, BPF inline assembly and the atomic intrinsics are
        // unstable, which a stable compiler allows with this.
        command
            .env("RUSTC_BOOTSTRAP", "1")
            .args(["build", "--release", "--locked"])
            .args(["--manifest-path", spec.manifest, "--target", target])
            .args(["-Z", "build-std=core"])
            .arg("--target-dir")
            .arg(output.join("bpf-target"))
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env(
                "RUSTFLAGS",
                format!(
                    "-C target-cpu=v3 -C debuginfo=2 -C link-arg=--btf -C link-arg=--export={}",
                    spec.kfuncs
                        .iter()
                        .map(|kfunc| kfunc.name)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        if sized_topology {
            command.args(["--features", "topo_size"]);
        }
        let status = command
            .status()
            .expect("run the BPF cargo build; install rust-src and bpf-linker");
        assert!(status.success(), "Rust BPF {variant} build failed");
        let object = output.join(format!("scheduler-{variant}.bpf.o"));
        fs::copy(
            output
                .join("bpf-target")
                .join(target)
                .join("release")
                .join(spec.crate_name),
            &object,
        )
        .expect("copy Rust BPF object");
        add_btf(
            spec,
            &object,
            &output.join(format!("scheduler-{variant}.btf")),
            sized_topology,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function `name` of `linkage` taking `parameters`, in `btf`.
    unsafe fn function(
        btf: *mut libbpf_sys::btf,
        name: &std::ffi::CStr,
        linkage: u32,
        parameters: &[i32],
    ) -> i32 {
        unsafe {
            let prototype = checked(libbpf_sys::btf__add_func_proto(btf, 0));
            for parameter in parameters {
                checked(libbpf_sys::btf__add_func_param(
                    btf,
                    c"p".as_ptr(),
                    *parameter,
                ));
            }
            checked(libbpf_sys::btf__add_func(
                btf,
                name.as_ptr(),
                linkage,
                prototype,
            ))
        }
    }

    #[test]
    fn task_parameters_of_global_functions_are_trusted() {
        unsafe {
            let btf = libbpf_sys::btf__new_empty();
            assert!(!btf.is_null());
            let int = checked(libbpf_sys::btf__add_int(
                btf,
                c"int".as_ptr(),
                4,
                libbpf_sys::BTF_INT_SIGNED as i32,
            ));
            let task = checked(libbpf_sys::btf__add_struct(btf, c"task_struct".as_ptr(), 0));
            let task_pointer = checked(libbpf_sys::btf__add_ptr(btf, task));
            // A pointer reached through a qualifier and a typedef.
            let constant = checked(libbpf_sys::btf__add_const(btf, task));
            let constant_pointer = checked(libbpf_sys::btf__add_ptr(btf, constant));
            let alias = checked(libbpf_sys::btf__add_typedef(
                btf,
                c"task_ref".as_ptr(),
                constant_pointer,
            ));
            let other = checked(libbpf_sys::btf__add_struct(btf, c"cpumask".as_ptr(), 0));
            let other_pointer = checked(libbpf_sys::btf__add_ptr(btf, other));

            let scan = function(
                btf,
                c"scan",
                libbpf_sys::BTF_FUNC_GLOBAL,
                &[task_pointer, int, alias],
            );
            function(btf, c"local", libbpf_sys::BTF_FUNC_STATIC, &[task_pointer]);
            function(
                btf,
                c"mask",
                libbpf_sys::BTF_FUNC_GLOBAL,
                &[other_pointer, int],
            );

            assert_eq!(trusted_arguments(btf), vec![(scan, 0), (scan, 2)]);
            libbpf_sys::btf__free(btf);
        }
    }
}
