// Copyright (c) 2026 NVIDIA Corporation.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::env;
use std::process::Command;

use anyhow::{bail, Result};

const MIN_PAHOLE_VERSION: &str = "1.26";
const SKIP_ENV: &str = "SCX_SKIP_PAHOLE_CHECK";

/// Verify that pahole on the build host is recent enough to produce correct BTF for kfuncs
/// annotated with KF_IMPLICIT_ARGS (e.g., scx_bpf_cpu_rq).
///
/// pahole < 1.26 omits the DECL_TAG entries for __bpf_kfunc functions that resolve_btfids needs in
/// order to split a kfunc into its public-facing prototype (without implicit args) and the matching
/// `_impl` variant (with the full prototype). Without that split, the visible BTF prototype keeps
/// the implicit argument and libbpf rejects the BPF program with:
///
///   libbpf: extern (func ksym) 'scx_bpf_cpu_rq': func_proto [N] incompatible with vmlinux [M]
///
/// This affects e.g. Ubuntu 24.04 LTS (pahole 1.25). See kernel commit 9edd04c4189e ("docs: Raise
/// minimum pahole version to 1.26 for KF_IMPLICIT_ARGS kfuncs").
///
/// Set SCX_SKIP_PAHOLE_CHECK=1 to skip this check (useful when the running kernel was built on a
/// different machine with a newer pahole).
pub fn check() -> Result<()> {
    println!("cargo:rerun-if-env-changed={SKIP_ENV}");

    if env::var_os(SKIP_ENV).is_some() {
        return Ok(());
    }

    let output = match Command::new("pahole").arg("--version").output() {
        Ok(o) => o,
        // pahole isn't installed: it can't have built the running kernel
        // with a too-old version. Skip silently.
        Err(_) => return Ok(()),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let raw = stdout.lines().next().unwrap_or("").trim();
    let ver = raw
        .trim_start_matches('v')
        .split_whitespace()
        .next()
        .unwrap_or("");

    if ver.is_empty() || !ver.chars().next().unwrap().is_ascii_digit() {
        println!("cargo:warning=could not parse pahole version: {raw:?}");
        return Ok(());
    }

    if version_compare::compare(ver, MIN_PAHOLE_VERSION) == Ok(version_compare::Cmp::Lt) {
        bail!(
            "pahole >= {MIN_PAHOLE_VERSION} required (found {ver}).\n\
             \n\
             pahole < 1.26 generates incorrect BTF for kfuncs annotated with\n\
             KF_IMPLICIT_ARGS (e.g. scx_bpf_cpu_rq), which causes BPF programs\n\
             to fail to load with 'func_proto incompatible with vmlinux'.\n\
             \n\
             Affected distros include Ubuntu 24.04 LTS. See kernel commit\n\
             9edd04c4189e (\"docs: Raise minimum pahole version to 1.26 for\n\
             KF_IMPLICIT_ARGS kfuncs\") for details.\n\
             \n\
             Fix: upgrade pahole and rebuild the kernel, or set\n\
             {SKIP_ENV}=1 if the running kernel was built elsewhere with a\n\
             newer pahole."
        );
    }

    Ok(())
}
