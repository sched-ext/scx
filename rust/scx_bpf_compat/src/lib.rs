// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;

use crate::bpf_skel::BpfSkelBuilder;

use std::mem::MaybeUninit;

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::ProgramType;
use once_cell::sync::OnceCell;
use scx_utils::compat::ksym_exists;

/// Check if kernel supports calling kfuncs from SYSCALL programs.
/// This was introduced in kernel commit a8e03b6bbb2c
/// "bpf: Allow invoking kfuncs from BPF_PROG_TYPE_SYSCALL progs"
pub fn kfuncs_supported_in_syscall() -> Result<bool> {
    static MEMO: OnceCell<bool> = OnceCell::new();

    MEMO.get_or_try_init(|| {
        if !ProgramType::Syscall.is_supported()? {
            return Ok(false);
        }
        if !ksym_exists("bpf_cpumask_create")? {
            return Ok(false);
        }
        if !ksym_exists("bpf_cpumask_release")? {
            return Ok(false);
        }

        let skel_builder = BpfSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();

        let mut open_skel = skel_builder.open(&mut open_object)?;
        for mut prog in open_skel.open_object_mut().progs_mut() {
            prog.set_autoload(prog.name() == "kfuncs_test_syscall");
        }

        let ret = match open_skel.load() {
            Ok(_) => true,
            Err(e) => {
                log::trace!("rejecting program for `kfuncs_supported_in_syscall` with error: {e}");
                false
            }
        };

        Ok(ret)
    })
    .copied()
}
