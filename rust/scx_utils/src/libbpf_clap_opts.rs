// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use clap::Parser;
use libbpf_rs::libbpf_sys::bpf_object_open_opts;
use libbpf_rs::libbpf_sys::size_t;

use std::ffi::c_char;
use std::ffi::CString;
use std::mem;

#[derive(Debug, Clone, Parser)]
pub struct LibbpfOpts {
    /// Parse map definitions non-strictly, allowing extra attributes/data.
    #[clap(long)]
    pub relaxed_maps: Option<bool>,

    /// Maps that set the 'pinning' attribute in their definition will have their pin_path
    /// attribute set to a file in this directory, and be auto-pinned to that path on load;
    /// defaults to "/sys/fs/bpf".
    #[clap(long)]
    pub pin_root_path: Option<String>,

    /// Additional kernel config content that augments and overrides system Kconfig for CONFIG_xxx
    /// externs.
    #[clap(long)]
    pub kconfig: Option<String>,

    /// Path to the custom BTF to be used for BPF CO-RE relocations. This custom BTF completely
    /// replaces the use of vmlinux BTF for the purpose of CO-RE relocations. NOTE: any other BPF
    /// feature (e.g., fentry/fexit programs, struct_ops, etc) will need actual kernel BTF at
    /// /sys/kernel/btf/vmlinux.
    #[clap(long)]
    pub btf_custom_path: Option<String>,

    /// Path to BPF FS mount point to derive BPF token from. Created BPF token will be used for
    /// all bpf() syscall operations that accept BPF token (e.g., map creation, BTF and program
    /// loads, etc) automatically within instantiated BPF object. If bpf_token_path is not
    /// specified, libbpf will consult LIBBPF_BPF_TOKEN_PATH environment variable. If set, it will
    /// be taken as a value of bpf_token_path option and will force libbpf to either create BPF
    /// token from provided custom BPF FS path, or will disable implicit BPF token creation, if
    /// envvar value is an empty string. bpf_token_path overrides LIBBPF_BPF_TOKEN_PATH, if both
    /// are set at the same time. Setting bpf_token_path option to empty string disables libbpf's
    /// automatic attempt to create BPF token from default BPF FS mount point (/sys/fs/bpf), in
    /// case this default behavior is undesirable.
    #[clap(long)]
    pub bpf_token_path: Option<String>,
}

impl Default for LibbpfOpts {
    fn default() -> Self {
        Self {
            relaxed_maps: None,
            pin_root_path: None,
            kconfig: None,
            btf_custom_path: None,
            bpf_token_path: None,
        }
    }
}

impl LibbpfOpts {
    /// Helper method to convert `LibbpfOpts` into an `Option<bpf_object_open_opts>`.
    ///
    /// Returns `Some(bpf_object_open_opts)` if any field in `LibbpfOpts` is set,
    /// otherwise returns `None`.
    pub fn into_bpf_open_opts(self) -> Option<bpf_object_open_opts> {
        if self.relaxed_maps.is_some()
            || self.pin_root_path.is_some()
            || self.kconfig.is_some()
            || self.btf_custom_path.is_some()
            || self.bpf_token_path.is_some()
        {
            let mut opts: bpf_object_open_opts = unsafe { mem::zeroed() };
            opts.sz = mem::size_of::<bpf_object_open_opts>() as size_t;

            if let Some(relaxed) = self.relaxed_maps {
                opts.relaxed_maps = relaxed;
            }

            // Using CString to ensure the strings are null-terminated.
            // The Box::into_raw() converts the CString into a raw C-style pointer.
            if let Some(pin_path) = self.pin_root_path {
                let c_string = CString::new(pin_path).ok()?;
                let boxed = c_string.into_boxed_c_str();
                opts.pin_root_path = Box::into_raw(boxed) as *const c_char;
            }

            if let Some(kconfig_str) = self.kconfig {
                let file_data = std::fs::read_to_string(kconfig_str).ok()?;
                let c_string = CString::new(file_data).ok()?;
                let boxed = c_string.into_boxed_c_str();
                opts.kconfig = Box::into_raw(boxed) as *const c_char;
            }

            if let Some(btf_path) = self.btf_custom_path {
                let c_string = CString::new(btf_path).ok()?;
                let boxed = c_string.into_boxed_c_str();
                opts.btf_custom_path = Box::into_raw(boxed) as *const c_char;
            }

            if let Some(token_path) = self.bpf_token_path {
                let c_string = CString::new(token_path).ok()?;
                let boxed = c_string.into_boxed_c_str();
                opts.bpf_token_path = Box::into_raw(boxed) as *const c_char;
            }

            Some(opts)
        } else {
            None
        }
    }
}
