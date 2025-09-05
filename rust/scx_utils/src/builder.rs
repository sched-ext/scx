// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::{
    fs,
    path::PathBuf,
};

include!("clang_info.rs");

pub struct Builder;

impl Builder {
    pub fn new() -> Self {
        Builder
    }

    fn create_temp_vmlinux(&self, out_dir: &str, target: &str) -> PathBuf {
        let temp_vmlinux_dir = PathBuf::from(out_dir).join("temp_vmlinux");
        fs::create_dir_all(&temp_vmlinux_dir).unwrap();
        
        let arch_dir = temp_vmlinux_dir.join("arch").join(target);
        fs::create_dir_all(&arch_dir).unwrap();
        
        // Get vmlinux data for the target architecture
        let vmlinux_data = match target {
            "aarch64" => scx_vmlinux_aarch64::VMLINUX_H,
            "arm" => scx_vmlinux_arm::VMLINUX_H,
            "mips" => scx_vmlinux_mips::VMLINUX_H,
            "powerpc" => scx_vmlinux_powerpc::VMLINUX_H,
            "riscv" => scx_vmlinux_riscv::VMLINUX_H,
            "s390" => scx_vmlinux_s390::VMLINUX_H,
            "x86" => scx_vmlinux_x86::VMLINUX_H,
            _ => panic!("Unsupported target architecture: {}", target),
        };
        
        let vmlinux_h_path = arch_dir.join("vmlinux.h");
        fs::write(&vmlinux_h_path, vmlinux_data).unwrap();
        
        vmlinux_h_path
    }

    fn gen_bindings(&self) {
        let out_dir = env::var("OUT_DIR").unwrap();
        let clang = ClangInfo::new().unwrap();
        let kernel_target = clang.kernel_target().unwrap();
        
        let vmlinux_h_path = self.create_temp_vmlinux(&out_dir, &kernel_target);
        
        let bindings = bindgen::Builder::default()
            .header(vmlinux_h_path.to_str().unwrap())
            .allowlist_type("scx_exit_kind")
            .allowlist_type("scx_consts")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(PathBuf::from(&out_dir).join("bindings.rs"))
            .expect("Couldn't write bindings");
    }

    pub fn build(self) {
        self.gen_bindings();
    }
}
