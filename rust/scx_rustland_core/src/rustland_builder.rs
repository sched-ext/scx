// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;

use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use scx_utils::BpfBuilder;

pub struct RustLandBuilder {
    inner_builder: BpfBuilder,
    temp_dir: tempfile::TempDir,
}

impl RustLandBuilder {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner_builder: BpfBuilder::new()?,
            temp_dir: tempdir()?,
        })
    }

    fn create_temp_file(
        &mut self,
        file_name: &str,
        content: &[u8],
    ) -> Result<PathBuf, Box<dyn Error>> {
        let mut temp_file = self.temp_dir.as_ref().to_path_buf();
        temp_file.push(file_name);
        let mut file = File::create(&temp_file)?;
        file.write_all(content)?;

        Ok(temp_file)
    }

    fn get_bpf_rs_content(&self) -> &'static str {
        include_str!("bpf.rs")
    }

    pub fn build(&mut self) -> Result<()> {
        // Embed the BPF source files in the crate.
        let intf = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/intf.h"));
        let skel = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/main.bpf.c"));

        let intf_path = self.create_temp_file("intf.h", intf).unwrap();
        let skel_path = self.create_temp_file("main.bpf.c", skel).unwrap();

        self.inner_builder
            .enable_intf(intf_path.to_str().unwrap(), "bpf_intf.rs");
        self.inner_builder
            .enable_skel(skel_path.to_str().unwrap(), "bpf");

        let content = self.get_bpf_rs_content();
        let path = Path::new("src/bpf.rs");
        let mut file = File::create(&path).expect("Unable to create file");
        file.write_all(content.as_bytes()).expect("Unable to write to file");

        self.inner_builder.build()
    }
}
