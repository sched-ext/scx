// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;

use scx_utils::BpfBuilder;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct RustLandBuilder {
    inner_builder: BpfBuilder,
}

impl RustLandBuilder {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner_builder: BpfBuilder::new()?,
        })
    }

    fn create_file(&self, file_name: &str, content: &[u8]) {
        let path = Path::new(file_name);

        // Limit file writing to when file contents differ (for caching)
        if let Ok(bytes_there) = fs::read(path) {
            if bytes_there == content {
                return;
            }
        }

        let mut file = File::create(path).expect("Unable to create file");
        file.write_all(content).expect("Unable to write to file");
    }

    pub fn build(&mut self) -> Result<()> {
        // Embed the BPF source files.
        let intf = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/bpf/intf.h"));
        let skel = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets/bpf/main.bpf.c"
        ));
        let bpf = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/bpf.rs"));

        // Generate BPF backend code (C).
        self.create_file("intf.h", intf);
        self.create_file("main.bpf.c", skel);

        self.inner_builder.enable_intf("intf.h", "bpf_intf.rs");
        self.inner_builder.enable_skel("main.bpf.c", "bpf");

        // Generate user-space BPF connector code (Rust).
        self.create_file("src/bpf.rs", bpf);

        // Build the scheduler.
        self.inner_builder.build()
    }
}
