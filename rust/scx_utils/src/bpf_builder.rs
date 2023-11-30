// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use sscanf::sscanf;
use std::collections::BTreeSet;
use std::env;
use std::path::Path;
use std::path::PathBuf;

const BPF_H_TAR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bpf_h.tar"));

fn install_bpf_h<P: AsRef<Path>>(dest: P) -> Result<()> {
    let mut ar = tar::Archive::new(BPF_H_TAR);
    ar.unpack(dest)?;
    Ok(())
}

fn vmlinux_h_version() -> (String, String) {
    let mut ar = tar::Archive::new(BPF_H_TAR);

    for file in ar.entries().unwrap() {
        let file = file.unwrap();
        if file.header().path().unwrap() != Path::new("vmlinux/vmlinux.h") {
            continue;
        }

        let name = file
            .link_name()
            .unwrap()
            .unwrap()
            .to_string_lossy()
            .to_string();

        return sscanf!(name, "vmlinux-v{String}-g{String}.h").unwrap();
    }

    panic!("vmlinux/vmlinux.h not found");
}

pub struct BpfBuilder {
    clang: String,
    cflags: String,
    out_dir: PathBuf,

    intf_input_output: Option<(String, String)>,
    skel_input_name: Option<(String, String)>,
    skel_deps: Option<Vec<String>>,
}

impl BpfBuilder {
    pub fn new() -> Result<Self> {
        Ok(Self {
            clang: env::var("BPF_CLANG")?,
            cflags: env::var("BPF_CFLAGS")?,
            out_dir: PathBuf::from(env::var("OUT_DIR")?),

            intf_input_output: None,
            skel_input_name: None,
            skel_deps: None,
        })
    }

    pub fn enable_intf(&mut self, input: &str, output: &str) -> &mut Self {
        self.intf_input_output = Some((input.into(), output.into()));
        self
    }

    pub fn enable_skel(&mut self, input: &str, name: &str) -> &mut Self {
        self.skel_input_name = Some((input.into(), name.into()));
        self
    }

    pub fn set_skel_deps<'a, I>(&mut self, deps: I) -> &mut Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.skel_deps = Some(deps.into_iter().map(|d| d.to_string()).collect());
        self
    }

    fn bindgen_bpf_intf(&self, deps: &mut BTreeSet<String>) -> Result<()> {
        let (input, output) = match &self.intf_input_output {
            Some(pair) => pair,
            None => return Ok(()),
        };

        // Tell cargo to invalidate the built crate whenever the wrapper changes
        deps.insert(input.to_string());

        // The bindgen::Builder is the main entry point to bindgen, and lets
        // you build up options for the resulting bindings.
        let bindings = bindgen::Builder::default()
            // Should run clang with the same -I options as BPF compilation.
            .clang_args(self.cflags.split_whitespace())
            // The input header we would like to generate bindings for.
            .header(input)
            // Tell cargo to invalidate the built crate whenever any of the
            // included header files changed.
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .context("Unable to generate bindings")?;

        bindings
            .write_to_file(self.out_dir.join(output))
            .context("Couldn't write bindings")
    }

    fn gen_bpf_skel(&self, deps: &mut BTreeSet<String>) -> Result<()> {
	let (input, name) = match &self.skel_input_name {
	    Some(pair) => pair,
	    None => return Ok(()),
	};

        let obj = self.out_dir.join(format!("{}.bpf.o", name));
        let skel_path = self.out_dir.join(format!("{}_skel.rs", name));

        SkeletonBuilder::new()
            .source(input)
            .obj(&obj)
            .clang(&self.clang)
            .clang_args(&self.cflags)
            .build_and_generate(&skel_path)?;

        match &self.skel_deps {
            Some(skel_deps) => {
                for path in skel_deps {
                    deps.insert(path.to_string());
                }
            }
            None => {
                let c_path = PathBuf::from(input);
                let dir = c_path
                    .parent()
                    .ok_or(anyhow!("Source {:?} doesn't have parent dir", c_path))?
                    .to_str()
                    .ok_or(anyhow!("Parent dir of {:?} isn't a UTF-8 string", c_path))?;

                for path in glob(&format!("{}/*.[hc]", dir))?.filter_map(Result::ok) {
                    deps.insert(
                        path.to_str()
                            .ok_or(anyhow!("Path {:?} is not a valid string", path))?
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }

    pub fn build(&self) -> Result<()> {
        let mut deps = BTreeSet::new();

        self.bindgen_bpf_intf(&mut deps)?;
        self.gen_bpf_skel(&mut deps)?;

        for dep in deps.iter() {
            println!("cargo:rerun-if-changed={}", dep);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;

    #[test]
    fn test_install_bpf_h() {
        let dir = concat!(env!("OUT_DIR"), "/test_install_bpf_h");
        super::install_bpf_h(dir).unwrap();

        let vmlinux_h = File::open(format!("{}/vmlinux/vmlinux.h", dir)).unwrap();
        assert_eq!(
            BufReader::new(vmlinux_h).lines().next().unwrap().unwrap(),
            "#ifndef __VMLINUX_H__"
        );
    }

    #[test]
    fn test_vmlinux_h_version() {
        let (ver, sha1) = super::vmlinux_h_version();

        println!("test_vmlinux_h_version: ver={:?} sha1={:?}", &ver, &sha1,);

        assert!(
            regex::Regex::new(r"^[1-9][0-9]*\.[1-9][0-9]*(\.[1-9][0-9]*)?$")
                .unwrap()
                .is_match(&ver)
        );
        assert!(regex::Regex::new(r"^[0-9a-z]{12}$")
            .unwrap()
            .is_match(&sha1));
    }
}
