// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use sscanf::sscanf;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

lazy_static::lazy_static! {
    // Map clang archs to the __TARGET_ARCH list in
    // tools/lib/bpf/bpf_tracing.h in the kernel tree.
    static ref ARCH_MAP: HashMap<&'static str, &'static str> = vec![
    ("x86", "x86"),
    ("x86_64", "x86"),
    ("s390", "s390"),
    ("arm", "arm"),
    ("aarch64", "arm64"),
    ("mips", "mips"),
    ("mips64", "mips"),
    ("ppc32", "powerpc"),
    ("ppc64", "powerpc"),
    ("sparc", "sparc"),
    ("sparcv9", "sparc"),
    ("riscv32", "riscv"),
    ("riscv64", "riscv"),
    ("arc", "arc"),			// unsure this is supported
    ("loongarch64", "loongarch"),	// ditto
    ].into_iter().collect();
}

#[derive(Debug)]
pub struct BpfBuilder {
    clang: (String, String, String), // (clang, ver, arch)
    cflags: Vec<String>,
    out_dir: PathBuf,

    intf_input_output: Option<(String, String)>,
    skel_input_name: Option<(String, String)>,
    skel_deps: Option<Vec<String>>,
}

impl BpfBuilder {
    fn find_clang() -> Result<(String, String, String)> {
        let clang = env::var("BPF_CLANG").unwrap_or("clang".into());
        let output = Command::new(&clang)
            .args(["--version"])
            .output()
            .with_context(|| format!("Failed to run \"{} --version\"", &clang))?;

        let stdout = String::from_utf8(output.stdout)?;
        let (mut ver, mut arch) = (None, None);
        for line in stdout.lines() {
            if let Ok(v) = sscanf!(line, "clang version {String}") {
                // Version could be followed by (URL SHA1). Only take
                // the first word.
                ver = Some(v.split_whitespace().next().unwrap().to_string());
                continue;
            }
            if let Ok(v) = sscanf!(line, "Target: {String}") {
                arch = Some(v.split('-').next().unwrap().to_string());
                continue;
            }
        }

        let (ver, arch) = (
            ver.ok_or(anyhow!("Failed to read clang version"))?,
            arch.ok_or(anyhow!("Failed to read clang target arch"))?,
        );

        if version_compare::compare(&ver, "16") == Ok(version_compare::Cmp::Lt) {
            bail!(
                "clang < 16 loses high 32 bits of 64 bit enums when compiling BPF ({:?} ver={:?})",
                &clang,
                &ver
            );
        }
        if version_compare::compare(&ver, "17") == Ok(version_compare::Cmp::Lt) {
            println!(
                "cargo:warning=clang >= 17 recommended ({:?} ver={:?})",
                &clang, &ver
            );
        }

        Ok((clang, ver, arch))
    }

    fn determine_base_cflags(
        (clang, _ver, arch): &(String, String, String),
    ) -> Result<Vec<String>> {
        // Determine kernel target arch.
        let kernel_target = match ARCH_MAP.get(arch.as_str()) {
            Some(v) => v,
            None => bail!("CPU arch {:?} not found in ARCH_MAP", &arch),
        };

        // Determine system includes.
        let output = Command::new(&clang)
            .args(["-v", "-E", "-"])
            .output()
            .with_context(|| format!("Failed to run \"{} -v -E - < /dev/null", &clang))?;
        let stderr = String::from_utf8(output.stderr)?;

        let mut sys_incls = None;
        for line in stderr.lines() {
            if line == "#include <...> search starts here:" {
                sys_incls = Some(vec![]);
                continue;
            }
            if sys_incls.is_none() {
                continue;
            }
            if line == "End of search list." {
                break;
            }

            sys_incls.as_mut().unwrap().push(line.trim());
        }
        let sys_incls = match sys_incls {
            Some(v) => v,
            None => bail!("Failed to find system includes from {:?}", &clang),
        };

        // Determine endian.
        let output = Command::new(&clang)
            .args(["-dM", "-E", "-"])
            .output()
            .with_context(|| format!("Failed to run \"{} -dM E - < /dev/null", &clang))?;
        let stdout = String::from_utf8(output.stdout)?;

        let mut endian = None;
        for line in stdout.lines() {
            match sscanf!(line, "#define __BYTE_ORDER__ {str}") {
                Ok(v) => {
                    endian = Some(match v {
                        "__ORDER_LITTLE_ENDIAN__" => "little",
                        "__ORDER_BIG_ENDIAN__" => "big",
                        v => bail!("Unknown __BYTE_ORDER__ {:?}", v),
                    });
                    break;
                }
                _ => {}
            }
        }
        let endian = match endian {
            Some(v) => v,
            None => bail!("Failed to find __BYTE_ORDER__ from {:?}", &clang),
        };

        // Assemble cflags.
        let mut cflags: Vec<String> =
            ["-g", "-O2", "-Wall", "-Wno-compare-distinct-pointer-types'"]
                .into_iter()
                .map(|x| x.into())
                .collect();
        cflags.push(format!("-D__TARGET_ARCH_{}", &kernel_target));
        cflags.push("-mcpu=v3".into());
        cflags.push(format!("-m{}-endian", endian));
        cflags.append(
            &mut sys_incls
                .into_iter()
                .flat_map(|x| ["-idirafter".into(), x.into()])
                .collect(),
        );
        Ok(cflags)
    }

    const BPF_H_TAR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bpf_h.tar"));

    fn install_bpf_h<P: AsRef<Path>>(dest: P) -> Result<()> {
        let mut ar = tar::Archive::new(Self::BPF_H_TAR);
        ar.unpack(dest)?;
        Ok(())
    }

    pub fn vmlinux_h_version() -> (String, String) {
        let mut ar = tar::Archive::new(Self::BPF_H_TAR);

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

    fn determine_cflags<P>(clang: &(String, String, String), out_dir: P) -> Result<Vec<String>>
    where
        P: AsRef<Path> + std::fmt::Debug,
    {
        let bpf_h = out_dir
            .as_ref()
            .join("scx_utils-bpf_h")
            .to_str()
            .ok_or(anyhow!(
                "{:?}/scx_utils-bph_h can't be converted to str",
                &out_dir
            ))?
            .to_string();
        Self::install_bpf_h(&bpf_h)?;

        let mut cflags = Vec::<String>::new();

        cflags.append(&mut match env::var("BPF_BASE_CFLAGS") {
            Ok(v) => v.split_whitespace().map(|x| x.into()).collect(),
            _ => Self::determine_base_cflags(&clang)?,
        });

        cflags.append(&mut match env::var("BPF_EXTRA_CFLAGS_PRE_INCL") {
            Ok(v) => v.split_whitespace().map(|x| x.into()).collect(),
            _ => vec![],
        });

        cflags.push(format!("-I{}/vmlinux", &bpf_h));
        cflags.push(format!("-I{}/common", &bpf_h));
        cflags.push(format!("-I{}/bpf-compat", &bpf_h));

        cflags.append(&mut match env::var("BPF_EXTRA_CFLAGS_POST_INCL") {
            Ok(v) => v.split_whitespace().map(|x| x.into()).collect(),
            _ => vec![],
        });

        Ok(cflags)
    }

    pub fn new() -> Result<Self> {
        let out_dir = PathBuf::from(env::var("OUT_DIR")?);

        let clang = Self::find_clang()?;
        let cflags = match env::var("BPF_CFLAGS") {
            Ok(v) => v.split_whitespace().map(|x| x.into()).collect(),
            _ => Self::determine_cflags(&clang, &out_dir)?,
        };

        println!("scx_utils:clang={:?} {:?}", &clang, &cflags);

        Ok(Self {
            clang,
            cflags,
            out_dir,

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

    fn cflags_string(&self) -> String {
        self.cflags
            .iter()
            .map(|x| x.as_str())
            .collect::<Vec<&str>>()
            .join(" ")
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
            .clang_args(
                self.cflags
                    .iter()
                    .chain(["-target".into(), "bpf".into()].iter()),
            )
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
            .clang(&self.clang.0)
            .clang_args(self.cflags_string())
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

        println!("cargo:rerun-if-env-changed=BPF_CLANG");
        println!("cargo:rerun-if-env-changed=BPF_CFLAGS");
        println!("cargo:rerun-if-env-changed=BPF_BASE_CFLAGS");
        println!("cargo:rerun-if-env-changed=BPF_EXTRA_CFLAGS_PRE_INCL");
        println!("cargo:rerun-if-env-changed=BPF_EXTRA_CFLAGS_POST_INCL");
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
    fn test_bpf_builder_new() {
        let res = super::BpfBuilder::new();
        assert!(res.is_ok(), "Failed to create BpfBuilder ({:?})", &res);
    }

    #[test]
    fn test_vmlinux_h_version() {
        let (ver, sha1) = super::BpfBuilder::vmlinux_h_version();

        println!("vmlinux.h: ver={:?} sha1={:?}", &ver, &sha1,);

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
