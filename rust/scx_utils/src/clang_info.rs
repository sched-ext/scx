use std::{collections::HashMap, env, process::Command};

use anyhow::{anyhow, bail, Context, Result};
use sscanf::sscanf;

lazy_static::lazy_static! {
    // Map clang archs to the __TARGET_ARCH list in
    // tools/lib/bpf/bpf_tracing.h in the kernel tree.
    static ref ARCH_MAP: HashMap<&'static str, &'static str> = vec![
    ("x86", "x86"),
    ("x86_64", "x86"),
    ("s390", "s390"),
    ("s390x", "s390"),
    ("arm", "arm"),
    ("aarch64", "arm64"),
    ("mips", "mips"),
    ("mips64", "mips"),
    ("ppc32", "powerpc"),
    ("ppc64", "powerpc"),
    ("ppc64le", "powerpc"),
    ("powerpc64le", "powerpc"),
    ("sparc", "sparc"),
    ("sparcv9", "sparc"),
    ("riscv32", "riscv"),
    ("riscv64", "riscv"),
    ("riscv64gc", "riscv"),
    ("arc", "arc"),			// unsure this is supported
    ("loongarch64", "loongarch"),	// ditto
    ].into_iter().collect();
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct ClangInfo {
    pub clang: String,
    pub ver: String,
    pub arch: String,
}

impl ClangInfo {
    pub fn new() -> Result<ClangInfo> {
        let mut clang_args = vec!["--version".to_string()];

        if let Ok(target) = env::var("TARGET") {
            clang_args.push(format!("--target={target}"));
        }

        let clang = env::var("BPF_CLANG").unwrap_or("clang".into());
        let output = Command::new(&clang)
            .args(clang_args)
            .output()
            .with_context(|| format!("Failed to run \"{} --version\"", &clang))?;

        let stdout = String::from_utf8(output.stdout)?;
        let (mut ver, mut arch) = (None, None);
        for line in stdout.lines() {
            if let Ok(v) = sscanf!(
                Self::skip_clang_version_prefix(line),
                "clang version {String}"
            ) {
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

        Ok(ClangInfo { clang, ver, arch })
    }

    fn skip_clang_version_prefix(line: &str) -> &str {
        if let Some(index) = line.find("clang version") {
            &line[index..]
        } else {
            line
        }
    }

    pub fn kernel_target(&self) -> Result<String> {
        // Determine kernel target arch.
        match ARCH_MAP.get(self.arch.as_str()) {
            Some(v) => Ok(v.to_string()),
            None => Err(anyhow!("CPU arch {} not found in ARCH_MAP", self.arch)),
        }
    }

    #[allow(dead_code)] // for it is not used during build script execution
    pub fn determine_base_cflags(&self) -> Result<Vec<String>> {
        let kernel_target = self.kernel_target()?;

        // Determine system includes.
        let output = Command::new(&self.clang)
            .args(["-v", "-E", "-"])
            .output()
            .with_context(|| format!("Failed to run \"{} -v -E - < /dev/null", self.clang))?;
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
            None => bail!("Failed to find system includes from {:?}", self.clang),
        };

        // Determine endian.
        let output = Command::new(&self.clang)
            .args(["-dM", "-E", "-"])
            .output()
            .with_context(|| format!("Failed to run \"{} -dM E - < /dev/null", self.clang))?;
        let stdout = String::from_utf8(output.stdout)?;

        let mut endian = None;
        for line in stdout.lines() {
            if let Ok(v) = sscanf!(line, "#define __BYTE_ORDER__ {str}") {
                endian = Some(match v {
                    "__ORDER_LITTLE_ENDIAN__" => "little",
                    "__ORDER_BIG_ENDIAN__" => "big",
                    v => bail!("Unknown __BYTE_ORDER__ {:?}", v),
                });
                break;
            }
        }
        let endian = match endian {
            Some(v) => v,
            None => bail!("Failed to find __BYTE_ORDER__ from {:?}", self.clang),
        };

        // Assemble cflags.
        let mut cflags: Vec<String> = ["-g", "-O2", "-Wall", "-Wno-compare-distinct-pointer-types"]
            .into_iter()
            .map(|x| x.into())
            .collect();
        cflags.push(format!("-D__TARGET_ARCH_{}", &kernel_target));
        cflags.push("-mcpu=v3".into());
        cflags.push(format!("-m{endian}-endian"));
        cflags.append(
            &mut sys_incls
                .into_iter()
                .flat_map(|x| ["-idirafter".into(), x.into()])
                .collect(),
        );
        Ok(cflags)
    }
}
