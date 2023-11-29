// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use sscanf::sscanf;
use std::env;
use std::path::Path;

const BPF_H_TAR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bpf_h.tar"));

pub fn install_bpf_h<P: AsRef<Path>>(dest: P) -> Result<()> {
    let mut ar = tar::Archive::new(BPF_H_TAR);
    ar.unpack(dest)?;
    Ok(())
}

pub fn vmlinux_h_version() -> (String, String) {
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
