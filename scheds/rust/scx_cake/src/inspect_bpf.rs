// SPDX-License-Identifier: GPL-2.0

use anyhow::{Context, Result};
use libbpf_rs::{AsRawLibbpf, libbpf_sys};
use std::fmt::Write;
use std::path::Path;

pub fn dump(object: &libbpf_rs::Object, path: &Path) -> Result<()> {
    std::fs::create_dir(path).context("inspection output must be a new directory")?;
    let mut manifest = String::from("name\tid\ttag\tbpf_bytes\tjit_bytes\tjit_visible\n");
    for prog in object.progs() {
        // Disabled autoload programs have no descriptor.
        let fd = unsafe { libbpf_sys::bpf_program__fd(prog.as_libbpf_object().as_ptr()) };
        if fd < 0 {
            continue;
        }
        let mut sizes = libbpf_sys::bpf_prog_info::default();
        query(fd, &mut sizes)?;
        let mut bpf = vec![0u8; sizes.xlated_prog_len as usize];
        let mut jit = vec![0u8; sizes.jited_prog_len as usize];
        let mut info = libbpf_sys::bpf_prog_info {
            xlated_prog_len: sizes.xlated_prog_len,
            jited_prog_len: sizes.jited_prog_len,
            xlated_prog_insns: bpf.as_mut_ptr() as u64,
            jited_prog_insns: jit.as_mut_ptr() as u64,
            ..Default::default()
        };
        query(fd, &mut info)?;
        let name = prog.name().to_str().context("non-UTF8 BPF name")?;
        anyhow::ensure!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        let bpf_visible = info.xlated_prog_insns != 0 && info.xlated_prog_len != 0;
        let jit_visible = info.jited_prog_insns != 0 && info.jited_prog_len != 0;
        if bpf_visible {
            std::fs::write(
                path.join(format!("{name}.bpf.bin")),
                &bpf[..info.xlated_prog_len as usize],
            )?;
        }
        if jit_visible {
            std::fs::write(
                path.join(format!("{name}.jit.bin")),
                &jit[..info.jited_prog_len as usize],
            )?;
        }
        let tag: String = info.tag.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            manifest,
            "{name}\t{}\t{tag}\t{}\t{}\t{jit_visible}",
            info.id,
            if bpf_visible { info.xlated_prog_len } else { 0 },
            info.jited_prog_len
        )?;
    }
    std::fs::write(path.join("programs.tsv"), manifest)?;
    Ok(())
}

fn query(fd: i32, info: &mut libbpf_sys::bpf_prog_info) -> Result<()> {
    let mut len = std::mem::size_of_val(info) as u32;
    let rc = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd,
            (info as *mut libbpf_sys::bpf_prog_info).cast(),
            &mut len,
        )
    };
    anyhow::ensure!(
        rc == 0,
        "BPF instruction query failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
