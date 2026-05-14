// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Meta Platforms

use crate::BpfSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::ProgramType;
use std::io::Read;
use std::io::Write;

fn dump_program_stream(
    prog_name: &str,
    stream_name: &str,
    mut stream: impl Read,
    stderr: bool,
) -> std::io::Result<bool> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let body = String::from_utf8_lossy(&buf);
    if body.len() == 0 {
        return Ok(false);
    }

    let stream_label = stream_name.to_ascii_uppercase();
    if stderr {
        eprintln!("\n===BEGIN BPF {stream_label} {prog_name}===");
        eprint!("{body}");
        eprintln!("\n====END BPF {stream_label} {prog_name}====");
        std::io::stderr().flush()?;
    } else {
        println!("\n===BEGIN BPF {stream_label} {prog_name}===");
        print!("{body}");
        println!("\n====END BPF {stream_label} {prog_name}====");
        std::io::stdout().flush()?;
    }

    Ok(!buf.is_empty())
}

pub(crate) fn dump_bpf_streams(skel: &mut BpfSkel<'_>) {
    let mut dumped = false;
    let mut unavailable = false;

    for prog in skel
        .object()
        .progs_mut()
        .filter(|prog| prog.prog_type() == ProgramType::StructOps)
    {
        let prog_name = prog.name().to_string_lossy();

        match dump_program_stream(prog_name.as_ref(), "stdout", prog.stdout(), false) {
            Ok(stream_dumped) => dumped |= stream_dumped,
            Err(_) => unavailable = true,
        }

        match dump_program_stream(prog_name.as_ref(), "stderr", prog.stderr(), true) {
            Ok(stream_dumped) => dumped |= stream_dumped,
            Err(_) => unavailable = true,
        }
    }

    if !dumped && unavailable {
        eprintln!("BPF stream dump unavailable (requires kernel/libbpf support for BPF streams)");
    }
}
