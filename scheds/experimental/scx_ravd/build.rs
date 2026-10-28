// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

use std::{env, fs, path::Path};

fn main() {
    scx_rustsched_build::build_default();
    refuse_unloadable(Path::new(
        &env::var("OUT_DIR").expect("run from a build script"),
    ));
}

/// Fail the build on an object the kernel or libbpf would refuse before
/// the verifier sees it, rather than the load. An empty object, from a
/// host without the BPF toolchain, passes.
///
/// - A panic cannot be compiled to BPF: rustc puts the call in a section
///   of its own, which libbpf refuses to relocate.
/// - Every parameter of a function in the BTF must have a name, or the
///   kernel refuses the BTF, "Invalid arg#N". An outlined closure takes
///   its environment as an unnamed one.
fn refuse_unloadable(out: &Path) {
    let Ok(entries) = fs::read_dir(out) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.to_string_lossy().ends_with(".bpf.o") {
            continue;
        }
        let Ok(object) = fs::read(&path) else {
            continue;
        };
        let has = |name: &str| object.windows(name.len()).any(|w| w == name.as_bytes());
        let found = ["panic_const", "panic_fmt", "panic_bounds_check"]
            .into_iter()
            .find(|name| has(name));
        if let Some(name) = found {
            panic!(
                "{} calls core::panicking ({name}): a division, an index or a clamp() \
                 kept its panic path",
                path.display()
            );
        }
        let Some(btf) = elf_section(&object, b".BTF") else {
            continue;
        };
        if let Some(function) = unnamed_parameter(btf) {
            panic!(
                "{}: {function} has an unnamed parameter, which the kernel's BTF check \
                 refuses. An outlined closure has one: call what inlines it from one place.",
                path.display()
            );
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// The section `name` of a little-endian ELF64 object.
fn elf_section<'a>(elf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let shoff = u64_at(elf, 0x28)? as usize;
    let shentsize = u16_at(elf, 0x3a)? as usize;
    let shnum = u16_at(elf, 0x3c)? as usize;
    let shstrndx = u16_at(elf, 0x3e)? as usize;
    let header = |index: usize| shoff + index * shentsize;
    let names = u64_at(elf, header(shstrndx) + 0x18)? as usize;
    for index in 0..shnum {
        let at = header(index);
        let start = names + u32_at(elf, at)? as usize;
        let end = start + name.len();
        if elf.get(start..end)? == name && elf.get(end) == Some(&0) {
            let offset = u64_at(elf, at + 0x18)? as usize;
            let size = u64_at(elf, at + 0x20)? as usize;
            return elf.get(offset..offset + size);
        }
    }
    None
}

/// The name of the first BTF function with a parameter that has a type
/// but no name, the kernel's btf_func_check(), or None.
fn unnamed_parameter(btf: &[u8]) -> Option<String> {
    const FUNC: u32 = 12;
    const FUNC_PROTO: u32 = 13;
    if u16_at(btf, 0)? != 0xeb9f {
        return None;
    }
    let header = u32_at(btf, 4)? as usize;
    let types = header + u32_at(btf, 8)? as usize;
    let types_end = types + u32_at(btf, 12)? as usize;
    let strings = header + u32_at(btf, 16)? as usize;
    let string = |offset: u32| {
        let start = strings + offset as usize;
        let len = btf.get(start..)?.iter().position(|&byte| byte == 0)?;
        Some(String::from_utf8_lossy(&btf[start..start + len]).into_owned())
    };

    // Every type by id, from 1: its kind, name, size or type, the start of
    // what follows it and its vlen.
    let mut table = vec![(0, 0, 0, 0, 0)];
    let mut at = types;
    while at < types_end {
        let info = u32_at(btf, at + 4)?;
        let (kind, vlen) = ((info >> 24) & 0x1f, (info & 0xffff) as usize);
        let data = at + 12;
        table.push((kind, u32_at(btf, at)?, u32_at(btf, at + 8)?, data, vlen));
        let fixed = match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            _ => 0,
        };
        let per = match kind {
            4 | 5 | 15 | 19 => 12,
            6 | 13 => 8,
            _ => 0,
        };
        at = data + fixed + per * vlen;
    }

    for &(kind, name, proto, _, _) in &table {
        if kind != FUNC {
            continue;
        }
        let &(proto_kind, _, _, params, count) = table.get(proto as usize)?;
        if proto_kind != FUNC_PROTO {
            continue;
        }
        for index in 0..count {
            let param = params + index * 8;
            if u32_at(btf, param)? == 0 && u32_at(btf, param + 4)? != 0 {
                return Some(format!("{} (arg#{index})", string(name)?));
            }
        }
    }
    None
}
