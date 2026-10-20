// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Match the return types of the object's kfunc prototypes to the running
//! kernel's.
//!
//! libbpf refuses an extern kfunc whose prototype is not compatible with
//! the kernel's, and a return type that is void on one side and a value on
//! the other is not. Such changes happen while the cid-form interface
//! settles: scx_bpf_kick_cid() returned s32 on kernels where it now returns
//! nothing, and scx_bpf_cidperf_set() the other way around. The BPF side
//! never reads what these return, so the object can be told whichever the
//! kernel has.
//!
//! The object's BTF is rewritten before libbpf opens it. Each kfunc whose
//! return type has to change gets a copy of its prototype with the kernel's
//! choice, appended after the last type, since the linker may share one
//! prototype between kfuncs that look alike. Type ids and string offsets
//! stay where they were, so .BTF.ext still holds. The longer .BTF goes at
//! the end of the image and its section header is pointed there.

use std::collections::BTreeMap;

use anyhow::{Context, bail, ensure};
use libbpf_rs::{
    Btf,
    btf::{ReferencesType, types::Func},
};

use crate::Result;

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_FUNC_EXTERN: u32 = 2;
const BTF_INT_SIGNED: u32 = 1;

fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    let word = bytes.get(at..at + 2).context("truncated BPF object")?;
    Ok(u16::from_le_bytes(word.try_into()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    let word = bytes.get(at..at + 4).context("truncated BPF object")?;
    Ok(u32::from_le_bytes(word.try_into()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    let word = bytes.get(at..at + 8).context("truncated BPF object")?;
    Ok(u64::from_le_bytes(word.try_into()?))
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// The section header of `.BTF` in an ELF64 little-endian object: where
/// the header is, and the section's offset and size.
fn btf_section(object: &[u8]) -> Result<Option<(usize, usize, usize)>> {
    ensure!(
        object.get(..6) == Some(&[0x7f, b'E', b'L', b'F', 2, 1][..]),
        "BPF object is not a little-endian ELF64 file"
    );
    let shoff = u64_at(object, 0x28)? as usize;
    let shentsize = u16_at(object, 0x3a)? as usize;
    let shnum = u16_at(object, 0x3c)? as usize;
    let shstrndx = u16_at(object, 0x3e)? as usize;
    let names = u64_at(object, shoff + shstrndx * shentsize + 24)? as usize;
    for index in 0..shnum {
        let header = shoff + index * shentsize;
        let name = names + u32_at(object, header)? as usize;
        if object.get(name..name + 5) == Some(&b".BTF\0"[..]) {
            let offset = u64_at(object, header + 24)? as usize;
            let size = u64_at(object, header + 32)? as usize;
            return Ok(Some((header, offset, size)));
        }
    }
    Ok(None)
}

/// The bytes a type takes after its 12-byte header.
fn trailing(kind: u32, vlen: usize) -> usize {
    match kind {
        1 | 14 | 17 => 4,     // INT, VAR, DECL_TAG
        3 => 12,              // ARRAY
        4 | 5 => vlen * 12,   // STRUCT, UNION
        6 | 13 => vlen * 8,   // ENUM, FUNC_PROTO
        15 | 19 => vlen * 12, // DATASEC, ENUM64
        _ => 0,
    }
}

struct Type {
    offset: usize,
    kind: u32,
    vlen: usize,
    name: String,
    size_or_type: u32,
}

/// Return `object` with the return types of its kfuncs matched to the
/// running kernel's, and the names of the kfuncs that changed.
pub fn adapt(object: &[u8]) -> Result<(Vec<u8>, Vec<String>)> {
    let Some((header, offset, size)) = btf_section(object)? else {
        return Ok((object.to_vec(), Vec::new()));
    };
    let btf = object
        .get(offset..offset + size)
        .context("truncated .BTF section")?;
    ensure!(u16_at(btf, 0)? == BTF_MAGIC, "bad .BTF magic");
    let hdr_len = u32_at(btf, 4)? as usize;
    let type_off = hdr_len + u32_at(btf, 8)? as usize;
    let type_len = u32_at(btf, 12)? as usize;
    let str_off = hdr_len + u32_at(btf, 16)? as usize;
    let str_len = u32_at(btf, 20)? as usize;
    ensure!(
        str_off == type_off + type_len && str_off + str_len <= size,
        "unexpected .BTF layout"
    );
    let string = |at: u32| -> String {
        let start = str_off + at as usize;
        let end = btf[start..str_off + str_len]
            .iter()
            .position(|&byte| byte == 0)
            .map_or(start, |length| start + length);
        String::from_utf8_lossy(&btf[start..end]).into_owned()
    };

    // Every type, by id from 1.
    let mut types = vec![];
    let mut at = type_off;
    while at < type_off + type_len {
        let info = u32_at(btf, at + 4)?;
        let (kind, vlen) = ((info >> 24) & 0x1f, (info & 0xffff) as usize);
        types.push(Type {
            offset: at,
            kind,
            vlen,
            name: string(u32_at(btf, at)?),
            size_or_type: u32_at(btf, at + 8)?,
        });
        at += 12 + trailing(kind, vlen);
    }
    ensure!(at == type_off + type_len, "unexpected .BTF type section");
    let by_id = |id: u32| types.get((id as usize).wrapping_sub(1));

    let kernel = Btf::from_vmlinux().context("read running kernel BTF")?;
    // The kfuncs whose return type has to change: the FUNC's offset, its
    // prototype's id, and whether the kernel returns a value.
    let mut changes = BTreeMap::new();
    for function in &types {
        if function.kind != BTF_KIND_FUNC || function.vlen as u32 != BTF_FUNC_EXTERN {
            continue;
        }
        let Some(prototype) = by_id(function.size_or_type) else {
            continue;
        };
        if prototype.kind != BTF_KIND_FUNC_PROTO {
            continue;
        }
        let Some(theirs) = kernel.type_by_name::<Func<'_>>(&function.name) else {
            continue;
        };
        let theirs = theirs.referenced_type();
        let Some(theirs) = libbpf_rs::btf::types::FuncProto::try_from(theirs).ok() else {
            continue;
        };
        let kernel_returns = u32::from(theirs.referenced_type_id()) != 0;
        if kernel_returns != (prototype.size_or_type != 0) {
            changes.insert(
                function.name.clone(),
                (function.offset, function.size_or_type, kernel_returns),
            );
        }
    }
    if changes.is_empty() {
        return Ok((object.to_vec(), Vec::new()));
    }

    // A 32-bit signed integer to return where the kernel returns a value:
    // one the object has, or one appended with its name.
    let mut strings = btf[str_off..str_off + str_len].to_vec();
    let mut appended = vec![];
    let mut next_id = types.len() as u32 + 1;
    let int_id = match types.iter().position(|ty| {
        ty.kind == BTF_KIND_INT
            && ty.size_or_type == 4
            && (u32_at(btf, ty.offset + 12).unwrap_or(0) >> 24) & BTF_INT_SIGNED != 0
    }) {
        Some(index) => index as u32 + 1,
        None if changes.values().any(|&(_, _, returns)| returns) => {
            let name = strings.len() as u32;
            strings.extend_from_slice(b"int\0");
            appended.extend_from_slice(&name.to_le_bytes());
            appended.extend_from_slice(&(BTF_KIND_INT << 24).to_le_bytes());
            appended.extend_from_slice(&4u32.to_le_bytes());
            appended.extend_from_slice(&((BTF_INT_SIGNED << 24) | 32).to_le_bytes());
            next_id += 1;
            next_id - 1
        }
        None => 0,
    };

    let mut patched = object.to_vec();
    let mut new_btf = btf[..str_off].to_vec();
    for &(function, prototype, returns) in changes.values() {
        let Some(original) = by_id(prototype) else {
            bail!("kfunc prototype {prototype} out of range");
        };
        let start = original.offset;
        let mut copy = btf[start..start + 12 + trailing(original.kind, original.vlen)].to_vec();
        put_u32(&mut copy, 8, if returns { int_id } else { 0 });
        appended.extend_from_slice(&copy);
        // The FUNC, in the copy of the type section, now names the copy.
        put_u32(&mut new_btf, function + 8, next_id);
        next_id += 1;
    }
    new_btf.extend_from_slice(&appended);
    new_btf.extend_from_slice(&strings);
    put_u32(&mut new_btf, 12, (type_len + appended.len()) as u32);
    put_u32(
        &mut new_btf,
        16,
        (type_off - hdr_len + type_len + appended.len()) as u32,
    );
    put_u32(&mut new_btf, 20, strings.len() as u32);

    while !patched.len().is_multiple_of(8) {
        patched.push(0);
    }
    let new_offset = patched.len();
    patched.extend_from_slice(&new_btf);
    put_u64(&mut patched, header + 24, new_offset as u64);
    put_u64(&mut patched, header + 32, new_btf.len() as u64);
    Ok((patched, changes.into_keys().collect()))
}
