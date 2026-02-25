//! BTF and ELF patching for Rust BPF struct_ops compatibility.
//!
//! HACK: The Rust BPF compiler produces ELF/BTF that libbpf cannot load
//! as-is for struct_ops programs. This module patches three issues:
//!
//! 1. **Missing kfunc BTF**: Rust doesn't emit FUNC/FUNC_PROTO entries
//!    for `extern "C"` kfunc declarations, nor a `.ksyms` DATASEC.
//!    We add these using libbpf's BTF API.
//!
//! 2. **Wrong fn-ptr field types**: Rust's `Option<fn>` compiles to a
//!    BTF STRUCT, but libbpf requires PTR -> FUNC_PROTO for struct_ops
//!    callback fields. We patch the raw BTF bytes.
//!
//! 3. **Wrong function linkage**: Rust emits struct_ops callbacks as
//!    `global` functions, but the BPF verifier requires `static` linkage
//!    for callbacks that return void. We patch the BTF FUNC entries.
//!
//! When aya gains native struct_ops + kfunc support, this entire module
//! becomes unnecessary.

use anyhow::{bail, Context, Result};

/// Number of function pointer fields in `sched_ext_ops` (before data fields).
const SCHED_EXT_OPS_NUM_FN_FIELDS: usize = 34;

/// All struct_ops callback function names that need static linkage.
const CALLBACK_NAMES: &[&[u8]] = &[
    b"simple_select_cpu\0",
    b"simple_enqueue\0",
    b"simple_dispatch\0",
    b"simple_running\0",
    b"simple_stopping\0",
    b"simple_enable\0",
    b"simple_init\0",
    b"simple_exit\0",
];

/// Patch the BPF ELF to fix all BTF issues. Returns a new ELF with a
/// corrected `.BTF` section.
pub fn patch_elf(elf: &[u8]) -> Result<Vec<u8>> {
    // ── Parse ELF64 header ──────────────────────────────────────────────

    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" {
        bail!("Not a valid ELF64 file");
    }

    let e_shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(elf[62..64].try_into().unwrap()) as usize;

    if e_shoff + e_shnum * e_shentsize > elf.len() {
        bail!("Section headers extend past EOF");
    }

    // Get section header string table
    let shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = u64::from_le_bytes(
        elf[shstrtab_hdr + 24..shstrtab_hdr + 32]
            .try_into()
            .unwrap(),
    ) as usize;

    // ── Find .BTF section ───────────────────────────────────────────────

    let mut btf_idx = None;
    let mut btf_sh_offset = 0usize;
    let mut btf_file_offset = 0usize;
    let mut btf_size = 0usize;

    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        let sh_name_off = u32::from_le_bytes(elf[sh..sh + 4].try_into().unwrap()) as usize;
        let name_start = shstrtab_off + sh_name_off;

        if name_start + 5 <= elf.len() && &elf[name_start..name_start + 5] == b".BTF\0" {
            btf_idx = Some(i);
            btf_sh_offset = sh;
            btf_file_offset =
                u64::from_le_bytes(elf[sh + 24..sh + 32].try_into().unwrap()) as usize;
            btf_size = u64::from_le_bytes(elf[sh + 32..sh + 40].try_into().unwrap()) as usize;
            break;
        }
    }

    let btf_idx = btf_idx.context("No .BTF section found in ELF")?;
    let old_btf_data = &elf[btf_file_offset..btf_file_offset + btf_size];

    // ── Patch BTF content ───────────────────────────────────────────────

    let new_btf_data = patch_btf(old_btf_data, btf_size)?;

    // ── Reassemble ELF with new .BTF section ────────────────────────────

    let size_delta = new_btf_data.len() as isize - btf_size as isize;
    let btf_end = btf_file_offset + btf_size;

    let mut out = Vec::with_capacity((elf.len() as isize + size_delta) as usize);
    out.extend_from_slice(&elf[..btf_file_offset]);
    out.extend_from_slice(&new_btf_data);
    out.extend_from_slice(&elf[btf_end..]);

    // Update .BTF section header's sh_size
    let new_btf_sh_offset = if e_shoff >= btf_end {
        btf_sh_offset + size_delta as usize
    } else {
        btf_sh_offset
    };
    out[new_btf_sh_offset + 32..new_btf_sh_offset + 40]
        .copy_from_slice(&(new_btf_data.len() as u64).to_le_bytes());

    // Adjust e_shoff if section header table is after .BTF
    if e_shoff >= btf_end {
        out[40..48].copy_from_slice(&((e_shoff as isize + size_delta) as u64).to_le_bytes());
    }

    // Adjust sh_offset for sections after .BTF in the file
    let new_e_shoff_val = if e_shoff >= btf_end {
        (e_shoff as isize + size_delta) as usize
    } else {
        e_shoff
    };
    for i in 0..e_shnum {
        if i == btf_idx {
            continue;
        }
        let sh = new_e_shoff_val + i * e_shentsize;
        let sh_offset = u64::from_le_bytes(out[sh + 24..sh + 32].try_into().unwrap()) as usize;
        if sh_offset >= btf_end {
            out[sh + 24..sh + 32]
                .copy_from_slice(&((sh_offset as isize + size_delta) as u64).to_le_bytes());
        }
    }

    Ok(out)
}

/// Patch BTF data: add kfunc entries, fix struct_ops field types, fix linkage.
fn patch_btf(old_btf_data: &[u8], btf_size: usize) -> Result<Vec<u8>> {
    unsafe {
        let btf = libbpf_sys::btf__new(old_btf_data.as_ptr() as *const _, btf_size as u32);
        if btf.is_null() {
            bail!("btf__new failed");
        }

        macro_rules! btf_check {
            ($expr:expr, $msg:expr) => {{
                let rc = $expr;
                if rc < 0 {
                    libbpf_sys::btf__free(btf);
                    bail!("{}: {}", $msg, rc);
                }
                rc
            }};
        }

        // ── Base types for kfunc signatures ─────────────────────────────

        let u64_id = btf_check!(
            libbpf_sys::btf__add_int(btf, c"u64".as_ptr(), 8, 0),
            "btf__add_int(u64)"
        );
        let bool_id = btf_check!(
            libbpf_sys::btf__add_int(btf, c"_Bool".as_ptr(), 1, 4),
            "btf__add_int(bool)"
        );
        let i32_id = btf_check!(
            libbpf_sys::btf__add_int(btf, c"int".as_ptr(), 4, libbpf_sys::BTF_INT_SIGNED as i32),
            "btf__add_int(int)"
        );

        // task_struct with one scalar field for CO-RE compat
        let task_struct_id = btf_check!(
            libbpf_sys::btf__add_struct(btf, c"task_struct".as_ptr(), 4),
            "btf__add_struct(task_struct)"
        );
        btf_check!(
            libbpf_sys::btf__add_field(btf, c"pid".as_ptr(), i32_id, 0, 0),
            "btf__add_field(pid)"
        );
        let task_ptr_id = btf_check!(
            libbpf_sys::btf__add_ptr(btf, task_struct_id),
            "btf__add_ptr(task)"
        );

        // ── kfunc FUNC_PROTO + FUNC entries ─────────────────────────────

        // scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags) -> void
        let proto_insert = btf_check!(
            libbpf_sys::btf__add_func_proto(btf, 0),
            "btf__add_func_proto(dsq_insert)"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"p".as_ptr(), task_ptr_id),
            "param"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"dsq_id".as_ptr(), u64_id),
            "param"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"slice".as_ptr(), u64_id),
            "param"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"enq_flags".as_ptr(), u64_id),
            "param"
        );
        let func_insert = btf_check!(
            libbpf_sys::btf__add_func(
                btf,
                c"scx_bpf_dsq_insert".as_ptr(),
                libbpf_sys::BTF_FUNC_EXTERN,
                proto_insert,
            ),
            "btf__add_func(dsq_insert)"
        );

        // scx_bpf_dsq_move_to_local(dsq_id) -> bool
        let proto_move = btf_check!(
            libbpf_sys::btf__add_func_proto(btf, bool_id),
            "btf__add_func_proto(dsq_move_to_local)"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"dsq_id".as_ptr(), u64_id),
            "param"
        );
        let func_move = btf_check!(
            libbpf_sys::btf__add_func(
                btf,
                c"scx_bpf_dsq_move_to_local".as_ptr(),
                libbpf_sys::BTF_FUNC_EXTERN,
                proto_move,
            ),
            "btf__add_func(dsq_move_to_local)"
        );

        // scx_bpf_create_dsq(dsq_id, node) -> i32
        let proto_create = btf_check!(
            libbpf_sys::btf__add_func_proto(btf, i32_id),
            "btf__add_func_proto(create_dsq)"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"dsq_id".as_ptr(), u64_id),
            "param"
        );
        btf_check!(
            libbpf_sys::btf__add_func_param(btf, c"node".as_ptr(), i32_id),
            "param"
        );
        let func_create = btf_check!(
            libbpf_sys::btf__add_func(
                btf,
                c"scx_bpf_create_dsq".as_ptr(),
                libbpf_sys::BTF_FUNC_EXTERN,
                proto_create,
            ),
            "btf__add_func(create_dsq)"
        );

        // ── .ksyms DATASEC ──────────────────────────────────────────────

        btf_check!(
            libbpf_sys::btf__add_datasec(btf, c".ksyms".as_ptr(), 0),
            "btf__add_datasec"
        );
        btf_check!(
            libbpf_sys::btf__add_datasec_var_info(btf, func_insert, 0, 0),
            "datasec_var_info"
        );
        btf_check!(
            libbpf_sys::btf__add_datasec_var_info(btf, func_move, 0, 0),
            "datasec_var_info"
        );
        btf_check!(
            libbpf_sys::btf__add_datasec_var_info(btf, func_create, 0, 0),
            "datasec_var_info"
        );

        // ── Dummy PTR -> FUNC_PROTO for struct_ops field type fixup ─────

        let dummy_proto = btf_check!(
            libbpf_sys::btf__add_func_proto(btf, 0),
            "btf__add_func_proto(dummy)"
        );
        let dummy_ptr = btf_check!(
            libbpf_sys::btf__add_ptr(btf, dummy_proto),
            "btf__add_ptr(dummy)"
        );

        // ── Serialize and apply raw BTF patches ─────────────────────────

        let mut raw_size: u32 = 0;
        let raw_ptr = libbpf_sys::btf__raw_data(btf, &mut raw_size as *mut _);
        if raw_ptr.is_null() {
            libbpf_sys::btf__free(btf);
            bail!("btf__raw_data failed");
        }
        let mut data = std::slice::from_raw_parts(raw_ptr as *const u8, raw_size as usize).to_vec();
        libbpf_sys::btf__free(btf);

        patch_struct_ops_field_types(&mut data, dummy_ptr as u32)?;
        patch_func_linkage_to_static(&mut data, CALLBACK_NAMES)?;

        Ok(data)
    }
}

/// Replace the first 34 `sched_ext_ops` member type_ids with a PTR -> FUNC_PROTO.
///
/// Rust's `Option<fn>` encodes as a BTF STRUCT, but libbpf's `resolve_func_ptr()`
/// requires PTR -> FUNC_PROTO for struct_ops callback fields.
fn patch_struct_ops_field_types(btf_data: &mut [u8], ptr_type_id: u32) -> Result<()> {
    if btf_data.len() < 24 {
        bail!("BTF data too small");
    }
    let hdr_len = u32::from_le_bytes(btf_data[4..8].try_into().unwrap()) as usize;
    let type_off = u32::from_le_bytes(btf_data[8..12].try_into().unwrap()) as usize;
    let type_len = u32::from_le_bytes(btf_data[12..16].try_into().unwrap()) as usize;
    let str_off = u32::from_le_bytes(btf_data[16..20].try_into().unwrap()) as usize;

    let type_start = hdr_len + type_off;
    let type_end = type_start + type_len;
    let str_start = hdr_len + str_off;

    let mut pos = type_start;
    while pos + 12 <= type_end {
        let name_off = u32::from_le_bytes(btf_data[pos..pos + 4].try_into().unwrap()) as usize;
        let info = u32::from_le_bytes(btf_data[pos + 4..pos + 8].try_into().unwrap());
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;

        if kind == 4 {
            // BTF_KIND_STRUCT
            let name_start = str_start + name_off;
            if name_start + 14 <= btf_data.len()
                && &btf_data[name_start..name_start + 14] == b"sched_ext_ops\0"
            {
                let members_start = pos + 12;
                let n = vlen.min(SCHED_EXT_OPS_NUM_FN_FIELDS);
                for i in 0..n {
                    let type_field = members_start + i * 12 + 4;
                    btf_data[type_field..type_field + 4]
                        .copy_from_slice(&ptr_type_id.to_le_bytes());
                }
                return Ok(());
            }
        }

        pos += 12;
        pos += btf_kind_extra_size(kind, vlen);
    }

    bail!("sched_ext_ops STRUCT type not found in BTF");
}

/// Change FUNC linkage from `global` to `static` for named functions.
///
/// The BPF verifier requires global functions to return scalars, but
/// struct_ops callbacks may return void. Clang emits them as static.
fn patch_func_linkage_to_static(btf_data: &mut [u8], names: &[&[u8]]) -> Result<()> {
    let hdr_len = u32::from_le_bytes(btf_data[4..8].try_into().unwrap()) as usize;
    let type_off = u32::from_le_bytes(btf_data[8..12].try_into().unwrap()) as usize;
    let type_len = u32::from_le_bytes(btf_data[12..16].try_into().unwrap()) as usize;
    let str_off = u32::from_le_bytes(btf_data[16..20].try_into().unwrap()) as usize;

    let type_start = hdr_len + type_off;
    let type_end = type_start + type_len;
    let str_start = hdr_len + str_off;

    let mut pos = type_start;
    let mut patched = 0;
    while pos + 12 <= type_end {
        let name_off = u32::from_le_bytes(btf_data[pos..pos + 4].try_into().unwrap()) as usize;
        let info = u32::from_le_bytes(btf_data[pos + 4..pos + 8].try_into().unwrap());
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;

        // BTF_KIND_FUNC = 12, vlen encodes linkage (0=static, 1=global)
        if kind == 12 && vlen == 1 {
            let ns = str_start + name_off;
            for target in names {
                if ns + target.len() <= btf_data.len()
                    && &btf_data[ns..ns + target.len()] == *target
                {
                    let new_info = info & !0xffff;
                    btf_data[pos + 4..pos + 8].copy_from_slice(&new_info.to_le_bytes());
                    patched += 1;
                    break;
                }
            }
        }

        pos += 12;
        pos += btf_kind_extra_size(kind, vlen);
    }

    if patched == 0 {
        bail!("No FUNC entries patched to static linkage");
    }
    Ok(())
}

/// Extra bytes following a BTF type entry, determined by kind and vlen.
fn btf_kind_extra_size(kind: u32, vlen: usize) -> usize {
    match kind {
        1 => 4,             // INT
        2 => 0,             // PTR
        3 => 12,            // ARRAY
        4 | 5 => vlen * 12, // STRUCT / UNION
        6 => vlen * 8,      // ENUM
        7..=11 => 0,        // FWD / TYPEDEF / VOLATILE / CONST / RESTRICT
        12 => 0,            // FUNC
        13 => vlen * 8,     // FUNC_PROTO
        14 => 4,            // VAR
        15 => vlen * 12,    // DATASEC
        16 => 0,            // FLOAT
        17 => 4,            // DECL_TAG
        18 => 0,            // TYPE_TAG
        19 => vlen * 16,    // ENUM64
        _ => 0,
    }
}
