//! Build-time vmlinux struct generation for pure-Rust sched_ext schedulers.
//!
//! Reads `/sys/kernel/btf/vmlinux` via `bpftool`, converts to C headers,
//! and runs `bindgen` to produce Rust struct definitions.
//!
//! # Usage in `build.rs`
//!
//! ```ignore
//! fn main() {
//!     scx_vmlinux::generate(&["task_struct", "sched_ext_entity", "scx_exit_info"])
//!         .expect("failed to generate vmlinux bindings");
//! }
//! ```
//!
//! Then in your eBPF code:
//! ```ignore
//! include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
//! ```

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Generates Rust struct definitions for the given type names from vmlinux BTF.
///
/// Uses `bpftool btf dump` to extract C headers and `bindgen` to convert
/// them to Rust. Writes output to `$OUT_DIR/vmlinux.rs`.
pub fn generate(type_names: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR")?;
    let out_path = Path::new(&out_dir).join("vmlinux.rs");

    // Step 1: Get C header from vmlinux BTF
    // Allow overriding the BTF source via SCX_VMLINUX_BTF env var
    // (e.g., SCX_VMLINUX_BTF=/lib/modules/6.16.0/build/vmlinux for cross-kernel builds)
    let btf_path = std::env::var("SCX_VMLINUX_BTF")
        .unwrap_or_else(|_| "/sys/kernel/btf/vmlinux".to_string());
    let bpftool_output = Command::new("bpftool")
        .args(["btf", "dump", "file", &btf_path, "format", "c"])
        .output()?;

    if !bpftool_output.status.success() {
        return Err(format!(
            "bpftool failed: {}",
            String::from_utf8_lossy(&bpftool_output.stderr)
        )
        .into());
    }

    let c_header = String::from_utf8(bpftool_output.stdout)?;

    // Step 2: Write header to temp file
    let tmp_dir = tempfile::tempdir()?;
    let header_path = tmp_dir.path().join("vmlinux.h");
    fs::write(&header_path, &c_header)?;

    // Step 3: Run bindgen with allowlisted types
    let mut builder = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .use_core()
        .ctypes_prefix("core::ffi")
        .layout_tests(false)
        .generate_comments(true)
        .prepend_enum_name(false)
        .derive_default(true);

    for name in type_names {
        builder = builder.allowlist_type(name);
    }

    let bindings = builder.generate().map_err(|_| "bindgen failed")?;

    // Step 4: Write output
    let mut file = fs::File::create(&out_path)?;
    writeln!(file, "// Auto-generated from /sys/kernel/btf/vmlinux")?;
    writeln!(file, "// Do not edit.\n")?;
    write!(file, "{bindings}")?;

    // Tell cargo to rerun if the kernel changes
    println!("cargo:rerun-if-changed={btf_path}");

    Ok(())
}
