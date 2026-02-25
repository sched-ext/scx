use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapType};

mod btf_hacks;

fn main() -> Result<()> {
    let raw_obj_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/scx_purerust"));
    let obj_bytes =
        btf_hacks::patch_elf(raw_obj_bytes).context("Failed to patch BPF object BTF")?;

    let open_obj = libbpf_rs::ObjectBuilder::default()
        .open_memory(&obj_bytes)
        .context("Failed to open BPF object")?;

    let mut obj = open_obj.load().context("Failed to load BPF object")?;

    // Find and attach the struct_ops map
    let link = obj
        .maps_mut()
        .find(|m| m.map_type() == MapType::StructOps)
        .context("No struct_ops map found in BPF object")?
        .attach_struct_ops()
        .context("Failed to attach struct_ops scheduler")?;

    println!("scx_purerust: scheduler attached (pure Rust BPF)");
    println!("Press Ctrl-C to detach and exit.");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    drop(link);
    println!("\nscx_purerust: scheduler detached");

    Ok(())
}
