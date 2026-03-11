use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{EbpfLoader, include_bytes_aligned};

fn main() -> Result<()> {
    let mut ebpf = EbpfLoader::new()
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/scx_simple"
        )))
        .context("Failed to load BPF object")?;

    let link = ebpf
        .attach_struct_ops("_scx_ops")
        .context("Failed to attach struct_ops scheduler")?;

    println!("scx_simple: scheduler attached (pure Rust BPF)");
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
    println!("\nscx_simple: scheduler detached");

    Ok(())
}
