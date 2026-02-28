use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{EbpfLoader, KfuncParamType, KfuncSignature, include_bytes_aligned};

fn main() -> Result<()> {
    let mut ebpf = EbpfLoader::new()
        .register_kfunc(
            "scx_bpf_dsq_insert",
            KfuncSignature {
                params: vec![
                    KfuncParamType::Ptr,
                    KfuncParamType::U64,
                    KfuncParamType::U64,
                    KfuncParamType::U64,
                ],
                ret: None,
            },
        )
        .register_kfunc(
            "scx_bpf_dsq_move_to_local",
            KfuncSignature {
                params: vec![KfuncParamType::U64],
                ret: Some(KfuncParamType::Bool),
            },
        )
        .register_kfunc(
            "scx_bpf_create_dsq",
            KfuncSignature {
                params: vec![KfuncParamType::U64, KfuncParamType::I32],
                ret: Some(KfuncParamType::I32),
            },
        )
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/scx_purerust"
        )))
        .context("Failed to load BPF object")?;

    let link = ebpf
        .attach_struct_ops("_scx_ops")
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
