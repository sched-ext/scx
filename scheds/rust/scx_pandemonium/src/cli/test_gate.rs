use std::process::Command;

use anyhow::{bail, Result};

use super::TARGET_DIR;

pub fn run_test_gate() -> Result<()> {
    let project_root = env!("CARGO_MANIFEST_DIR");

    log_info!("PANDEMONIUM test gate");

    // LAYER 1: UNIT TESTS (NO ROOT)
    log_info!("Layer 1: Rust unit tests");
    let l1 = Command::new("cargo")
        .args(["test", "--release"])
        .env("CARGO_TARGET_DIR", TARGET_DIR)
        .current_dir(project_root)
        .status()?;

    if !l1.success() {
        bail!("LAYER 1 FAILED -- SKIPPING REMAINING LAYERS");
    }

    // LAYERS 2-5: INTEGRATION TESTS (REQUIRES ROOT)
    log_info!("Layers 2-5: integration (requires root)");
    let l2 = Command::new("sudo")
        .args([
            "-E",
            &format!("CARGO_TARGET_DIR={}", TARGET_DIR),
            "cargo",
            "test",
            "--test",
            "gate",
            "--release",
            "--",
            "--ignored",
            "--test-threads=1",
            "full_gate",
        ])
        .env("CARGO_TARGET_DIR", TARGET_DIR)
        .current_dir(project_root)
        .status()?;

    if !l2.success() {
        std::process::exit(l2.code().unwrap_or(1));
    }

    Ok(())
}
