// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{bail, Context, Result};
use libbpf_rs::MapHandle;
use libbpf_rs::OpenMapMut;
use serde_json::Value;
use std::os::unix::io::AsFd;
use std::process::Command;

/// Check if bpftool is available and functional
fn check_bpftool_available() -> Result<()> {
    let output = Command::new("bpftool").args(["--version"]).output()?;

    if !output.status.success() {
        bail!("bpftool command failed. Check if it's properly installed.");
    }

    Ok(())
}

/// Find a map by name using bpftool and return its ID
fn find_map_id_by_name(map_name: &str) -> Result<u32> {
    let output = Command::new("bpftool")
        .args(["map", "show", "name", map_name, "--json"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("bpftool map show failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        bail!("Map '{}' not found. Is scx_layered running?", map_name);
    }

    let json: Value =
        serde_json::from_str(&stdout).context("Failed to parse bpftool JSON output")?;

    let id = json["id"]
        .as_u64()
        .context("Missing or invalid 'id' field in bpftool output")?;

    Ok(id as u32)
}

/// Create a MapHandle from map ID
fn create_map_handle(map_id: u32) -> Result<MapHandle> {
    MapHandle::from_map_id(map_id)
        .context("Failed to create MapHandle from map ID. Map may have been unloaded.")
}

pub fn attach_to_existing_map(
    existing_map_name: &str,
    new_map: &mut OpenMapMut,
) -> Result<MapHandle> {
    check_bpftool_available().expect("bpftool availability check failed");

    // Find the map by name
    let map_id = find_map_id_by_name(existing_map_name)
        .expect("Failed to find map by name, check if scx_layered is running");

    // Create MapHandle from ID
    let map_handle = create_map_handle(map_id).expect("Failed to create MapHandle");

    let borrowed_fd = map_handle.as_fd();
    new_map
        .reuse_fd(borrowed_fd)
        .expect("Failed to reuse_fd on task_ctxs map");

    Ok(map_handle)
}
