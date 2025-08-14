// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use libbpf_rs::query;
use libbpf_rs::MapHandle;
use libbpf_rs::OpenMapMut;
use std::os::unix::io::AsFd;

pub fn attach_to_existing_map(
    existing_map_name: &str,
    new_map: &mut OpenMapMut,
) -> Result<MapHandle> {
    for map in query::MapInfoIter::default() {
        if map.name.to_str().unwrap() == existing_map_name {
            let map_handle = MapHandle::from_map_id(map.id)
                .expect("Failed to create MapHandle from map ID. Map may have been unloaded.");

            let borrowed_fd = map_handle.as_fd();
            new_map
                .reuse_fd(borrowed_fd)
                .expect("Failed to reuse_fd on task_ctxs map");

            return Ok(map_handle);
        }
    }

    Err(anyhow::anyhow!("failed to find {existing_map_name}"))
}
