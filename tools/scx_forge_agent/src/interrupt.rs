// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;

#[derive(Debug)]
pub struct Interrupted;

impl fmt::Display for Interrupted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("interrupted by Ctrl-C")
    }
}

impl std::error::Error for Interrupted {}

pub fn requested(interrupted: &AtomicBool) -> bool {
    interrupted.load(Ordering::SeqCst)
}

pub fn err() -> Error {
    Interrupted.into()
}

pub fn is(err: &Error) -> bool {
    err.downcast_ref::<Interrupted>().is_some()
}

pub async fn wait(interrupted: Arc<AtomicBool>) {
    while !requested(&interrupted) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
