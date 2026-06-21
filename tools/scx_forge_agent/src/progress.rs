// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! TTY-only progress spinners for local blocking phases.

use std::io::{IsTerminal, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::color::Style;

pub struct ProgressSpinner {
    running: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl ProgressSpinner {
    pub fn stdout(label: impl Into<String>, color: Style) -> Self {
        if !std::io::stdout().is_terminal() {
            return Self {
                running: None,
                handle: None,
            };
        }

        let label = label.into();
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();
        let handle = thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0usize;
            while thread_running.load(Ordering::Relaxed) {
                print!(
                    "\r{} {}",
                    color.dim(frames[i % frames.len()]),
                    color.dim(&label)
                );
                let _ = std::io::stdout().flush();
                i += 1;
                thread::sleep(Duration::from_millis(80));
            }
        });

        Self {
            running: Some(running),
            handle: Some(handle),
        }
    }

    pub fn stop(&mut self) {
        if let Some(running) = self.running.take() {
            running.store(false, Ordering::Relaxed);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
            print!("\r\x1b[K");
            let _ = std::io::stdout().flush();
        }
    }
}

impl Drop for ProgressSpinner {
    fn drop(&mut self) {
        self.stop();
    }
}
