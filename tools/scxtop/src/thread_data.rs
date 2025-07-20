// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;

use anyhow::Result;
use procfs::process::{ProcState, Task};

/// Container for Thread data.
#[derive(Clone, Debug)]
pub struct ThreadData {
    pub pid: i32,
    pub tgid: i32,
    pub cpu: i32,
    pub dsq: Option<usize>,
    pub state: ProcState,
    pub data: EventData,
    pub max_data_size: usize,
}

impl ThreadData {
    /// Creates a new ThreadData.
    pub fn new(thread: Task, max_data_size: usize) -> Result<ThreadData> {
        let thread_stats = thread.stat()?;
        let cpu = thread_stats
            .processor
            .expect("thread_stats should have processor");

        let thread_data = Self {
            pid: thread.tid,
            tgid: thread.pid,
            cpu,
            dsq: None,
            state: thread_stats.state()?,
            data: EventData::new(max_data_size),
            max_data_size,
        };

	Ok(thread_data)
    }
}
