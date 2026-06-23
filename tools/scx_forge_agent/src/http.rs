// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! HTTP client for an OpenAI-compatible inference endpoint: large request bodies
//! and long server think times.

use anyhow::{Context, Result};
use std::time::Duration;

/// Build a client suitable for multi-KB JSON prompts and slow inference APIs.
///
/// - Long connect (5 min) and overall (1 h) timeouts for slow inference.
/// - HTTP/1.1 only: avoids sporadic HTTP/2 stalls seen with some cloud gateways.
/// - TCP keepalive so idle long responses are less likely to be dropped.
pub fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(300))
        .timeout(Duration::from_secs(3_600))
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(45))
        .pool_max_idle_per_host(4)
        .user_agent(concat!("scx-forge-agent/", env!("CARGO_PKG_VERSION")))
        .http1_only()
        .build()
        .context("build reqwest HTTP client")
}
