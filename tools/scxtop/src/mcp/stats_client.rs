// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use log::{debug, warn};
use scx_stats::StatsClient;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use std::sync::RwLock;

/// Default path for scheduler stats socket
const DEFAULT_STATS_SOCKET_PATH: &str = "/var/run/scx/root/stats";

/// Thread-safe wrapper for stats client
pub struct SharedStatsClient {
    inner: Arc<RwLock<Option<StatsClient>>>,
    socket_path: String,
}

impl SharedStatsClient {
    pub fn new(socket_path: Option<String>) -> Self {
        let socket_path = socket_path.unwrap_or_else(|| DEFAULT_STATS_SOCKET_PATH.to_string());
        Self {
            inner: Arc::new(RwLock::new(None)),
            socket_path,
        }
    }

    /// Try to connect to the scheduler's stats socket
    pub fn connect(&self) -> Result<()> {
        let client = StatsClient::new()
            .set_path(&self.socket_path)
            .connect(None)?;
        let mut inner = self.inner.write().unwrap();
        *inner = Some(client);
        debug!("Connected to stats socket at {}", self.socket_path);
        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.is_some()
    }

    /// Request stats from the scheduler
    pub fn request_stats(&self, target: Option<Vec<(String, String)>>) -> Result<JsonValue> {
        let mut inner = self.inner.write().unwrap();

        if inner.is_none() {
            // Try to connect
            drop(inner);
            if let Err(e) = self.connect() {
                warn!("Failed to connect to stats socket: {}", e);
                return Ok(serde_json::json!({
                    "error": "not_connected",
                    "message": format!("Failed to connect to scheduler stats: {}", e),
                    "note": "Ensure a scheduler is running and providing stats at the socket path"
                }));
            }
            inner = self.inner.write().unwrap();
        }

        if let Some(ref mut client) = *inner {
            match client.request::<JsonValue>("stats", target.unwrap_or_default()) {
                Ok(result) => Ok(result),
                Err(e) => {
                    warn!("Stats request failed: {}", e);
                    // Connection might be stale, clear it
                    *inner = None;
                    Ok(serde_json::json!({
                        "error": "request_failed",
                        "message": format!("Failed to request stats: {}", e),
                        "note": "The scheduler may have stopped or restarted"
                    }))
                }
            }
        } else {
            Ok(serde_json::json!({
                "error": "not_connected",
                "message": "Not connected to scheduler stats socket"
            }))
        }
    }

    /// Request stats metadata from the scheduler
    pub fn request_stats_meta(&self) -> Result<JsonValue> {
        let mut inner = self.inner.write().unwrap();

        if inner.is_none() {
            // Try to connect
            drop(inner);
            if let Err(e) = self.connect() {
                warn!("Failed to connect to stats socket: {}", e);
                return Ok(serde_json::json!({
                    "error": "not_connected",
                    "message": format!("Failed to connect to scheduler stats: {}", e),
                }));
            }
            inner = self.inner.write().unwrap();
        }

        if let Some(ref mut client) = *inner {
            match client.request::<JsonValue>("stats_meta", vec![]) {
                Ok(result) => Ok(result),
                Err(e) => {
                    warn!("Stats meta request failed: {}", e);
                    // Connection might be stale, clear it
                    *inner = None;
                    Ok(serde_json::json!({
                        "error": "request_failed",
                        "message": format!("Failed to request stats metadata: {}", e),
                    }))
                }
            }
        } else {
            Ok(serde_json::json!({
                "error": "not_connected",
                "message": "Not connected to scheduler stats socket"
            }))
        }
    }
}

impl Clone for SharedStatsClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            socket_path: self.socket_path.clone(),
        }
    }
}
