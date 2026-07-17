// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use anyhow::Error as AnyhowError;

/// Default wall-clock cap for one planner or coding model turn.
pub const DEFAULT_TURN_TIMEOUT_SECS: u64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct ModelTurnTimeout {
    limit: Duration,
    elapsed: Duration,
}

impl ModelTurnTimeout {
    fn new(limit: Duration, elapsed: Duration) -> Self {
        Self { limit, elapsed }
    }

    pub fn summary(&self) -> String {
        format!(
            "model turn exceeded the {} time limit (elapsed {})",
            format_duration(self.limit),
            format_duration(self.elapsed)
        )
    }
}

impl fmt::Display for ModelTurnTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

impl Error for ModelTurnTimeout {}

#[derive(Debug, Clone, Copy)]
pub struct ModelTurnDeadline {
    started: Instant,
    limit: Duration,
}

impl ModelTurnDeadline {
    pub fn new(limit: Duration) -> Self {
        Self {
            started: Instant::now(),
            limit,
        }
    }

    pub fn check(&self) -> Result<(), ModelTurnTimeout> {
        if self.expired() {
            Err(self.timeout())
        } else {
            Ok(())
        }
    }

    pub fn expired(&self) -> bool {
        self.started.elapsed() >= self.limit
    }

    pub fn remaining(&self) -> Duration {
        self.limit
            .checked_sub(self.started.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    pub fn timeout(&self) -> ModelTurnTimeout {
        ModelTurnTimeout::new(self.limit, self.started.elapsed())
    }
}

pub fn is(err: &AnyhowError) -> bool {
    err.downcast_ref::<ModelTurnTimeout>().is_some()
}

pub fn summary(err: &AnyhowError) -> String {
    err.downcast_ref::<ModelTurnTimeout>()
        .map(ModelTurnTimeout::summary)
        .unwrap_or_else(|| err.to_string())
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 60 && secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_timeout() {
        let err = ModelTurnTimeout::new(Duration::from_secs(300), Duration::from_secs(301));

        assert_eq!(
            err.summary(),
            "model turn exceeded the 5m time limit (elapsed 301s)"
        );
    }
}
