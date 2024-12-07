// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Vladislav Nepogodin <vnepogodin@cachyos.org>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub mod config;
pub mod dbus;

use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use zvariant::OwnedValue;
use zvariant::Type;
use zvariant::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Type)]
#[zvariant(signature = "s")]
#[serde(rename_all = "lowercase")]
pub enum SupportedSched {
    #[serde(rename = "scx_bpfland")]
    Bpfland,
    #[serde(rename = "scx_rusty")]
    Rusty,
    #[serde(rename = "scx_lavd")]
    Lavd,
    #[serde(rename = "scx_flash")]
    Flash,
}

#[derive(Debug, Clone, Deserialize, Serialize, Type, Value, OwnedValue, PartialEq)]
pub enum SchedMode {
    /// Default values for the scheduler
    Auto = 0,
    /// Applies flags for better gaming experience
    Gaming = 1,
    /// Applies flags for lower power usage
    PowerSave = 2,
    /// Starts scheduler in low latency mode
    LowLatency = 3,
}

impl From<&SupportedSched> for &str {
    fn from(scx_name: &SupportedSched) -> &'static str {
        match scx_name {
            SupportedSched::Bpfland => "scx_bpfland",
            SupportedSched::Rusty => "scx_rusty",
            SupportedSched::Lavd => "scx_lavd",
            SupportedSched::Flash => "scx_flash",
        }
    }
}

impl From<SupportedSched> for &str {
    fn from(scx_name: SupportedSched) -> &'static str {
        scx_name.into()
    }
}

impl FromStr for SupportedSched {
    type Err = anyhow::Error;

    fn from_str(scx_name: &str) -> anyhow::Result<SupportedSched> {
        match scx_name {
            "scx_bpfland" => Ok(SupportedSched::Bpfland),
            "scx_rusty" => Ok(SupportedSched::Rusty),
            "scx_lavd" => Ok(SupportedSched::Lavd),
            "scx_flash" => Ok(SupportedSched::Flash),
            _ => Err(anyhow::anyhow!("{scx_name} is not supported")),
        }
    }
}
