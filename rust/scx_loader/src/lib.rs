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
    #[serde(rename = "scx_p2dq")]
    P2DQ,
    #[serde(rename = "scx_tickless")]
    Tickless,
}

impl FromStr for SupportedSched {
    type Err = anyhow::Error;

    fn from_str(scx_name: &str) -> anyhow::Result<SupportedSched> {
        match scx_name {
            "scx_bpfland" => Ok(SupportedSched::Bpfland),
            "scx_flash" => Ok(SupportedSched::Flash),
            "scx_lavd" => Ok(SupportedSched::Lavd),
            "scx_p2dq" => Ok(SupportedSched::P2DQ),
            "scx_tickless" => Ok(SupportedSched::Tickless),
            "scx_rusty" => Ok(SupportedSched::Rusty),
            _ => Err(anyhow::anyhow!("{scx_name} is not supported")),
        }
    }
}

impl TryFrom<&str> for SupportedSched {
    type Error = <SupportedSched as FromStr>::Err;
    fn try_from(s: &str) -> Result<SupportedSched, Self::Error> {
        <SupportedSched as FromStr>::from_str(s)
    }
}

impl From<SupportedSched> for &str {
    fn from(scx_name: SupportedSched) -> Self {
        match scx_name {
            SupportedSched::Bpfland => "scx_bpfland",
            SupportedSched::Flash => "scx_flash",
            SupportedSched::Lavd => "scx_lavd",
            SupportedSched::P2DQ => "scx_p2dq",
            SupportedSched::Tickless => "scx_tickless",
            SupportedSched::Rusty => "scx_rusty",
        }
    }
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
    /// Starts scheduler in server-oriented mode
    Server = 4,
}

impl FromStr for SchedMode {
    type Err = anyhow::Error;

    fn from_str(mode_name: &str) -> anyhow::Result<SchedMode> {
        match mode_name {
            "auto" => Ok(SchedMode::Auto),
            "gaming" => Ok(SchedMode::Gaming),
            "powersave" => Ok(SchedMode::PowerSave),
            "lowlatency" => Ok(SchedMode::LowLatency),
            "server" => Ok(SchedMode::Server),
            _ => Err(anyhow::anyhow!("{mode_name} is not supported")),
        }
    }
}

impl TryFrom<&str> for SchedMode {
    type Error = <SchedMode as FromStr>::Err;
    fn try_from(s: &str) -> Result<SchedMode, Self::Error> {
        <SchedMode as FromStr>::from_str(s)
    }
}

impl From<SchedMode> for &str {
    fn from(mode_name: SchedMode) -> Self {
        match mode_name {
            SchedMode::Auto => "auto",
            SchedMode::Gaming => "gaming",
            SchedMode::PowerSave => "powersave",
            SchedMode::LowLatency => "lowlatency",
            SchedMode::Server => "server",
        }
    }
}
