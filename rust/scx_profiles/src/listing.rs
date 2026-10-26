// SPDX-License-Identifier: GPL-2.0

//! The profile list as `scxcli list --json` prints it: the file's
//! profiles, each with whether its scheduler is installed, plus the
//! current state.

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::profile::{Action, Loaded, Profile, Profiles};
use crate::state::{Current, OUTPUT_VERSION};
use crate::systemd;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub label: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sched: Option<String>,
    /// The resolved executable, when the scheduler is installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// The profile can be applied on this machine.
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub version: u32,
    pub source: PathBuf,
    pub customized: bool,
    pub profiles: Vec<Entry>,
    /// Every `scx_*` scheduler installed in systemd's default search
    /// path, by name, for the advanced path that bypasses profiles.
    #[serde(default)]
    pub installed: Vec<String>,
    /// The unit's environment file that applying a profile writes, for
    /// clients to watch. Absent when the unit declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,
    pub current: Current,
}

/// Builds the entries, resolving each scheduler against `dirs`.
pub fn entries(profiles: &Profiles, dirs: &[PathBuf]) -> Vec<Entry> {
    profiles.profiles.iter().map(|p| entry(p, dirs)).collect()
}

fn entry(profile: &Profile, dirs: &[PathBuf]) -> Entry {
    let path = profile
        .sched
        .as_deref()
        .and_then(|sched| systemd::resolve_scheduler(sched, dirs).ok())
        .map(|p| p.to_string_lossy().into_owned());
    Entry {
        id: profile.id.clone(),
        label: profile.label.clone(),
        description: profile.description.clone(),
        action: profile.action,
        sched: profile.sched.clone(),
        available: profile.action.is_some() || path.is_some(),
        path,
        args: profile.args.clone(),
    }
}

/// The listing of the live system.
pub fn list() -> Result<Listing> {
    Ok(list_with_paths()?.0)
}

/// The listing together with the installed schedulers' paths, from the
/// same scan, so a caller that shows both cannot show two different
/// sets.
pub fn list_with_paths() -> Result<(Listing, Vec<(String, PathBuf)>)> {
    let loaded = crate::profile::load()?;
    list_from(&loaded)
}

pub fn list_from(loaded: &Loaded) -> Result<(Listing, Vec<(String, PathBuf)>)> {
    let dirs = systemd::system_binary_dirs()?;
    let config = systemd::unit_info()
        .ok()
        .and_then(|info| systemd::config_path(&info).ok());
    let current = crate::state::current_with(&loaded.profiles)?;
    let installed = systemd::scan_dirs_with_paths(dirs.clone());
    let listing = Listing {
        version: OUTPUT_VERSION,
        source: loaded.source.clone(),
        customized: crate::profile::is_customized(),
        profiles: entries(&loaded.profiles, &dirs),
        installed: installed.iter().map(|(name, _)| name.clone()).collect(),
        config,
        current,
    };
    Ok((listing, installed))
}
