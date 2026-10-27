// SPDX-License-Identifier: GPL-2.0

//! `scxcli list --json`: the recommended entries and the installed
//! schedulers, resolved against the live system, with the current
//! state.

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::catalog::{Catalog, Loaded};
use crate::state::{Current, OUTPUT_VERSION};
use crate::systemd;

/// One recommended entry, resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pick {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    /// The executable the entry resolves to; absent for `default` and
    /// for a scheduler that is not installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Whether the entry can be started here: `default` always, a
    /// scheduler when it is installed.
    pub available: bool,
}

/// One installed scheduler the catalog does not hide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub name: String,
    pub path: PathBuf,
    pub recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub version: u32,
    pub source: PathBuf,
    pub customized: bool,
    pub recommended: Vec<Pick>,
    /// Every `scx_*` scheduler installed in systemd's default search
    /// path that the catalog does not hide, by name.
    pub all: Vec<Installed>,
    /// The unit's environment file that starting a scheduler writes,
    /// for clients to watch. Absent when the unit declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,
    pub current: Current,
}

/// Builds the recommended entries from the catalog and the scan.
pub fn picks(catalog: &Catalog, installed: &[(String, PathBuf)]) -> Vec<Pick> {
    catalog
        .recommended
        .iter()
        .map(|entry| {
            let path = entry.sched().and_then(|sched| {
                installed
                    .iter()
                    .find(|(name, _)| name == sched)
                    .map(|(_, path)| path.clone())
            });
            Pick {
                id: entry.id.clone(),
                label: entry.label.clone(),
                description: entry.description.clone(),
                available: entry.sched().is_none() || path.is_some(),
                path,
            }
        })
        .collect()
}

/// The installed schedulers minus the hidden ones.
pub fn shown(catalog: &Catalog, installed: &[(String, PathBuf)]) -> Vec<Installed> {
    installed
        .iter()
        .filter(|(name, _)| !catalog.is_hidden(name))
        .map(|(name, path)| Installed {
            name: name.clone(),
            path: path.clone(),
            recommended: catalog.is_recommended(name),
        })
        .collect()
}

/// The listing of the live system.
pub fn list() -> Result<Listing> {
    let loaded = crate::catalog::load()?;
    list_from(&loaded)
}

pub fn list_from(loaded: &Loaded) -> Result<Listing> {
    let dirs = systemd::system_binary_dirs()?;
    let config = systemd::unit_info()
        .ok()
        .and_then(|info| systemd::config_path(&info).ok());
    let current = crate::state::current()?;
    let installed = systemd::scan_dirs_with_paths(dirs);
    Ok(Listing {
        version: OUTPUT_VERSION,
        source: loaded.source.clone(),
        customized: crate::catalog::is_customized(),
        recommended: picks(&loaded.catalog, &installed),
        all: shown(&loaded.catalog, &installed),
        config,
        current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_and_shown_follow_the_catalog_and_the_scan() {
        let catalog = Catalog::parse(
            r#"{"version":1,"recommended":[
                {"id":"default","label":"Default"},
                {"id":"scx_cosmos","label":"Cosmos"},
                {"id":"scx_eevdf","label":"EEVDF"}
            ],"hidden":["scx_layered"]}"#,
        )
        .unwrap();
        let installed = vec![
            (
                "scx_bpfland".to_owned(),
                PathBuf::from("/usr/bin/scx_bpfland"),
            ),
            (
                "scx_cosmos".to_owned(),
                PathBuf::from("/usr/bin/scx_cosmos"),
            ),
            (
                "scx_layered".to_owned(),
                PathBuf::from("/usr/bin/scx_layered"),
            ),
        ];
        let picks = picks(&catalog, &installed);
        assert_eq!(
            picks
                .iter()
                .map(|p| (p.id.as_str(), p.available, p.path.is_some()))
                .collect::<Vec<_>>(),
            vec![
                ("default", true, false),
                ("scx_cosmos", true, true),
                ("scx_eevdf", false, false)
            ]
        );
        let shown = shown(&catalog, &installed);
        assert_eq!(
            shown
                .iter()
                .map(|s| (s.name.as_str(), s.recommended))
                .collect::<Vec<_>>(),
            vec![("scx_bpfland", false), ("scx_cosmos", true)]
        );
    }
}
