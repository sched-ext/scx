// SPDX-License-Identifier: GPL-2.0

//! `scxcli list --json`: the recommended entries and the installed
//! schedulers, resolved against the live system, with the current
//! state.

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::catalog::{Catalog, Loaded, Tier};
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
    /// What the catalog says about it: `stable`, `experimental`, or
    /// `unknown` when it names the scheduler nowhere.
    pub tier: Tier,
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

/// The installed schedulers minus the hidden ones: the recommended ones
/// first, in the catalog's order, then the other stable ones by name,
/// then the experimental ones by name, then the ones the catalog does
/// not name. The full list is what a user who skipped the recommended
/// view scrolls through: the maintainers' picks should be the first
/// thing in it and what nobody vouches for the last.
pub fn shown(catalog: &Catalog, installed: &[(String, PathBuf)]) -> Vec<Installed> {
    let mut shown: Vec<Installed> = installed
        .iter()
        .filter(|(name, _)| !catalog.is_hidden(name))
        .map(|(name, path)| Installed {
            name: name.clone(),
            path: path.clone(),
            recommended: catalog.is_recommended(name),
            tier: catalog.tier(name),
        })
        .collect();
    // By tier, rank and then name, not by rank alone: the scan happens
    // to come sorted, but the order is this function's contract, not
    // the scan's.
    shown.sort_by_cached_key(|s| {
        let rank = catalog
            .recommended
            .iter()
            .position(|r| r.id == s.name)
            .unwrap_or(usize::MAX);
        (s.tier, rank, s.name.clone())
    });
    shown
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
                {"id":"scx_eevdf","label":"EEVDF"},
                {"id":"scx_cosmos","label":"Cosmos"}
            ],"hidden":["scx_layered","scx_nitosis"],
            "stable":["scx_bpfland","scx_rusty","scx_layered"],
            "experimental":["scx_flow","scx_nitosis","scx_mlfq"]}"#,
        )
        .unwrap();
        let installed: Vec<(String, PathBuf)> = [
            "scx_bpfland",
            "scx_cosmos",
            "scx_eevdf",
            "scx_flow",
            "scx_layered",
            "scx_mlfq",
            "scx_nitosis",
            "scx_rake",
            "scx_rusty",
        ]
        .iter()
        .map(|n| ((*n).to_owned(), PathBuf::from(format!("/usr/bin/{n}"))))
        .collect();
        let picks = picks(&catalog, &installed);
        assert_eq!(
            picks
                .iter()
                .map(|p| (p.id.as_str(), p.available, p.path.is_some()))
                .collect::<Vec<_>>(),
            vec![
                ("default", true, false),
                ("scx_eevdf", true, true),
                ("scx_cosmos", true, true)
            ]
        );
        // Recommended first, in the catalog's order (eevdf before cosmos
        // although it sorts after it), then the other stable ones by
        // name, then the experimental ones by name, then what the catalog
        // does not name; hidden ones (layered, and nitosis although
        // experimental too) not at all.
        let ordered = shown(&catalog, &installed);
        assert_eq!(
            ordered
                .iter()
                .map(|s| (s.name.as_str(), s.recommended, s.tier))
                .collect::<Vec<_>>(),
            vec![
                ("scx_eevdf", true, Tier::Stable),
                ("scx_cosmos", true, Tier::Stable),
                ("scx_bpfland", false, Tier::Stable),
                ("scx_rusty", false, Tier::Stable),
                ("scx_flow", false, Tier::Experimental),
                ("scx_mlfq", false, Tier::Experimental),
                ("scx_rake", false, Tier::Unknown),
            ]
        );
        // The order does not depend on the scan's: reversed input, same
        // output.
        let reversed: Vec<(String, PathBuf)> = installed.iter().rev().cloned().collect();
        assert_eq!(shown(&catalog, &reversed), ordered);
    }
}
