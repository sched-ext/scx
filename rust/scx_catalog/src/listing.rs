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

/// One profile of `recommended`, resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pick {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    /// A custom profile's scheduler, by name. Absent on a plain
    /// profile, whose `id` is the scheduler, and on `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sched: Option<String>,
    /// The options `start ID` would launch the scheduler with: a
    /// custom profile's, and none for a plain profile. The command a
    /// profile stands for is `path` and `args`, which is what a client
    /// compares the running or selected command to; the id is not in
    /// the unit's file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The executable the profile resolves to; absent for `default` and
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
    /// Whether a plain profile names it.
    pub recommended: bool,
    /// Whether the catalog features it: the maintainers' pick, first
    /// in the list.
    #[serde(default)]
    pub featured: bool,
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

/// Builds the profiles from the catalog and the scan. A custom profile
/// resolves its scheduler like a plain one does, hidden or not, so
/// `available` and `path` say the same thing for both.
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
                sched: entry.sched.clone(),
                args: entry.args.clone(),
                available: entry.sched().is_none() || path.is_some(),
                path,
            }
        })
        .collect()
}

/// The installed schedulers minus the hidden ones: the featured ones
/// first, in `featured`'s order, then the other stable ones by name,
/// then the experimental ones by name, then the ones the catalog does
/// not name. The full list is what a user who skipped the recommended
/// view scrolls through: the maintainers' picks should be the first
/// thing in it and what nobody vouches for the last. The order is
/// upstream's list, not the profiles: an override that rewrites the
/// profiles does not reorder what upstream features.
pub fn shown(catalog: &Catalog, installed: &[(String, PathBuf)]) -> Vec<Installed> {
    let mut shown: Vec<Installed> = installed
        .iter()
        .filter(|(name, _)| !catalog.is_hidden(name))
        .map(|(name, path)| Installed {
            name: name.clone(),
            path: path.clone(),
            recommended: catalog.is_recommended(name),
            featured: catalog.is_featured(name),
            tier: catalog.tier(name),
        })
        .collect();
    // By tier, rank and then name, not by rank alone: the scan happens
    // to come sorted, but the order is this function's contract, not
    // the scan's.
    let featured = catalog.featured();
    shown.sort_by_cached_key(|s| {
        let rank = featured
            .iter()
            .position(|f| *f == s.name)
            .unwrap_or(usize::MAX);
        (s.tier, rank, s.name.clone())
    });
    shown
}

/// The listing of the live system, with the installed catalog.
pub fn list() -> Result<Listing> {
    list_with(None)
}

/// The listing with the catalog at `catalog`, when given, instead of
/// the installed one: the same scan and the same state, classified by
/// that file. `customized` is then false, since the administrator's
/// override is not what is in use, and `source` names the file.
pub fn list_with(catalog: Option<&std::path::Path>) -> Result<Listing> {
    let loaded = match catalog {
        Some(path) => crate::catalog::load_file(path)?,
        None => crate::catalog::load()?,
    };
    let mut listing = list_from(&loaded)?;
    if catalog.is_some() {
        listing.customized = false;
    }
    Ok(listing)
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
    use std::path::Path;

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
        assert!(picks.iter().all(|p| p.sched.is_none() && p.args.is_empty()));
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

    /// With `featured` written out, it is what orders the full list,
    /// not the profiles: an administrator's override that offers eevdf
    /// profiles first still shows upstream's featured order, and a
    /// scheduler with a profile but not featured sorts by its tier.
    #[test]
    fn featured_orders_the_full_list_not_the_profiles() {
        let catalog = Catalog::parse(
            r#"{"version":2,"recommended":[
                {"id":"default","label":"Default"},
                {"id":"scx_eevdf","label":"EEVDF"},
                {"id":"latency","label":"Low latency","sched":"scx_eevdf",
                 "args":["--slice-us","1600"]},
                {"id":"scx_rusty","label":"Rusty"}
            ],
            "featured":["scx_cosmos","scx_lavd","scx_eevdf"],
            "stable":["scx_rusty","scx_bpfland"],
            "experimental":["scx_flow"]}"#,
        )
        .unwrap();
        let installed: Vec<(String, PathBuf)> = [
            "scx_bpfland",
            "scx_cosmos",
            "scx_eevdf",
            "scx_flow",
            "scx_lavd",
            "scx_rusty",
        ]
        .iter()
        .map(|n| ((*n).to_owned(), PathBuf::from(format!("/usr/bin/{n}"))))
        .collect();
        assert_eq!(
            shown(&catalog, &installed)
                .iter()
                .map(|s| (s.name.as_str(), s.recommended, s.tier))
                .collect::<Vec<_>>(),
            vec![
                ("scx_cosmos", false, Tier::Stable),
                ("scx_lavd", false, Tier::Stable),
                ("scx_eevdf", true, Tier::Stable),
                ("scx_bpfland", false, Tier::Stable),
                ("scx_rusty", true, Tier::Stable),
                ("scx_flow", false, Tier::Experimental),
            ]
        );
        // A plain profile's scheduler is still available through the
        // profile, whatever its place in the full list, and a custom
        // profile carries its command: the resolved scheduler and the
        // options, which is what a client matches the unit's state to.
        let picks = picks(&catalog, &installed);
        assert_eq!(picks.len(), 4);
        assert!(picks.iter().all(|p| p.available));
        let latency = &picks[2];
        assert_eq!(
            (
                latency.id.as_str(),
                latency.sched.as_deref(),
                latency.path.as_deref(),
                latency.args.as_slice()
            ),
            (
                "latency",
                Some("scx_eevdf"),
                Some(Path::new("/usr/bin/scx_eevdf")),
                ["--slice-us".to_owned(), "1600".to_owned()].as_slice()
            )
        );
        let shown = shown(&catalog, &installed);
        assert_eq!(
            shown
                .iter()
                .map(|s| (s.name.as_str(), s.featured))
                .collect::<Vec<_>>(),
            vec![
                ("scx_cosmos", true),
                ("scx_lavd", true),
                ("scx_eevdf", true),
                ("scx_bpfland", false),
                ("scx_rusty", false),
                ("scx_flow", false),
            ]
        );
        // The JSON carries the command and the mark; a plain profile
        // writes neither key.
        let json = serde_json::to_value(&picks).unwrap();
        assert_eq!(json[2]["sched"], "scx_eevdf");
        assert_eq!(json[2]["args"][1], "1600");
        assert!(json[1].get("sched").is_none() && json[1].get("args").is_none());
    }
}
