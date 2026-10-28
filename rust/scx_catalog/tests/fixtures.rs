// SPDX-License-Identifier: GPL-2.0

//! The shared fixtures under `fixtures/`, the executable form of
//! `services/CATALOG.md`. Clients copy them to test their parsers
//! against the same inputs and outputs.
//!
//! `catalog/valid/*.json` must load and `catalog/invalid/*.json` must
//! not. Each `detection/*.json` is one system to detect the running
//! scheduler on, with the inputs shared between cases kept once:
//!
//! - `unit`: the name of a `detection/units/*.txt` file holding
//!   `systemctl show` output, where `@name` in `EnvironmentFiles=`
//!   stands for an entry of `files`;
//! - `manager`: `systemctl show-environment` output, one line each;
//! - `files`: the environment files, by the name `unit` refers to;
//! - `cmdline`: the unit's main process, one argv word each, or null
//!   when the unit has no process;
//! - `sysfs`: `/sys/kernel/sched_ext` as `state` and `root/ops` (null
//!   while nothing is attached), or null on a kernel without
//!   `sched_ext`;
//! - `expected`: what `scxcli get --json` prints.
//!
//! Detection does not read the catalog: which scheduler runs is a fact
//! about the unit and the kernel, and whether it is recommended or
//! hidden is the listing's business.

use std::fs;
use std::path::{Path, PathBuf};

use scx_catalog::catalog::{Catalog, Tier};
use scx_catalog::failure::verdict;
use scx_catalog::state::{Current, detect};
use scx_catalog::systemd::{Process, parse_manager_environment, parse_unit_info, unit_environment};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn sorted_dir(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "{} is empty", dir.display());
    entries
}

#[test]
fn valid_catalog_files_load_and_round_trip() {
    for path in sorted_dir(&fixtures().join("catalog/valid")) {
        let text = fs::read_to_string(&path).unwrap();
        let catalog =
            Catalog::parse(&text).unwrap_or_else(|err| panic!("{}: {err:#}", path.display()));
        let again = Catalog::parse(&catalog.render().unwrap()).unwrap();
        assert_eq!(again, catalog, "{}", path.display());
    }
}

#[test]
fn invalid_catalog_files_are_rejected() {
    for path in sorted_dir(&fixtures().join("catalog/invalid")) {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            Catalog::parse(&text).is_err(),
            "{} should not load",
            path.display()
        );
    }
}

#[test]
fn the_shipped_catalog_is_the_valid_fixture() {
    let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../services/catalog.json");
    let text = fs::read_to_string(&shipped).unwrap();
    Catalog::parse(&text).unwrap();
    let fixture = fs::read_to_string(fixtures().join("catalog/valid/shipped.json")).unwrap();
    assert_eq!(
        text, fixture,
        "fixtures/catalog/valid/shipped.json is a copy of services/catalog.json"
    );
}

/// The `scx_*` directories directly under `scheds/<dir>` in this
/// checkout.
fn schedulers_under(dir: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scheds")
        .join(dir);
    let mut names: Vec<String> = fs::read_dir(&root)
        .unwrap_or_else(|err| panic!("{}: {err}", root.display()))
        .map(|e| e.unwrap())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("scx_"))
        .collect();
    names.sort();
    names
}

/// The tiers in the shipped catalog follow the tree, in the direction
/// that keeps the labels honest. Every scheduler under
/// `scheds/experimental` is experimental; a scheduler under
/// `scheds/rust` may be experimental too when its own README says so
/// (scx_chaos exists to misbehave, scx_forge is a base to be rewritten
/// by an agent), so the list may hold more, never less. Every `stable`
/// entry and every recommended scheduler lives under `scheds/rust`, and
/// a place there is not stability: what the catalog calls stable it
/// says by name. Adding or moving a scheduler without updating the
/// catalog fails here, so the file cannot drift from the layout it
/// describes, and the extras are recorded so that each is a decision
/// rather than an oversight.
#[test]
fn the_shipped_tiers_follow_the_tree() {
    let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../services/catalog.json");
    let catalog = Catalog::parse(&fs::read_to_string(shipped).unwrap()).unwrap();
    let rust = schedulers_under("rust");
    let experimental = schedulers_under("experimental");

    for sched in &experimental {
        assert!(
            catalog.experimental.contains(sched),
            "services/catalog.json: {sched} is under scheds/experimental but not experimental"
        );
    }
    let extras: Vec<&String> = catalog
        .experimental
        .iter()
        .filter(|s| !experimental.contains(s))
        .collect();
    for sched in &extras {
        assert!(
            rust.contains(sched),
            "experimental {sched} is under neither scheds/experimental nor scheds/rust"
        );
    }
    assert_eq!(extras, [&"scx_chaos".to_owned(), &"scx_forge".to_owned()]);

    for sched in &catalog.stable {
        assert!(
            rust.contains(sched),
            "stable {sched} is not under scheds/rust"
        );
    }
    for entry in &catalog.recommended {
        if let Some(sched) = entry.sched() {
            assert!(
                rust.contains(&sched.to_owned()),
                "recommended {sched} is not under scheds/rust"
            );
        }
    }
    for list in [&catalog.stable, &catalog.experimental] {
        let mut sorted = list.clone();
        sorted.sort();
        assert_eq!(list, &sorted, "the tier lists are kept sorted");
    }
    // Every scheduler in the tree has a tier on record; nothing under
    // scheds/rust is left for the default to decide.
    for sched in rust.iter().chain(&experimental) {
        assert_ne!(
            catalog.tier(sched),
            Tier::Unknown,
            "{sched} is in the tree but the catalog says nothing about it"
        );
    }
}

/// One `detection/*.json` case.
#[derive(serde::Deserialize)]
struct Case {
    unit: String,
    #[serde(default)]
    manager: Vec<String>,
    #[serde(default)]
    files: std::collections::BTreeMap<String, String>,
    cmdline: Option<Vec<String>>,
    sysfs: Option<Sysfs>,
    expected: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct Sysfs {
    state: String,
    ops: Option<String>,
}

/// Materialises a case's inputs in `dir`, the sysfs view included so
/// that the production reader (`kernel::read_at`) is what reads it,
/// and returns what [`detect`] makes of them.
fn detect_case(case: &Case, dir: &Path) -> Current {
    let fixtures = fixtures().join("detection");
    for (name, content) in &case.files {
        fs::write(dir.join(name), content).unwrap();
    }
    let unit = fs::read_to_string(fixtures.join("units").join(format!("{}.txt", case.unit)))
        .unwrap_or_else(|err| panic!("units/{}.txt: {err}", case.unit))
        .replace('@', &format!("{}/", dir.display()));
    let info = parse_unit_info(&unit);
    let manager = parse_manager_environment(&case.manager.join("\n"));
    let env = unit_environment(&info, manager);
    let process = case.cmdline.as_ref().map(|words| {
        let (argv0, args) = words.split_first().expect("cmdline names the executable");
        Process {
            sched: scx_catalog::catalog::sched_name(argv0),
            args: args.to_vec(),
        }
    });
    let sysfs = dir.join("sysfs");
    if let Some(s) = &case.sysfs {
        fs::create_dir_all(sysfs.join("root")).unwrap();
        fs::write(sysfs.join("state"), format!("{}\n", s.state)).unwrap();
        if let Some(ops) = &s.ops {
            fs::write(sysfs.join("root/ops"), format!("{ops}\n")).unwrap();
        }
    }
    let kernel = scx_catalog::kernel::read_at(&sysfs).unwrap();
    detect(&info, &env, process, kernel, verdict(&info))
}

#[test]
fn detection_fixtures_match_their_expected_output() {
    let detection = fixtures().join("detection");
    let scratch = tempfile::tempdir().unwrap();
    let mut cases: Vec<PathBuf> = fs::read_dir(&detection)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    cases.sort();
    assert!(cases.len() >= 10);
    for path in cases {
        let case: Case = serde_json::from_str(&fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        let dir = scratch.path().join(path.file_stem().unwrap());
        fs::create_dir_all(&dir).unwrap();
        let current = detect_case(&case, &dir);
        let got = serde_json::to_value(&current).unwrap();
        assert_eq!(
            got,
            case.expected,
            "{}\n got: {}",
            path.display(),
            serde_json::to_string_pretty(&got).unwrap()
        );
        // The output parses back into the same type, so a client written
        // against these types reads what scxcli prints.
        let parsed: Current = serde_json::from_value(got).unwrap();
        assert_eq!(parsed, current);
    }
}
