// SPDX-License-Identifier: GPL-2.0

//! The shared fixtures under `fixtures/`, the executable form of
//! `services/PROFILES.md`. Clients copy them to test their parsers
//! against the same inputs and outputs.
//!
//! `profiles/valid/*.json` must load and `profiles/invalid/*.json` must
//! not. Each `detection/*.json` is one system to detect the running
//! profile on, with the inputs shared between cases kept once:
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
//! - `profiles`: a list for this case, when it is not the shared
//!   `detection/profiles.json`;
//! - `expected`: what `scxcli get --json` prints.

use std::fs;
use std::path::{Path, PathBuf};

use scx_profiles::failure::verdict;
use scx_profiles::profile::Profiles;
use scx_profiles::state::{Current, detect};
use scx_profiles::systemd::{
    Process, parse_manager_environment, parse_unit_info, unit_environment,
};

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
fn valid_profile_files_load_and_round_trip() {
    for path in sorted_dir(&fixtures().join("profiles/valid")) {
        let text = fs::read_to_string(&path).unwrap();
        let profiles =
            Profiles::parse(&text).unwrap_or_else(|err| panic!("{}: {err:#}", path.display()));
        let again = Profiles::parse(&profiles.render().unwrap()).unwrap();
        assert_eq!(again, profiles, "{}", path.display());
    }
}

#[test]
fn invalid_profile_files_are_rejected() {
    for path in sorted_dir(&fixtures().join("profiles/invalid")) {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            Profiles::parse(&text).is_err(),
            "{} should not load",
            path.display()
        );
    }
}

#[test]
fn the_shipped_list_is_the_valid_fixture() {
    let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../services/profiles.json");
    let text = fs::read_to_string(&shipped).unwrap();
    Profiles::parse(&text).unwrap();
    let fixture = fs::read_to_string(fixtures().join("profiles/valid/shipped.json")).unwrap();
    assert_eq!(
        text, fixture,
        "fixtures/profiles/valid/shipped.json is a copy of services/profiles.json"
    );
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
    profiles: Option<Profiles>,
    expected: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct Sysfs {
    state: String,
    ops: Option<String>,
}

/// Materialises a case's inputs in `dir` and returns what [`detect`]
/// makes of them.
fn detect_case(case: &Case, shared: &Profiles, dir: &Path) -> Current {
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
            sched: scx_profiles::profile::sched_name(argv0),
            args: args.to_vec(),
        }
    });
    let kernel = case
        .sysfs
        .as_ref()
        .map(|s| scx_profiles::kernel::KernelState {
            state: s.state.clone(),
            ops: s.ops.clone(),
        });
    let profiles = case.profiles.as_ref().unwrap_or(shared);
    detect(profiles, &info, &env, process, kernel, verdict(&info))
}

#[test]
fn detection_fixtures_match_their_expected_output() {
    let detection = fixtures().join("detection");
    let shared =
        Profiles::parse(&fs::read_to_string(detection.join("profiles.json")).unwrap()).unwrap();
    let scratch = std::env::temp_dir().join(format!("scx_profiles-detect-{}", std::process::id()));
    let mut cases: Vec<PathBuf> = fs::read_dir(&detection)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "json")
                && p.file_name() != Some("profiles.json".as_ref())
        })
        .collect();
    cases.sort();
    assert!(cases.len() >= 10);
    for path in cases {
        let case: Case = serde_json::from_str(&fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        let dir = scratch.join(path.file_stem().unwrap());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let current = detect_case(&case, &shared, &dir);
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
    let _ = fs::remove_dir_all(&scratch);
}
