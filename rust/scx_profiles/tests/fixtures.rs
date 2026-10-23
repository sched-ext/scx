// SPDX-License-Identifier: GPL-2.0

//! The shared fixtures under `fixtures/`, the executable form of
//! `services/PROFILES.md`. Clients copy them to test their parsers
//! against the same inputs and outputs.
//!
//! `profiles/valid/*.json` must load and `profiles/invalid/*.json` must
//! not. Each `detection/*/` directory holds one system to detect the
//! running profile on: `unit.txt` (`systemctl show` output, with `@` in
//! `EnvironmentFiles=` standing for the directory), `manager.txt`
//! (`systemctl show-environment` output), the environment files named
//! by `unit.txt`, `cmdline.txt` (the unit's main process, one argv word
//! per line, absent when the unit has no process), `sysfs/` (a copy of
//! `/sys/kernel/sched_ext`, absent on a kernel without `sched_ext`),
//! `profiles.json`, and `expected.json`, what `scxcli get --json`
//! prints.

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

/// Reads one detection fixture into [`detect`]'s inputs and returns what
/// it detects.
fn detect_fixture(dir: &Path) -> Current {
    let read = |name: &str| {
        fs::read_to_string(dir.join(name))
            .unwrap_or_else(|err| panic!("{}/{name}: {err}", dir.display()))
    };
    let unit = read("unit.txt").replace('@', &format!("{}/", dir.display()));
    let info = parse_unit_info(&unit);
    let manager = parse_manager_environment(&read("manager.txt"));
    let env = unit_environment(&info, manager);
    let process = fs::read_to_string(dir.join("cmdline.txt"))
        .ok()
        .map(|text| {
            let mut words = text.lines().map(str::to_owned);
            let argv0 = words.next().expect("cmdline.txt names the executable");
            Process {
                sched: scx_profiles::profile::sched_name(&argv0),
                args: words.collect(),
            }
        });
    let kernel = scx_profiles::kernel::read_at(&dir.join("sysfs")).unwrap();
    let profiles = Profiles::parse(&read("profiles.json")).unwrap();
    detect(&profiles, &info, &env, process, kernel, verdict(&info))
}

#[test]
fn detection_fixtures_match_their_expected_output() {
    for dir in sorted_dir(&fixtures().join("detection")) {
        let current = detect_fixture(&dir);
        let got = serde_json::to_value(&current).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
        assert_eq!(
            got,
            expected,
            "{}\n got: {}",
            dir.display(),
            serde_json::to_string_pretty(&got).unwrap()
        );
        // The output parses back into the same type, so a client written
        // against these types reads what scxcli prints.
        let parsed: Current = serde_json::from_value(got).unwrap();
        assert_eq!(parsed, current);
    }
}
