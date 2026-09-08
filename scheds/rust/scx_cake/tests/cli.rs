// SPDX-License-Identifier: GPL-2.0

use std::process::Command;

#[test]
fn obsolete_profiles_warn_and_reach_version_without_attaching() {
    for args in [
        vec!["--profile", "gaming"],
        vec!["--profile=performance"],
        vec!["-p", "powersave"],
        vec!["-pperformance"],
        vec!["-vpperformance"],
        vec!["--profile"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_scx_cake"))
            .args(&args)
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stdout.starts_with("scx_cake "), "{stdout}");
        assert!(stderr.contains("ignored unknown option"), "{stderr}");
        assert!(stderr.contains("defaults used"), "{stderr}");
    }
}

#[test]
fn ordinary_version_has_no_warnings() {
    let output = Command::new(env!("CARGO_BIN_EXE_scx_cake"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}

#[test]
fn help_still_succeeds_and_missing_toggle_value_still_fails() {
    for (flag, success) in [("--help", true), ("--toggle", false)] {
        let output = Command::new(env!("CARGO_BIN_EXE_scx_cake"))
            .args(["--profile", "gaming", flag])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), success, "{output:?}");
    }
}
