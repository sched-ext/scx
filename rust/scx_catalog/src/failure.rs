// SPDX-License-Identifier: GPL-2.0

//! Why the unit's last start failed.

use crate::state::Failure;
use crate::systemd::{UNIT, UnitInfo, system_command};

/// systemd's own verdict: `Some` when the unit is not active and its
/// last run did not end in success. Pure over the unit's properties.
pub fn verdict(info: &UnitInfo) -> Option<Failure> {
    if info.active || info.result.is_empty() || info.result == "success" {
        return None;
    }
    Some(Failure {
        message: format!("{UNIT} ended with result {}", info.result),
        status: format!("{}/{}", info.result, info.exec_main_status.unwrap_or(0)),
    })
}

/// The verdict with the scheduler's own last words from the current
/// boot's journal, when the journal can be read (a user outside
/// `systemd-journal` cannot, and then the verdict alone is the message).
pub fn failure_for(info: &UnitInfo) -> Option<Failure> {
    let mut failure = verdict(info)?;
    if let Some(tail) = journal_tail(info.invocation_id.as_deref()).filter(|m| !m.is_empty()) {
        failure.message = tail;
    }
    Some(failure)
}

/// The last lines the unit logged in this boot, from its last invocation
/// when systemd still knows its id.
fn journal_tail(invocation: Option<&str>) -> Option<String> {
    let mut cmd = system_command("journalctl").ok()?;
    cmd.args(["-b", "-u", UNIT, "-o", "cat", "-n", "5", "--no-pager", "-q"]);
    if let Some(id) = invocation {
        cmd.arg(format!("_SYSTEMD_INVOCATION_ID={id}"));
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_failed_last_run_is_a_failure() {
        let mut info = UnitInfo {
            result: "success".into(),
            ..UnitInfo::default()
        };
        assert_eq!(verdict(&info), None);
        info.result = "exit-code".into();
        info.exec_main_status = Some(1);
        info.active = true;
        assert_eq!(verdict(&info), None, "a running unit has no failure");
        info.active = false;
        let failure = verdict(&info).unwrap();
        assert_eq!(failure.status, "exit-code/1");
        assert!(failure.message.contains("exit-code"));
        info.result = "start-limit-hit".into();
        info.exec_main_status = None;
        assert_eq!(verdict(&info).unwrap().status, "start-limit-hit/0");
    }
}
