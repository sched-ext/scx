// SPDX-License-Identifier: GPL-2.0

//! Which profile is running, by the rules of `services/PROFILES.md`.
//! [`detect`] is pure over its inputs so the rules are tested against
//! the shared fixtures; [`current`] gathers the inputs from the live
//! system.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::envfile::{
    FLAGS_KEY, FLAGS_OVERRIDE_KEY, PROFILE_KEY, SCHEDULER_KEY, SCHEDULER_OVERRIDE_KEY, split_flags,
};
use crate::kernel::KernelState;
use crate::profile::{DEFAULT_ID, Profiles, sched_name};
use crate::systemd::{Process, UnitEnvironment, UnitInfo};

/// The version of the JSON that `scxcli get --json` and `list --json`
/// print. Fields are only added within a version.
pub const OUTPUT_VERSION: u32 = 1;

/// The unit's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    pub active: bool,
    pub enabled: bool,
}

/// What the unit runs now, from its main process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Running {
    pub sched: String,
    pub args: Vec<String>,
}

/// What the next start would run, resolved like the unit's `ExecStart`
/// does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Next {
    pub sched: String,
    pub args: Vec<String>,
    /// An `SCX_SCHEDULER_OVERRIDE` or `SCX_FLAGS_OVERRIDE` decided it.
    #[serde(rename = "override")]
    pub overridden: bool,
}

/// Why the unit's last start failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// The last lines the scheduler wrote to the journal, or systemd's
    /// own verdict when there are none.
    pub message: String,
    /// `Result/ExecMainStatus`, e.g. `exit-code/1`, `signal/9`,
    /// `start-limit-hit/0`.
    pub status: String,
}

/// The current state, as `scxcli get --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Current {
    pub version: u32,
    /// The profile that is running, when one is.
    pub profile: Option<String>,
    /// The profile the environment file says was applied.
    pub applied: Option<String>,
    /// A scheduler is attached that matches no profile.
    pub custom: bool,
    pub unit: Unit,
    pub running: Option<Running>,
    pub next: Option<Next>,
    pub kernel: Option<KernelState>,
    pub failure: Option<Failure>,
    /// The environment could not be fully resolved; `next` may be
    /// incomplete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_error: Option<String>,
}

impl Current {
    /// Whether a scheduler is attached at all.
    pub fn attached(&self) -> bool {
        self.kernel.as_ref().is_some_and(|k| k.ops.is_some())
    }
}

/// The rules. `process` is the unit's main process when the unit is
/// active and it could be read.
pub fn detect(
    profiles: &Profiles,
    info: &UnitInfo,
    env: &UnitEnvironment,
    process: Option<Process>,
    kernel: Option<KernelState>,
    failure: Option<Failure>,
) -> Current {
    let marker = env.non_empty(PROFILE_KEY);
    let applied = marker
        .filter(|id| profiles.get(id).is_some())
        .map(str::to_owned);
    // Only a file without any marker, written by an older tool, is
    // matched against the list by scheduler and options. A marker that
    // names no profile is never a reason to guess: `custom` is a
    // scheduler started on purpose outside the profiles, and any other
    // name is a profile that has since been deleted or renamed, whose
    // scheduler keeps running as Custom rather than as whichever
    // profile happens to share its command line.
    let unmatched_marker = marker.is_some() && applied.is_none();
    let running = process.filter(|_| info.active).map(|p| Running {
        sched: p.sched,
        args: p.args,
    });
    let attached = kernel.as_ref().is_some_and(|k| k.ops.is_some());
    // A scheduler is running when the unit's process is there and the
    // kernel agrees it is the one attached.
    let live = running
        .as_ref()
        .filter(|r| kernel.as_ref().is_some_and(|k| k.matches(&r.sched)));

    let profile = match live {
        Some(r) => match &applied {
            Some(id) => profiles
                .get(id)
                .filter(|p| p.sched_name().as_deref() == Some(r.sched.as_str()) && p.args == r.args)
                .map(|p| p.id.clone()),
            None if unmatched_marker => None,
            None => profiles.matching(&r.sched, &r.args).map(|p| p.id.clone()),
        },
        None => {
            let nothing_runs = !attached && !info.active;
            let applied_default = applied.as_deref().is_none_or(|id| id == DEFAULT_ID);
            (nothing_runs && applied_default).then(|| DEFAULT_ID.to_owned())
        }
    };
    let custom = attached && profile.is_none();

    let override_sched = env.non_empty(SCHEDULER_OVERRIDE_KEY);
    let override_flags = env.non_empty(FLAGS_OVERRIDE_KEY);
    let next = override_sched
        .or_else(|| env.non_empty(SCHEDULER_KEY))
        .map(|sched| Next {
            sched: sched.to_owned(),
            args: override_flags
                .or_else(|| env.get(FLAGS_KEY))
                .map(split_flags)
                .unwrap_or_default(),
            overridden: override_sched.is_some() || override_flags.is_some(),
        });

    Current {
        version: OUTPUT_VERSION,
        profile,
        applied,
        custom,
        unit: Unit {
            active: info.active,
            enabled: info.enabled,
        },
        running,
        next,
        kernel,
        failure,
        config_error: env.error.clone(),
    }
}

/// The current state of the live system.
pub fn current() -> Result<Current> {
    let loaded = crate::profile::load()?;
    current_with(&loaded.profiles)
}

pub fn current_with(profiles: &Profiles) -> Result<Current> {
    let info = crate::systemd::unit_info()?;
    let env = crate::systemd::current_environment(&info);
    let process = info.main_pid.and_then(crate::systemd::read_process);
    let kernel = crate::kernel::read()?;
    let failure = crate::failure::failure_for(&info);
    Ok(detect(profiles, &info, &env, process, kernel, failure))
}

/// `sched` of `next` as a name, for display.
pub fn next_name(next: &Next) -> String {
    sched_name(&next.sched)
}
