// SPDX-License-Identifier: GPL-2.0

//! Which scheduler is running, by the rules of `services/CATALOG.md`.
//! [`detect`] is pure over its inputs so the rules are tested against
//! the shared fixtures; [`current`] gathers the inputs from the live
//! system.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::catalog::DEFAULT_ID;
use crate::envfile::{
    FLAGS_KEY, FLAGS_OVERRIDE_KEY, SCHEDULER_KEY, SCHEDULER_OVERRIDE_KEY, split_flags,
};
use crate::kernel::KernelState;
use crate::systemd::{Process, UnitEnvironment, UnitInfo};

/// The version of the JSON that `scxcli get --json` and `list --json`
/// print. Fields are only added within a version.
pub const OUTPUT_VERSION: u32 = 2;

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
    /// The scheduler in charge, when the unit and the kernel agree on
    /// it: the unit's process by name while the kernel reports it
    /// attached, or `default` while nothing is attached and the unit is
    /// inactive. Null while they disagree: the unit is active but
    /// nothing is attached yet, or something is attached that the unit
    /// did not start.
    pub scheduler: Option<String>,
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
    info: &UnitInfo,
    env: &UnitEnvironment,
    process: Option<Process>,
    kernel: Option<KernelState>,
    failure: Option<Failure>,
) -> Current {
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
    let scheduler = match live {
        Some(r) => Some(r.sched.clone()),
        None => (!attached && !info.active).then(|| DEFAULT_ID.to_owned()),
    };

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
        scheduler,
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
    let info = crate::systemd::unit_info()?;
    let env = crate::systemd::current_environment(&info);
    let process = info.main_pid.and_then(crate::systemd::read_process);
    let kernel = crate::kernel::read()?;
    let failure = crate::failure::failure_for(&info);
    Ok(detect(&info, &env, process, kernel, failure))
}

/// `sched` of `next` as a name, for display.
pub fn next_name(next: &Next) -> String {
    crate::catalog::sched_name(&next.sched)
}
