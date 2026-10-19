// SPDX-License-Identifier: GPL-2.0

//! Scheduler-management backend.
//!
//! `scx.service` is the only backend: the systemd unit that runs the
//! scheduler named by `SCX_SCHEDULER` in its environment file. The trait
//! exists so the application logic can be exercised against an in-memory
//! stub in tests, not to support alternative daemons.

pub mod service;

use anyhow::Result;

/// The unit's main process as observed through `/proc`: what is actually
/// running, as opposed to what the configuration says will run next.
#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    /// Executable name (`argv[0]` basename), e.g. `scx_bpfland`.
    pub sched: String,
    /// `argv[1..]`.
    pub args: Vec<String>,
}

/// Snapshot of the scheduler state as reported by the backend. Two
/// questions are answered separately because they have separate sources
/// of truth: what runs now (the unit's process) and what the next start
/// would run (environment file plus manager-environment overrides). The
/// file can be edited under a running unit, so the two legitimately
/// differ until a restart.
// PartialEq: consumers act on a *change* between snapshots, never absolute values.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    /// Whether the unit is active.
    pub active: bool,
    /// The running scheduler process. `None` when the unit is inactive,
    /// or when it is active but `/proc` could not be read (the panel then
    /// says "active" without naming the scheduler, never a guess).
    pub process: Option<Process>,
    /// Scheduler the next start resolves to: the override when set, else
    /// `SCX_SCHEDULER` from the file.
    pub next_sched: Option<String>,
    /// Flags the next start resolves to, split the way the shell will.
    pub next_flags: Vec<String>,
    /// `SCX_SCHEDULER` from the environment file, if configured.
    pub configured: Option<String>,
    /// `SCX_SCHEDULER_OVERRIDE` in effect, from whichever layer of the
    /// unit's environment set it (manager environment, `Environment=`,
    /// or an environment file). The unit prefers it over `SCX_SCHEDULER`,
    /// so the status panel must say so.
    pub override_sched: Option<String>,
    /// `SCX_FLAGS_OVERRIDE` in effect, likewise. It replaces whatever a
    /// profile wrote to `SCX_FLAGS`.
    pub override_flags: Option<Vec<String>>,
    /// Why the next-start answer may be incomplete: an environment file
    /// the unit declares could not be read. Shown instead of silently
    /// reporting "nothing configured".
    pub config_error: Option<String>,
}

impl Status {
    /// Name of the running scheduler, when the unit is active and the
    /// process is known.
    pub fn running(&self) -> Option<&str> {
        if self.active {
            self.process.as_ref().map(|p| p.sched.as_str())
        } else {
            None
        }
    }
}

/// Common interface of the scheduler-management backend.
///
/// Scheduler names cross this boundary as plain strings (full names with the
/// `scx_` prefix), so the TUI never rejects a scheduler the backend knows.
pub trait SchedulerBackend {
    /// Short human-readable backend description for the header line.
    fn label(&self) -> String;

    fn status(&self) -> Result<Status>;

    fn supported_schedulers(&self) -> Result<Vec<String>>;

    /// Writes `sched` and `flags` to the environment file and starts the
    /// unit. Success means systemd accepted the start, not that the
    /// scheduler attached: callers observe that through [`Self::status`]
    /// and the kernel view.
    fn start(&self, sched: &str, flags: &[String]) -> Result<()>;

    /// Same as [`Self::start`], but restarts the unit so the change
    /// applies to a running service.
    fn switch(&self, sched: &str, flags: &[String]) -> Result<()>;

    fn stop(&self) -> Result<()>;

    fn restart(&self) -> Result<()>;
}
