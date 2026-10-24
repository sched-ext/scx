// SPDX-License-Identifier: GPL-2.0

//! The backend is `scxcli`: the one program that reads and changes the
//! profiles and `scx.service`. scxtui spawns it for everything, reads
//! its `--json` output for state, and runs the privileged commands
//! through `pkexec` when it is not root. The trait exists so the
//! application logic is exercised against an in-memory stub in tests,
//! not to support another backend.

pub mod scxcli;

use crate::model::{Listing, ProfilesFile};
use anyhow::Result;

/// What a write command printed, for the message bar.
pub type Report = String;

pub trait ProfileBackend {
    /// Short description for the header line.
    fn label(&self) -> String;

    /// `scxcli list --json`: the profiles, the installed schedulers and
    /// the current state in one round trip.
    fn list(&self) -> Result<Listing>;

    /// `scxcli apply ID`. Success means scxcli accepted it, not that
    /// the scheduler attached: callers read that back through
    /// [`Self::list`].
    fn apply(&self, id: &str) -> Result<Report>;

    /// `scxcli run SCHED ARGS...`.
    fn run(&self, sched: &str, args: &[String]) -> Result<Report>;

    /// `scxcli profiles save`, with the list on stdin.
    fn save(&self, profiles: &ProfilesFile) -> Result<Report>;

    /// `scxcli profiles reset`.
    fn reset(&self) -> Result<Report>;

    /// Whether the privileged commands go through `pkexec`, which may
    /// prompt on the terminal and so needs it handed over.
    fn escalates(&self) -> bool;
}
