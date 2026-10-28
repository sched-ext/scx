// SPDX-License-Identifier: GPL-2.0

//! The backend is `scxcli`, the one program that changes what
//! `scx.service` runs. scxtui spawns it for everything, reads its
//! `--json` output for state, and runs the privileged commands through
//! `pkexec` when it is not root. The trait exists so the application
//! logic is exercised against an in-memory stub in tests, not to
//! support another backend.

pub mod scxcli;

use crate::model::Listing;
use anyhow::Result;

/// What a write command printed, for the message bar.
pub type Report = String;

pub trait Backend {
    /// Short description for the header line.
    fn label(&self) -> String;

    /// `scxcli list --json`.
    fn list(&self) -> Result<Listing>;

    /// `scxcli start ID`: `default`, or a scheduler by name with its
    /// defaults. Returns scxcli's one-line report; the state comes
    /// back through [`Self::list`].
    fn start(&self, id: &str) -> Result<Report>;

    /// `scxcli run SCHED ARGS...`.
    fn run(&self, sched: &str, args: &[String]) -> Result<Report>;

    /// `scxcli stop`: the unit stops, the selection stays.
    fn stop(&self) -> Result<Report>;

    /// Whether the privileged commands go through `pkexec`, which may
    /// prompt on the terminal and so needs it handed over.
    fn escalates(&self) -> bool;
}
