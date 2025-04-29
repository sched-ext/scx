// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Vladislav Nepogodin <vnepogodin@cachyos.org>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::SchedMode;
use crate::SupportedSched;

#[zbus::proxy(
    interface = "org.scx.Loader",
    default_service = "org.scx.Loader",
    default_path = "/org/scx/Loader"
)]
pub trait LoaderClient {
    /// Starts the specified scheduler with the given mode.
    fn start_scheduler(&self, scx_name: SupportedSched, sched_mode: SchedMode) -> zbus::Result<()>;

    /// Starts the specified scheduler with the provided arguments.
    fn start_scheduler_with_args(
        &self,
        scx_name: SupportedSched,
        scx_args: &[String],
    ) -> zbus::Result<()>;

    /// Stops the currently running scheduler.
    fn stop_scheduler(&self) -> zbus::Result<()>;

    /// Method for switching to the specified scheduler with the given mode.
    /// This method will stop the currently running scheduler (if any) and
    /// then start the new scheduler.
    fn switch_scheduler(&self, scx_name: SupportedSched, sched_mode: SchedMode)
        -> zbus::Result<()>;

    /// Switches to the specified scheduler with the provided arguments. This
    /// method will stop the currently running scheduler (if any) and then
    /// start the new scheduler with the given arguments.
    fn switch_scheduler_with_args(
        &self,
        scx_name: SupportedSched,
        scx_args: &[String],
    ) -> zbus::Result<()>;

    /// The name of the currently running scheduler. If no scheduler is active,
    /// this property will be set to "unknown".
    #[zbus(property)]
    fn current_scheduler(&self) -> zbus::Result<String>;

    /// The currently active scheduler mode.  Scheduler modes allow you to
    /// apply pre-defined configurations to a scheduler that are
    /// optimized for different use cases. If no scheduler is active,
    /// this property will be set to 0 (Auto).
    #[zbus(property)]
    fn scheduler_mode(&self) -> zbus::Result<SchedMode>;

    /// A list of the schedulers currently supported by the Scheduler Loader.
    /// The names of the supported schedulers will be listed as strings in
    /// this array.
    #[zbus(property)]
    fn supported_schedulers(&self) -> zbus::Result<Vec<String>>;
}
