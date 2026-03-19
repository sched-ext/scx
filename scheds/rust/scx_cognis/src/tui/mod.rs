// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only

pub mod dashboard;

pub use dashboard::{
    emergency_restore_terminal, new_shared_state, poll_tui_quit, restore_terminal, setup_terminal,
    tick_tui, SharedState, Term, WallEntry,
};
