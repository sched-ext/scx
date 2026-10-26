// SPDX-License-Identifier: GPL-2.0

//! High-level scheduling profiles for sched_ext, built on `scx.service`.
//!
//! A profile names what the machine should do well and maps to a
//! scheduler and its options. This crate owns the profile file: loading
//! and validating it, applying a profile to the unit's environment file,
//! detecting which profile is running, and editing the list. The
//! contract it implements is `services/PROFILES.md`.
//!
//! `scxcli` is the crate's command-line front end and the interface
//! every other client uses. Nothing here starts a daemon or talks to
//! D-Bus: the configuration is the unit's `EnvironmentFile`, and the
//! truth about what runs is the kernel's.

#![deny(unsafe_code)]

pub mod apply;
pub mod envfile;
pub mod failure;
mod files;
pub mod kernel;
pub mod listing;
pub mod profile;
pub mod state;
pub mod systemd;

pub use apply::{Applied, apply, installed, resumable, run, start, stop, stop_and_forget};
pub use listing::{Entry, Listing, list, list_with_paths};
pub use profile::{
    Action, DEFAULT_ID, FORMAT_VERSION, Loaded, Profile, Profiles, is_customized, load,
    load_shipped, reset, save,
};
pub use state::{Current, Failure, Next, OUTPUT_VERSION, Running, Unit, current};

/// Whether an error is a lack of privileges rather than a failure: a
/// file that cannot be written or a `systemctl` verb that was refused.
/// Callers map it to their permission exit code.
pub fn permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
            || {
                let text = cause.to_string();
                text.contains("Permission denied")
                    || text.contains("Access denied")
                    || text.contains("Interactive authentication required")
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_errors_are_told_apart() {
        let io = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("cannot rewrite /etc/default/scx");
        assert!(permission_denied(&io));
        let polkit = anyhow::anyhow!(
            "systemctl restart scx.service failed: Interactive authentication required."
        );
        assert!(permission_denied(&polkit));
        assert!(!permission_denied(&anyhow::anyhow!("no profile \"x\"")));
    }
}
