// SPDX-License-Identifier: GPL-2.0

//! The sched_ext scheduler catalog, built on `scx.service`.
//!
//! The catalog says which schedulers scx recommends and which it keeps
//! out of the lists. This crate owns the catalog file: loading and
//! validating it, starting a scheduler from it by rewriting the unit's
//! environment file, and detecting which scheduler is running. The
//! contract it implements is `services/CATALOG.md`.
//!
//! `scxcli` is the crate's command-line front end and the interface
//! every other client uses. Nothing here starts a daemon or talks to
//! D-Bus: the configuration is the unit's `EnvironmentFile`, and the
//! truth about what runs is the kernel's.

#![deny(unsafe_code)]

pub mod catalog;
pub mod envfile;
pub mod failure;
mod files;
pub mod kernel;
pub mod listing;
pub mod start;
pub mod state;
pub mod systemd;

pub use catalog::{
    Catalog, DEFAULT_ID, FORMAT_VERSION, Loaded, Recommendation, Tier, is_customized, load,
    load_shipped,
};
pub use listing::{Installed, Listing, Pick, list};
pub use start::{Resumable, Started, installed, resumable, resume, run, start, stop};
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
        assert!(!permission_denied(&anyhow::anyhow!("no scheduler \"x\"")));
    }
}
