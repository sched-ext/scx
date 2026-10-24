// SPDX-License-Identifier: GPL-2.0

//! Applying a profile: the one path that changes what `scx.service`
//! runs. Everything here needs root.

use anyhow::{Context, Result, bail};

use crate::envfile::{CUSTOM_MARKER, Launch, Written};
use crate::profile::{self, Action, DEFAULT_ID, Profiles, validate_arg, validate_id};
use crate::systemd;

/// What [`apply`] decided to write and do, for the caller's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub id: String,
    /// The resolved scheduler path and its options, or `None` for a
    /// profile that stops the unit.
    pub launch: Option<(String, Vec<String>)>,
}

/// Applies the profile `id` from the list in use.
pub fn apply(id: &str) -> Result<Applied> {
    validate_id(id)?;
    let loaded = profile::load()?;
    apply_from(&loaded.profiles, id)
}

pub fn apply_from(profiles: &Profiles, id: &str) -> Result<Applied> {
    let Some(profile) = profiles.get(id) else {
        bail!("no profile {id:?}");
    };
    let info = systemd::unit_info()?;
    match (&profile.action, &profile.sched) {
        (Some(Action::Stop), _) => {
            // Stopping comes first and does not depend on the cleanup:
            // the point of Default is that no scheduler runs, and a
            // configuration that cannot be rewritten (a later file sets
            // the keys, say) must not leave one running. The cleanup
            // then removes every managed key, so a later `systemctl
            // start` by hand finds no scheduler to run; if it fails the
            // error says the unit is already stopped.
            systemd::systemctl(&["disable", "--now"])?;
            let cleanup = systemd::write_config(
                &info,
                &Written {
                    profile: None,
                    launch: Launch::Remove,
                },
            )
            .and_then(|()| systemd::clear_overrides());
            cleanup.context(
                "scx.service is stopped and disabled, but the configuration cleanup is \
incomplete; a start by hand may reuse the stale configuration or overrides",
            )?;
            Ok(Applied {
                id: profile.id.clone(),
                launch: None,
            })
        }
        (None, Some(sched)) => {
            let path = systemd::resolve(sched)
                .with_context(|| format!("profile {id:?} cannot be applied"))?;
            let path = path.to_string_lossy().into_owned();
            start(
                &info,
                Written {
                    profile: Some(profile.id.clone()),
                    launch: Launch::Set(path.clone(), profile.args.clone()),
                },
            )?;
            Ok(Applied {
                id: profile.id.clone(),
                launch: Some((path, profile.args.clone())),
            })
        }
        _ => bail!("profile {id:?} is invalid"),
    }
}

/// Applies `default`: stops the unit and marks the choice.
pub fn stop() -> Result<Applied> {
    apply(DEFAULT_ID)
}

/// Starts `sched` with `args` outside any profile. The marker is set to
/// the reserved `custom`, so every client reports Custom even when the
/// scheduler and options happen to equal a profile's.
pub fn run(sched: &str, args: &[String]) -> Result<Applied> {
    for arg in args {
        validate_arg(arg)?;
    }
    let path = systemd::resolve(sched)?.to_string_lossy().into_owned();
    let info = systemd::unit_info()?;
    start(
        &info,
        Written {
            profile: Some(CUSTOM_MARKER.to_owned()),
            launch: Launch::Set(path.clone(), args.to_vec()),
        },
    )?;
    Ok(Applied {
        id: String::new(),
        launch: Some((path, args.to_vec())),
    })
}

fn start(info: &systemd::UnitInfo, written: Written) -> Result<()> {
    systemd::write_config(info, &written)?;
    systemd::clear_overrides()?;
    systemd::systemctl(&["enable"])?;
    systemd::reset_failed();
    systemd::systemctl(&["restart"])
}
