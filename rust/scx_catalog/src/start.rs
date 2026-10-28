// SPDX-License-Identifier: GPL-2.0

//! Starting and stopping schedulers: the one path that changes what
//! `scx.service` runs. Everything here needs root.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::catalog::{self, Catalog, DEFAULT_ID, validate_arg, validate_name};
use crate::envfile::Launch;
use crate::systemd;

/// What [`start`] or [`run`] decided to write and do, for the caller's
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// The scheduler by name, or `default`.
    pub id: String,
    /// The resolved scheduler path and its options, or `None` for
    /// `default`, which stops the unit.
    pub launch: Option<(String, Vec<String>)>,
}

/// Starts `id`: `default`, or a scheduler from `list all`, with its own
/// defaults. With the shipped policy this runs without a password, so
/// it takes only what that list offers: a bare name the catalog does
/// not hide, resolved in systemd's default search path. A hidden
/// scheduler and any options are `run`'s, as an administrator.
pub fn start(id: &str) -> Result<Started> {
    let loaded = catalog::load()?;
    start_from(&loaded.catalog, id)
}

pub fn start_from(catalog: &Catalog, id: &str) -> Result<Started> {
    let info = systemd::unit_info()?;
    if id == DEFAULT_ID {
        // Stopping comes first and does not depend on the cleanup: the
        // point of Default is that no scheduler runs, and a
        // configuration that cannot be rewritten (a later file sets
        // the keys, say) must not leave one running. The cleanup then
        // writes both managed keys empty, which masks a scheduler set
        // in a lower layer (Environment= in the unit file or a
        // drop-in), and the environment is read back the way the unit
        // would, so that a later `systemctl start` by hand is known to
        // find no scheduler. If the stop fails the error says the unit
        // is already stopped.
        systemd::systemctl(&["disable", "--now"])?;
        let cleanup = systemd::write_config(&info, &Launch::Clear)
            .and_then(|()| systemd::clear_overrides())
            .and_then(|()| systemd::verify_cleared(&info));
        cleanup.context(
            "scx.service is stopped and disabled, but the configuration cleanup is \
incomplete; a start by hand may reuse the stale configuration or overrides",
        )?;
        return Ok(Started {
            id: DEFAULT_ID.to_owned(),
            launch: None,
        });
    }
    validate_name(id)?;
    listed(catalog, id)?;
    let path = systemd::resolve(id)?.to_string_lossy().into_owned();
    launch(&info, Launch::Set(path.clone(), Vec::new()))?;
    Ok(Started {
        id: id.to_owned(),
        launch: Some((path, Vec::new())),
    })
}

/// Stops the unit and nothing else: the selected scheduler stays in the
/// file, so `get` reports it as the next start, and the next boot or
/// [`resume`] brings it back. For a baseline measurement or a test,
/// where "no scheduler for now" is not "no scheduler".
pub fn stop() -> Result<()> {
    systemd::systemctl(&["stop"])
}

/// Starts the unit again after [`stop`], without a password with the
/// shipped policy. That is only sound when what the unit would run is
/// something [`start`] would have started without one: [`resumable`]
/// decides, and anything else is refused with the command that does it
/// with the right authority. Returns the scheduler's name.
pub fn resume() -> Result<String> {
    let loaded = catalog::load()?;
    let info = systemd::unit_info()?;
    let env = systemd::current_environment(&info);
    let dirs = systemd::system_binary_dirs()?;
    let name = resumable(&loaded.catalog, &env, &dirs)?;
    systemd::reset_failed();
    systemd::systemctl(&["start"])?;
    Ok(name)
}

/// Whether the environment the unit would start with is one `start
/// SCHED` could have written, and which scheduler that is:
/// `SCX_SCHEDULER` must resolve, against `dirs` (systemd's search
/// path) and through the same rules `start` and `run` use, to an
/// executable the catalog does not hide; `SCX_FLAGS` must be empty; no
/// override may be in effect; and the environment must have resolved.
/// Options, a hidden scheduler, and a scheduler off the search path all
/// fail: starting those as root without a password would run something
/// nobody approved for that. `run` as an administrator, or `start
/// SCHED`, is the answer then, and the error says which.
pub fn resumable(
    catalog: &Catalog,
    env: &systemd::UnitEnvironment,
    dirs: &[PathBuf],
) -> Result<String> {
    use crate::envfile::{
        FLAGS_KEY, FLAGS_OVERRIDE_KEY, SCHEDULER_KEY, SCHEDULER_OVERRIDE_KEY, split_flags,
    };
    if let Some(err) = &env.error {
        bail!(
            "the environment of {} could not be resolved ({err}); nothing started",
            systemd::UNIT
        );
    }
    if env.non_empty(SCHEDULER_OVERRIDE_KEY).is_some()
        || env.non_empty(FLAGS_OVERRIDE_KEY).is_some()
    {
        bail!(
            "an SCX_SCHEDULER_OVERRIDE or SCX_FLAGS_OVERRIDE is in effect, so a start would not \
run the selected scheduler; use `start SCHED`, which clears them"
        );
    }
    let Some(configured) = env.non_empty(SCHEDULER_KEY) else {
        bail!("no scheduler is selected; use `start SCHED` to choose one first");
    };
    let args = env.get(FLAGS_KEY).map(split_flags).unwrap_or_default();
    if !args.is_empty() {
        bail!(
            "the configuration starts {configured} with options ({}), which is not something \
that starts without a password; use `run` as an administrator, or `start SCHED` for the \
scheduler's own defaults",
            args.join(" ")
        );
    }
    // Through the one resolver start and run use: a value that is not
    // on the search path or not executable is refused here as it would
    // be there.
    let path = systemd::resolve_scheduler(configured, dirs).with_context(|| {
        format!("the configured scheduler {configured} cannot be started; use `start SCHED`")
    })?;
    let name = catalog::sched_name(&path.to_string_lossy());
    listed(catalog, &name).context("the configured scheduler cannot be resumed")?;
    Ok(name)
}

/// Whether `name` is something `list all` would show, which is exactly
/// what the password-free `start` may run: a scheduler by the scan's
/// own test (`scx_loader` and the other `scx_*` tools are not), and not
/// one the catalog hides. The listing applies the same two tests, so
/// the two cannot disagree on what is startable.
fn listed(catalog: &Catalog, name: &str) -> Result<()> {
    if !systemd::is_scheduler_name(name) {
        bail!("{name} is not a scheduler; `list all` does not offer it");
    }
    if catalog.is_hidden(name) {
        bail!(
            "{name} is not in the list: it needs a configuration of its own; start it with \
`run {name} ARGS...` as an administrator"
        );
    }
    Ok(())
}

/// The schedulers installed in systemd's default search path, each
/// with its resolved path, from the one scan `list` uses. Hidden ones
/// included; the caller filters.
pub fn installed() -> Result<Vec<(String, PathBuf)>> {
    Ok(systemd::scan_dirs_with_paths(systemd::system_binary_dirs()?))
}

/// Starts `sched` with `args`, whatever they are: the administrator's
/// path. A hidden scheduler is allowed, since this is where it gets
/// the configuration it needs.
pub fn run(sched: &str, args: &[String]) -> Result<Started> {
    for arg in args {
        validate_arg(arg)?;
    }
    // Hidden is fine here; a tool that is not a scheduler is not, with
    // any authority: scx.service exists to run schedulers.
    let name = catalog::sched_name(sched);
    if !systemd::is_scheduler_name(&name) {
        bail!("{name} is not a scheduler");
    }
    let path = systemd::resolve(sched)?.to_string_lossy().into_owned();
    let info = systemd::unit_info()?;
    launch(&info, Launch::Set(path.clone(), args.to_vec()))?;
    Ok(Started {
        id: catalog::sched_name(&path),
        launch: Some((path, args.to_vec())),
    })
}

fn launch(info: &systemd::UnitInfo, launch: Launch) -> Result<()> {
    systemd::write_config(info, &launch)?;
    systemd::clear_overrides()?;
    systemd::systemctl(&["enable"])?;
    systemd::reset_failed();
    systemd::systemctl(&["restart"])
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::systemd::UnitEnvironment;

    fn catalog() -> Catalog {
        Catalog::parse(
            r#"{"version":1,"recommended":[
                {"id":"default","label":"Default"},
                {"id":"scx_cosmos","label":"Cosmos"}
            ],"hidden":["scx_layered"]}"#,
        )
        .unwrap()
    }

    fn env(vars: &[(&str, &str)]) -> UnitEnvironment {
        let mut env = UnitEnvironment::default();
        for (k, v) in vars {
            env.vars.insert((*k).to_owned(), (*v).to_owned());
        }
        env
    }

    fn exe(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// A search path of one directory holding cosmos (recommended),
    /// bpfland (installed only) and layered (hidden).
    fn dirs() -> (tempfile::TempDir, Vec<PathBuf>) {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        for name in ["scx_cosmos", "scx_bpfland", "scx_layered", "scx_loader"] {
            exe(&bin, name);
        }
        let dirs = vec![bin];
        (root, dirs)
    }

    fn decide(dirs: &[PathBuf], vars: &[(&str, &str)]) -> Result<String> {
        resumable(&catalog(), &env(vars), dirs)
    }

    fn refused(dirs: &[PathBuf], vars: &[(&str, &str)]) -> String {
        format!("{:#}", decide(dirs, vars).unwrap_err())
    }

    #[test]
    fn a_listed_scheduler_without_options_is_resumable() {
        let (_root, dirs) = dirs();
        // Recommended or merely installed, flags empty or absent.
        for sched in ["scx_cosmos", "scx_bpfland"] {
            for flags in [Some(""), None] {
                let mut vars = vec![("SCX_SCHEDULER", sched)];
                if let Some(f) = flags {
                    vars.push(("SCX_FLAGS", f));
                }
                assert_eq!(decide(&dirs, &vars).unwrap(), sched);
            }
        }
    }

    #[test]
    fn options_hidden_and_unresolvable_schedulers_are_refused() {
        let (_root, dirs) = dirs();
        let msg = refused(
            &dirs,
            &[("SCX_SCHEDULER", "scx_cosmos"), ("SCX_FLAGS", "-v")],
        );
        assert!(msg.contains("options") && msg.contains("run"), "{msg}");
        let msg = refused(&dirs, &[("SCX_SCHEDULER", "scx_layered")]);
        assert!(msg.contains("not in the list"), "{msg}");
        // Installed, executable, scx_-prefixed, and still not a
        // scheduler: what the scan leaves out, start leaves out.
        let msg = refused(&dirs, &[("SCX_SCHEDULER", "scx_loader")]);
        assert!(msg.contains("not a scheduler"), "{msg}");
        let err = listed(&catalog(), "scx_loader").unwrap_err().to_string();
        assert!(err.contains("not a scheduler"), "{err}");
        listed(&catalog(), "scx_bpfland").unwrap();
        let msg = refused(&dirs, &[("SCX_SCHEDULER", "scx_rusty")]);
        assert!(msg.contains("cannot be started"), "{msg}");
        // A path: off the search path, or under a tree the path policy
        // refuses, is never resumed by its basename.
        for sched in ["/tmp/scx_cosmos", "/usr/local/bin/scx_cosmos"] {
            let msg = refused(&dirs, &[("SCX_SCHEDULER", sched)]);
            assert!(msg.contains("cannot be started"), "{sched}: {msg}");
        }
    }

    #[test]
    fn nothing_selected_overrides_and_errors_are_refused() {
        let (_root, dirs) = dirs();
        assert!(refused(&dirs, &[]).contains("no scheduler is selected"));
        assert!(refused(&dirs, &[("SCX_SCHEDULER", "")]).contains("no scheduler is selected"));
        let msg = refused(
            &dirs,
            &[
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_SCHEDULER_OVERRIDE", "scx_rusty"),
            ],
        );
        assert!(msg.contains("OVERRIDE"), "{msg}");
        let msg = refused(
            &dirs,
            &[
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_FLAGS_OVERRIDE", "-v"),
            ],
        );
        assert!(msg.contains("OVERRIDE"), "{msg}");
        let mut broken = env(&[("SCX_SCHEDULER", "scx_cosmos")]);
        broken.error = Some("x is unreadable".into());
        assert!(
            resumable(&catalog(), &broken, &dirs)
                .unwrap_err()
                .to_string()
                .contains("could not be resolved")
        );
    }
}
