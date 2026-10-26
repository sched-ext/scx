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
            launch(
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

/// Applies `default`: stops the unit and removes the choice.
pub fn stop_and_forget() -> Result<Applied> {
    apply(DEFAULT_ID)
}

/// Stops the unit and nothing else: the applied profile stays in the
/// file, so `get` reports it as applied but not running, and the next
/// boot or [`start`] brings it back. For a baseline measurement or a
/// test, where "no scheduler for now" is not "no scheduler".
pub fn stop() -> Result<()> {
    systemd::systemctl(&["stop"])
}

/// Starts the unit again after [`stop`], without a password with the
/// shipped policy. That is only sound when what the unit would run is
/// a profile the administrator approved, exactly as `apply ID` would
/// have written it: [`resumable`] decides, and anything else is
/// refused with the command that does it with the right authority.
pub fn start() -> Result<String> {
    let loaded = profile::load()?;
    let info = systemd::unit_info()?;
    let env = systemd::current_environment(&info);
    let dirs = systemd::system_binary_dirs()?;
    let id = resumable(&loaded.profiles, &env, &dirs)?;
    systemd::reset_failed();
    systemd::systemctl(&["start"])?;
    Ok(id)
}

/// Whether the environment the unit would start with is an approved
/// profile, and which. The file must name a profile in the list by
/// `SCX_PROFILE`; its `SCX_SCHEDULER` must resolve, against `dirs`
/// (systemd's search path), to the same executable the profile's
/// scheduler resolves to, and `SCX_FLAGS` must be the profile's
/// options; no override may be in effect, and the environment must
/// have resolved fully. The comparison is on resolved paths, never on
/// names: a file naming another executable with the profile's basename
/// (another directory on the path, or one off it) is not the profile.
/// A file without a marker, a `custom` marker, a deleted profile, or an
/// edit since the profile was applied all fail: starting those as root
/// without a password would run something nobody approved for that.
/// `apply ID` (password-free) or `run` (administrator) is the answer
/// then, and the error says which.
pub fn resumable(
    profiles: &Profiles,
    env: &systemd::UnitEnvironment,
    dirs: &[std::path::PathBuf],
) -> Result<String> {
    resumable_with(profiles, env, |sched| {
        systemd::resolve_scheduler(sched, dirs)
    })
}

/// [`resumable`] with the resolver supplied, so the comparison of
/// resolved executables is tested apart from the path policy the
/// production resolver enforces (which has tests of its own). Not part
/// of the API: the resolver is not a choice callers get to make.
fn resumable_with(
    profiles: &Profiles,
    env: &systemd::UnitEnvironment,
    resolve: impl Fn(&str) -> Result<std::path::PathBuf>,
) -> Result<String> {
    use crate::envfile::{
        CUSTOM_MARKER, FLAGS_KEY, FLAGS_OVERRIDE_KEY, PROFILE_KEY, SCHEDULER_KEY,
        SCHEDULER_OVERRIDE_KEY, split_flags,
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
run the applied profile; use `apply ID`, which clears them"
        );
    }
    let Some(marker) = env.non_empty(PROFILE_KEY) else {
        if env.non_empty(SCHEDULER_KEY).is_none() {
            bail!("nothing is applied; use `apply ID` to choose a profile first");
        }
        bail!(
            "the configuration names a scheduler but no profile, so it is not one that can be \
started without a password; use `apply ID`, or `run` as an administrator"
        );
    };
    if marker == CUSTOM_MARKER {
        bail!(
            "the configuration was started with `run`, outside any profile; starting it again \
takes `run` as an administrator, or `apply ID`"
        );
    }
    if marker == DEFAULT_ID {
        bail!("the applied profile is default, which runs no scheduler; use `apply ID`");
    }
    let Some(profile) = profiles.get(marker) else {
        bail!(
            "the applied profile {marker:?} is no longer in the list; use `apply ID` to choose \
one that is"
        );
    };
    let mismatch = || {
        anyhow::anyhow!(
            "the configuration no longer matches the applied profile {marker:?} (edited since \
it was applied); use `apply {marker}` to write it again"
        )
    };
    let args = env.get(FLAGS_KEY).map(split_flags).unwrap_or_default();
    if args != profile.args {
        return Err(mismatch());
    }
    let Some(configured) = env.non_empty(SCHEDULER_KEY) else {
        return Err(mismatch());
    };
    let Some(expected) = profile.sched.as_deref() else {
        return Err(mismatch());
    };
    // Both sides through the one resolver apply uses: a value that is
    // not on the search path, not executable, or a different file of
    // the same name is refused here as it would be there.
    let configured = resolve(configured).map_err(|_| mismatch())?;
    let expected =
        resolve(expected).with_context(|| format!("profile {marker:?} cannot be started"))?;
    if configured != expected {
        return Err(mismatch());
    }
    Ok(profile.id.clone())
}

/// The schedulers installed in systemd's default search path, each
/// with its resolved path, from the one scan `list` uses.
pub fn installed() -> Result<Vec<(String, std::path::PathBuf)>> {
    Ok(systemd::scan_dirs_with_paths(systemd::system_binary_dirs()?))
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
    launch(
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

fn launch(info: &systemd::UnitInfo, written: Written) -> Result<()> {
    systemd::write_config(info, &written)?;
    systemd::clear_overrides()?;
    systemd::systemctl(&["enable"])?;
    systemd::reset_failed();
    systemd::systemctl(&["restart"])
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::systemd::UnitEnvironment;

    fn profiles() -> Profiles {
        Profiles::parse(
            r#"{"version":2,"profiles":[
                {"id":"default","label":"Default","description":"Use the kernel's default scheduler.","action":"stop"},
                {"id":"gaming","label":"Gaming","sched":"scx_lavd","args":["--performance","--pinned-slice-us","500"]},
                {"id":"plain","label":"Plain","sched":"scx_cosmos"}
            ]}"#,
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

    /// A search path of two directories, both under /usr so the paths
    /// pass validation: `bin` holds scx_lavd and scx_cosmos, `local`
    /// holds another scx_lavd. The scratch root is under the test's
    /// temp dir, so the /usr prefix is only in the names resolve sees.
    struct Dirs {
        _root: tempfile::TempDir,
        bin: PathBuf,
        local: PathBuf,
    }

    fn exe(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("usr").join("bin");
        let local = root.path().join("usr").join("local").join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&local).unwrap();
        exe(&bin, "scx_lavd");
        exe(&bin, "scx_cosmos");
        exe(&local, "scx_lavd");
        Dirs {
            _root: root,
            bin,
            local,
        }
    }

    fn search(d: &Dirs) -> Vec<PathBuf> {
        vec![d.bin.clone(), d.local.clone()]
    }

    fn decide(d: &Dirs, vars: &[(&str, &str)]) -> Result<String> {
        resumable(&profiles(), &env(vars), &search(d))
    }

    fn refused(d: &Dirs, vars: &[(&str, &str)]) -> String {
        decide(d, vars).unwrap_err().to_string()
    }

    /// The resolver the production code uses, minus its path policy:
    /// a bare name is looked up in `dirs`, an absolute path must lie in
    /// one of `dirs` and be executable. That lets the comparison be
    /// tested with absolute paths under a scratch root, which the
    /// `/usr` rule of the production resolver would refuse; that rule
    /// has its own tests in `profile` and `systemd`.
    fn resolve_in(dirs: &[PathBuf]) -> impl Fn(&str) -> Result<PathBuf> + '_ {
        move |sched: &str| {
            let path = Path::new(sched);
            let is_exe = |p: &Path| {
                fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            };
            if path.is_absolute() {
                let dir = path.parent().unwrap();
                if dirs.iter().any(|d| d == dir) && is_exe(path) {
                    return Ok(path.to_path_buf());
                }
                bail!("{sched} is not on the search path");
            }
            dirs.iter()
                .map(|d| d.join(sched))
                .find(|p| is_exe(p))
                .ok_or_else(|| anyhow::anyhow!("{sched} not found"))
        }
    }

    fn gaming(sched: &str) -> Vec<(&'static str, String)> {
        vec![
            ("SCX_PROFILE", "gaming".to_owned()),
            ("SCX_SCHEDULER", sched.to_owned()),
            (
                "SCX_FLAGS",
                "--performance --pinned-slice-us 500".to_owned(),
            ),
        ]
    }

    fn with_resolver(d: &Dirs, vars: &[(&str, String)]) -> Result<String> {
        let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        resumable_with(&profiles(), &env(&vars), resolve_in(&search(d)))
    }

    #[test]
    fn a_profile_written_by_apply_is_resumable() {
        let d = dirs();
        // What apply writes: the absolute path the profile resolves to.
        let lavd = d.bin.join("scx_lavd");
        assert_eq!(
            with_resolver(&d, &gaming(lavd.to_str().unwrap())).unwrap(),
            "gaming"
        );
        // A bare name resolves to the same executable, through the
        // production resolver as well.
        assert_eq!(decide(&d, &gaming_bare()).unwrap(), "gaming");
        // A profile without options, flags key empty or absent.
        for flags in [Some(""), None] {
            let mut vars = vec![("SCX_PROFILE", "plain"), ("SCX_SCHEDULER", "scx_cosmos")];
            if let Some(f) = flags {
                vars.push(("SCX_FLAGS", f));
            }
            assert_eq!(decide(&d, &vars).unwrap(), "plain");
        }
    }

    fn gaming_bare() -> [(&'static str, &'static str); 3] {
        [
            ("SCX_PROFILE", "gaming"),
            ("SCX_SCHEDULER", "scx_lavd"),
            ("SCX_FLAGS", "--performance --pinned-slice-us 500"),
        ]
    }

    /// Two executables of the profile's basename, both on the search
    /// path, both valid as paths: the file naming the one the profile
    /// does not resolve to is refused. Only resolution tells them
    /// apart; the name is the same.
    #[test]
    fn a_different_executable_with_the_profiles_name_is_refused() {
        let d = dirs();
        let other = d.local.join("scx_lavd");
        let msg = with_resolver(&d, &gaming(other.to_str().unwrap()))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("no longer matches"), "{msg}");
        // With the search order reversed the profile resolves to that
        // very file, and the same configuration is then the profile.
        let reversed = vec![d.local.clone(), d.bin.clone()];
        let vars = gaming(other.to_str().unwrap());
        let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(
            resumable_with(&profiles(), &env(&vars), resolve_in(&reversed)).unwrap(),
            "gaming"
        );
        // A path to an executable in a directory off the search path.
        let off = d._root.path().join("opt");
        fs::create_dir_all(&off).unwrap();
        let stray = exe(&off, "scx_lavd");
        let msg = with_resolver(&d, &gaming(stray.to_str().unwrap()))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("no longer matches"), "{msg}");
    }

    /// Through the production resolver: paths its policy rejects, with
    /// the profile's basename, never pass as the profile.
    #[test]
    fn the_path_policy_applies_to_the_configured_scheduler_too() {
        let d = dirs();
        for sched in [
            "/tmp/scx_lavd",
            "/usr/local/bin/scx_lavd",
            "/usr/bin/../scx_lavd",
        ] {
            let vars = gaming(sched);
            let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let msg = resumable(&profiles(), &env(&vars), &search(&d))
                .unwrap_err()
                .to_string();
            assert!(msg.contains("no longer matches"), "{sched}: {msg}");
        }
    }

    #[test]
    fn nothing_applied_or_no_marker_is_refused() {
        let d = dirs();
        assert!(refused(&d, &[]).contains("nothing is applied"));
        // A hand-written file with a scheduler but no marker is exactly
        // what must not start as root without a password.
        assert!(refused(&d, &[("SCX_SCHEDULER", "scx_lavd")]).contains("no profile"));
    }

    #[test]
    fn an_edited_profile_is_refused() {
        let d = dirs();
        let msg = refused(
            &d,
            &[
                ("SCX_PROFILE", "gaming"),
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_FLAGS", "--performance --pinned-slice-us 500"),
            ],
        );
        assert!(msg.contains("no longer matches"), "{msg}");
        let msg = refused(
            &d,
            &[
                ("SCX_PROFILE", "gaming"),
                ("SCX_SCHEDULER", "scx_lavd"),
                ("SCX_FLAGS", "--performance --pinned-slice-us 500 --extra"),
            ],
        );
        assert!(msg.contains("no longer matches"), "{msg}");
    }

    #[test]
    fn custom_deleted_default_and_overrides_are_refused() {
        let d = dirs();
        assert!(
            refused(
                &d,
                &[("SCX_PROFILE", "custom"), ("SCX_SCHEDULER", "scx_lavd")]
            )
            .contains("run")
        );
        assert!(
            refused(
                &d,
                &[("SCX_PROFILE", "my-gaming"), ("SCX_SCHEDULER", "scx_lavd")]
            )
            .contains("no longer in the list")
        );
        assert!(refused(&d, &[("SCX_PROFILE", "default")]).contains("runs no scheduler"));
        let msg = refused(
            &d,
            &[
                ("SCX_PROFILE", "gaming"),
                ("SCX_SCHEDULER", "scx_lavd"),
                ("SCX_FLAGS", "--performance --pinned-slice-us 500"),
                ("SCX_SCHEDULER_OVERRIDE", "scx_rusty"),
            ],
        );
        assert!(msg.contains("OVERRIDE"), "{msg}");
        let mut broken = env(&[("SCX_PROFILE", "gaming")]);
        broken.error = Some("x is unreadable".into());
        assert!(
            resumable(&profiles(), &broken, &search(&d))
                .unwrap_err()
                .to_string()
                .contains("could not be resolved")
        );
    }
}
