// SPDX-License-Identifier: GPL-2.0

//! Starting and stopping schedulers: the one path that changes what
//! `scx.service` runs. Everything here needs root.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::catalog::{self, Catalog, DEFAULT_ID, Recommendation, validate_arg, validate_name};
use crate::envfile::Launch;
use crate::systemd;

/// What [`start`] or [`run`] decided to write and do, for the caller's
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// What was asked for: a scheduler by name, a profile by id, or
    /// `default`.
    pub id: String,
    /// The resolved scheduler path and its options, or `None` for
    /// `default`, which stops the unit.
    pub launch: Option<(String, Vec<String>)>,
}

/// Starts `id`: `default`, a scheduler from `list all` with its own
/// defaults, or a custom profile from the installed catalog with the
/// options that catalog gives it. With the shipped policy this runs
/// without a password, so it takes only what the lists offer: a bare
/// name the catalog does not hide, resolved in systemd's default search
/// path, or a profile whose options an administrator wrote into the
/// trusted catalog. Any other options, and a hidden scheduler without
/// a profile, are `run`'s, as an administrator.
pub fn start(id: &str) -> Result<Started> {
    let loaded = catalog::load()?;
    start_from(&loaded.catalog, id)
}

pub fn start_from(catalog: &Catalog, id: &str) -> Result<Started> {
    let info = systemd::unit_info()?;
    if id != DEFAULT_ID {
        let started = plan(catalog, id, &systemd::system_binary_dirs()?)?;
        let (path, args) = started.launch.clone().expect("not default");
        launch(&info, Launch::Set(path, args))?;
        return Ok(started);
    }
    {
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
        // The unit is stopped and the configuration cleared, but the
        // kernel is the truth: a scheduler started outside scx.service
        // (from a shell, say) survives both, and Default has not
        // happened until the kernel's own scheduler runs.
        if let Some(ops) = still_attached()? {
            bail!(
                "scx.service is stopped and disabled, but the kernel still reports a \
scheduler attached (ops \"{ops}\"); it is not under scx.service's control, so stop its \
process to return to the kernel's scheduler"
            );
        }
        Ok(Started {
            id: DEFAULT_ID.to_owned(),
            launch: None,
        })
    }
}

/// What `start ID` would launch, for an `id` other than `default`,
/// resolved against `dirs` (systemd's search path): the decision
/// without the launch, so that it is tested on a scratch tree. A
/// custom profile's id comes first, since the catalog keeps the two
/// namespaces apart (a profile id never starts with `scx_`); anything
/// else is a scheduler name, which must be one `list all` shows. The
/// options of a profile are the catalog's, never the caller's: `start`
/// takes nothing but the id, and the catalog it reads is the trusted
/// one.
pub fn plan(catalog: &Catalog, id: &str, dirs: &[PathBuf]) -> Result<Started> {
    if let Some(profile) = catalog.get(id).filter(|p| p.is_custom()) {
        let (path, args) = profile_launch(profile, dirs)?;
        return Ok(Started {
            id: id.to_owned(),
            launch: Some((path, args)),
        });
    }
    validate_name(id).with_context(|| format!("{id:?} is not a profile in the catalog"))?;
    listed(catalog, id)?;
    let path = systemd::resolve_scheduler(id, dirs)?
        .to_string_lossy()
        .into_owned();
    Ok(Started {
        id: id.to_owned(),
        launch: Some((path, Vec::new())),
    })
}

/// A custom profile's command: its scheduler resolved in `dirs`, with
/// its options. Hidden is fine, that is what a profile is for; a tool
/// that is not a scheduler is not, with any authority.
fn profile_launch(profile: &Recommendation, dirs: &[PathBuf]) -> Result<(String, Vec<String>)> {
    let sched = profile
        .sched()
        .expect("a custom profile names its scheduler");
    if !systemd::is_scheduler_name(sched) {
        bail!(
            "profile {} names {sched}, which is not a scheduler",
            profile.id
        );
    }
    let path = systemd::resolve_scheduler(sched, dirs)
        .with_context(|| format!("profile {} cannot be started", profile.id))?;
    Ok((path.to_string_lossy().into_owned(), profile.args.clone()))
}

/// The ops name of a scheduler the kernel still reports attached after
/// the unit was stopped, or `None` once nothing is. A scheduler the
/// unit did run detaches as its process exits, which `systemctl stop`
/// waits for, but the kernel's view can trail that by a moment, so a
/// short wait tells "not yet" from "not ours". A kernel without
/// sched_ext has nothing attached.
fn still_attached() -> Result<Option<String>> {
    settle(
        || Ok(crate::kernel::read()?.and_then(|k| k.ops)),
        20,
        std::time::Duration::from_millis(50),
    )
}

/// Polls `read` up to `tries` times, `pause` apart, until it reports
/// nothing attached; what it reported last otherwise. Pure over the
/// reader, so the three outcomes are tested without a kernel.
fn settle(
    mut read: impl FnMut() -> Result<Option<String>>,
    tries: u32,
    pause: std::time::Duration,
) -> Result<Option<String>> {
    let mut last = None;
    for attempt in 0..tries {
        last = read()?;
        if last.is_none() {
            return Ok(None);
        }
        if attempt + 1 < tries {
            std::thread::sleep(pause);
        }
    }
    Ok(last)
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
    let resumed = resumable(&loaded.catalog, &env, &dirs)?;
    // What was validated is the executable `path`; what the unit's
    // shell would run is `SCX_SCHEDULER` as written, and a bare name in
    // it is looked up in the shell's own PATH, which a drop-in or an
    // environment file can point elsewhere. So the file is made to say
    // the path before the start, as `start ID` writes it, with the
    // options as they were; a file that already does is left alone.
    if resumed.pin {
        let launch = Launch::Set(resumed.path.clone(), resumed.args.clone());
        systemd::write_config(&info, &launch)
            .context("cannot pin the validated scheduler path before starting")?;
    }
    systemd::reset_failed();
    systemd::systemctl(&["start"])?;
    Ok(resumed.name)
}

/// What [`resumable`] found: the scheduler by name, the executable it
/// resolved to, the options the file holds, the custom profile those
/// match when they do, and whether the file names something other than
/// that path (a bare name, or a path spelled differently) and must be
/// rewritten to it before the unit starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resumable {
    pub name: String,
    pub path: String,
    pub args: Vec<String>,
    pub profile: Option<String>,
    pub pin: bool,
}

/// Whether the environment the unit would start with is one `start ID`
/// could have written, and which scheduler and executable:
/// `SCX_SCHEDULER` must resolve, against `dirs` (systemd's search
/// path) and through the same rules `start` and `run` use, to an
/// executable; no override may be in effect; the environment must have
/// resolved; and then either `SCX_FLAGS` is empty and the catalog does
/// not hide the scheduler, or the scheduler and the options are
/// exactly those of a custom profile in `catalog`, the trusted one,
/// which is what `start ID` would have written for it. Anything else
/// fails: options nobody wrote into the catalog, a hidden scheduler
/// without a profile, a scheduler off the search path, a profile whose
/// options changed since the selection. Starting those as root without
/// a password would run something nobody approved for that. `run` as
/// an administrator, or `start ID`, is the answer then, and the error
/// says which.
pub fn resumable(
    catalog: &Catalog,
    env: &systemd::UnitEnvironment,
    dirs: &[PathBuf],
) -> Result<Resumable> {
    use crate::envfile::{FLAGS_KEY, FLAGS_OVERRIDE_KEY, SCHEDULER_KEY, SCHEDULER_OVERRIDE_KEY};
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
    let args = canonical_flags(env.get(FLAGS_KEY).unwrap_or(""))?;
    // Through the one resolver start and run use: a value that is not
    // on the search path or not executable is refused here as it would
    // be there.
    let path = systemd::resolve_scheduler(configured, dirs).with_context(|| {
        format!("the configured scheduler {configured} cannot be started; use `start SCHED`")
    })?;
    let path = path.to_string_lossy().into_owned();
    let name = catalog::sched_name(&path);
    // A custom profile's command, exactly: the same executable and the
    // same options in the same order. That is what `start ID` wrote,
    // and what an administrator approved. The profile is matched on
    // what it resolves to now, so a profile whose scheduler went away
    // does not match, and a selection whose profile has since changed
    // is refused rather than started as something else.
    let profile = catalog
        .recommended
        .iter()
        .filter(|p| p.is_custom())
        .find(|p| profile_launch(p, dirs).is_ok_and(|(p, a)| p == path && a == args));
    if let Some(profile) = profile {
        return Ok(Resumable::of(
            name,
            configured,
            path,
            args,
            Some(profile.id.clone()),
        ));
    }
    if !args.is_empty() {
        bail!(
            "the configuration starts {configured} with options ({}) that no profile in the \
catalog has, which is not something that starts without a password; use `run` as an \
administrator, or `start ID` for a profile or a scheduler's own defaults",
            args.join(" ")
        );
    }
    listed(catalog, &name).context("the configured scheduler cannot be resumed")?;
    Ok(Resumable::of(name, configured, path, args, None))
}

/// The options in `SCX_FLAGS`, which must be in the one form `start`
/// and `run` write: words separated by single spaces, nothing around
/// them. The unit's shell splits the value on its own IFS, which is not
/// what [`split_flags`] (`split_whitespace`, Unicode) splits on: a
/// no-break space between two words is a separator to the one and part
/// of a word to the other, so a value this reader took for a profile's
/// two options could reach the scheduler as one. Rather than mirror
/// the shell, the resume path accepts only the form it knows the shell
/// reads as the words it sees; anything else is `start ID`'s to
/// rewrite. An empty value is no options.
fn canonical_flags(raw: &str) -> Result<Vec<String>> {
    use crate::envfile::split_flags;
    let args = split_flags(raw);
    if raw != args.join(" ") {
        bail!(
            "SCX_FLAGS is not in the form `start` writes (options separated by single spaces), \
so what the unit would run cannot be checked; use `start ID` to rewrite it"
        );
    }
    Ok(args)
}

impl Resumable {
    /// Pinned when the file says anything but the resolved path: a bare
    /// name, or a path spelled differently. A file that already holds
    /// the path, as `start` and `run` leave it, is not rewritten, which
    /// matters for a file an administrator made readable but not
    /// writable to this tool.
    fn of(
        name: String,
        configured: &str,
        path: String,
        args: Vec<String>,
        profile: Option<String>,
    ) -> Self {
        Resumable {
            name,
            pin: configured != path,
            path,
            args,
            profile,
        }
    }
}

/// Whether `name` is something `list all` would show, which is exactly
/// what the password-free `start NAME` may run: a scheduler by the
/// scan's own test (`scx_loader` and the other `scx_*` tools are not),
/// and not one the catalog hides. The listing applies the same two
/// tests, so the two cannot disagree on what is startable by name.
fn listed(catalog: &Catalog, name: &str) -> Result<()> {
    if !systemd::is_scheduler_name(name) {
        bail!("{name} is not a scheduler; `list all` does not offer it");
    }
    if catalog.is_hidden(name) {
        bail!(
            "{name} is not in the list: it needs a configuration of its own; start it with \
`run {name} ARGS...` as an administrator, or through a profile in the catalog"
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

    /// Cosmos recommended, layered hidden, and two custom profiles:
    /// `latency` on cosmos with options, `gaming` on hidden layered.
    fn catalog() -> Catalog {
        Catalog::parse(
            r#"{"version":2,"recommended":[
                {"id":"default","label":"Default"},
                {"id":"scx_cosmos","label":"Cosmos"},
                {"id":"latency","label":"Low latency","sched":"scx_cosmos",
                 "args":["--slice-us","1600"]},
                {"id":"gaming","label":"Gaming","sched":"scx_layered",
                 "args":["--run-example"]},
                {"id":"absent","label":"Absent","sched":"scx_rusty","args":["-v"]},
                {"id":"tool","label":"Tool","sched":"scx_loader","args":["-v"]}
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
        resumable(&catalog(), &env(vars), dirs).map(|r| r.name)
    }

    fn bin(dirs: &[PathBuf], name: &str) -> String {
        dirs[0].join(name).to_string_lossy().into_owned()
    }

    /// `start ID` with a profile id launches the profile's scheduler
    /// with the profile's options, hidden or not; with a scheduler name
    /// it is what it was. What `list` would not offer, `start` refuses.
    #[test]
    fn start_plans_profiles_and_names_and_refuses_the_rest() {
        let (_root, dirs) = dirs();
        let c = catalog();
        let latency = plan(&c, "latency", &dirs).unwrap();
        assert_eq!(
            latency,
            Started {
                id: "latency".into(),
                launch: Some((
                    bin(&dirs, "scx_cosmos"),
                    vec!["--slice-us".into(), "1600".into()]
                )),
            }
        );
        // A hidden scheduler starts through its profile, and only so.
        let gaming = plan(&c, "gaming", &dirs).unwrap();
        assert_eq!(
            gaming.launch,
            Some((bin(&dirs, "scx_layered"), vec!["--run-example".into()]))
        );
        let msg = format!("{:#}", plan(&c, "scx_layered", &dirs).unwrap_err());
        assert!(
            msg.contains("not in the list") && msg.contains("profile"),
            "{msg}"
        );
        // A name is a name: its own defaults, no options.
        assert_eq!(
            plan(&c, "scx_cosmos", &dirs).unwrap().launch,
            Some((bin(&dirs, "scx_cosmos"), Vec::new()))
        );
        assert_eq!(
            plan(&c, "scx_bpfland", &dirs).unwrap().launch,
            Some((bin(&dirs, "scx_bpfland"), Vec::new()))
        );
        for (id, what) in [
            ("absent", "cannot be started"),
            ("tool", "not a scheduler"),
            ("scx_loader", "not a scheduler"),
            ("scx_rusty", "not an executable"),
            ("nosuch", "not a profile"),
            ("Latency", "not a profile"),
        ] {
            let msg = format!("{:#}", plan(&c, id, &dirs).unwrap_err());
            assert!(msg.contains(what), "{id}: {msg}");
        }
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
        // A bare name is validated against systemd's search path, but
        // the unit's shell would look it up in its own PATH, so the
        // resolved path is to be pinned into the file first. A file
        // that already holds that path is left alone.
        let found = resumable(&catalog(), &env(&[("SCX_SCHEDULER", "scx_cosmos")]), &dirs).unwrap();
        let expected = bin(&dirs, "scx_cosmos");
        assert_eq!(
            found,
            Resumable {
                name: "scx_cosmos".into(),
                path: expected.clone(),
                args: Vec::new(),
                profile: None,
                pin: true
            }
        );
        // A file that already holds the resolved path is not rewritten.
        // The decision is taken on the strings; the production resolver
        // only takes absolute paths under /usr, which a scratch tree is
        // not, so the resolution step is covered above and the decision
        // here.
        let of = |configured: &str| {
            Resumable::of(
                "scx_cosmos".into(),
                configured,
                expected.clone(),
                Vec::new(),
                None,
            )
        };
        assert!(!of(&expected).pin);
        assert!(of("scx_cosmos").pin);
        assert!(of("/usr/bin/../bin/scx_cosmos").pin);
    }

    /// A configuration with options resumes only when it is exactly a
    /// custom profile's command: an administrator wrote those options
    /// into the trusted catalog, which is the approval the
    /// password-free start rests on. One option more, fewer or
    /// different, and it is a `run`.
    #[test]
    fn a_configuration_that_is_a_profiles_command_is_resumable() {
        let (_root, dirs) = dirs();
        let found = resumable(
            &catalog(),
            &env(&[
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_FLAGS", "--slice-us 1600"),
            ]),
            &dirs,
        )
        .unwrap();
        // A bare name in the file is pinned, with the options kept (the
        // scratch tree is not under /usr, so the file cannot hold the
        // resolved path here; `of` above covers that decision).
        assert_eq!(
            found,
            Resumable {
                name: "scx_cosmos".into(),
                path: bin(&dirs, "scx_cosmos"),
                args: vec!["--slice-us".into(), "1600".into()],
                profile: Some("latency".into()),
                pin: true
            }
        );
        // A hidden scheduler resumes through its profile, where by name
        // it would not.
        let found = resumable(
            &catalog(),
            &env(&[
                ("SCX_SCHEDULER", "scx_layered"),
                ("SCX_FLAGS", "--run-example"),
            ]),
            &dirs,
        )
        .unwrap();
        assert_eq!(found.profile.as_deref(), Some("gaming"));
        assert!(refused(&dirs, &[("SCX_SCHEDULER", "scx_layered")]).contains("not in the list"));
        // Not the profile's command: one option too many, too few, in
        // another order, or the profile edited since (the catalog now
        // says 1600 and the file says 2000).
        for flags in [
            "--slice-us 1600 -v",
            "--slice-us",
            "1600 --slice-us",
            "--slice-us 2000",
            "-v",
        ] {
            let msg = refused(
                &dirs,
                &[("SCX_SCHEDULER", "scx_cosmos"), ("SCX_FLAGS", flags)],
            );
            assert!(
                msg.contains("no profile") && msg.contains("run"),
                "{flags:?}: {msg}"
            );
        }
        // The profile's scheduler must still be what the file resolves
        // to: the `absent` profile names rusty, which is not installed.
        let msg = refused(
            &dirs,
            &[("SCX_SCHEDULER", "scx_bpfland"), ("SCX_FLAGS", "-v")],
        );
        assert!(msg.contains("no profile"), "{msg}");
    }

    /// The options are compared in the one form `start` writes. A
    /// value this reader splits into the profile's words but the unit's
    /// shell would not (a no-break space is whitespace to Rust and a
    /// character to bash's IFS), or the other way round, is refused
    /// rather than resumed as something the shell reads differently.
    #[test]
    fn flags_resume_only_in_the_form_start_writes() {
        let (_root, dirs) = dirs();
        assert_eq!(canonical_flags("").unwrap(), Vec::<String>::new());
        assert_eq!(
            canonical_flags("--slice-us 1600").unwrap(),
            ["--slice-us", "1600"]
        );
        for raw in [
            "--slice-us\u{a0}1600",
            "--slice-us\t1600",
            "--slice-us  1600",
            " --slice-us 1600",
            "--slice-us 1600 ",
            "--slice-us\n1600",
            " ",
            "\u{a0}",
        ] {
            let err = canonical_flags(raw).unwrap_err().to_string();
            assert!(err.contains("single spaces"), "{raw:?}: {err}");
            let msg = refused(
                &dirs,
                &[("SCX_SCHEDULER", "scx_cosmos"), ("SCX_FLAGS", raw)],
            );
            assert!(msg.contains("single spaces"), "{raw:?}: {msg}");
        }
        // The profile's own form resumes; the split is the shell's.
        let found = resumable(
            &catalog(),
            &env(&[
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_FLAGS", "--slice-us 1600"),
            ]),
            &dirs,
        )
        .unwrap();
        assert_eq!(found.profile.as_deref(), Some("latency"));
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

    #[test]
    fn settle_waits_for_a_detach_and_reports_what_stays() {
        use std::time::Duration;
        let no_wait = Duration::ZERO;
        // No sched_ext, or nothing attached: done at once.
        let mut calls = 0;
        let got = settle(
            || {
                calls += 1;
                Ok(None)
            },
            20,
            no_wait,
        )
        .unwrap();
        assert_eq!((got, calls), (None, 1));
        // Attached throughout: every try is used and the name comes back.
        let mut calls = 0;
        let got = settle(
            || {
                calls += 1;
                Ok(Some("rusty".to_owned()))
            },
            5,
            no_wait,
        )
        .unwrap();
        assert_eq!((got.as_deref(), calls), (Some("rusty"), 5));
        // Detaches on the third read: the wait pays off.
        let mut calls = 0;
        let got = settle(
            || {
                calls += 1;
                Ok((calls < 3).then(|| "cosmos".to_owned()))
            },
            20,
            no_wait,
        )
        .unwrap();
        assert_eq!((got, calls), (None, 3));
        // A read error is the caller's, not swallowed.
        assert!(settle(|| bail!("sysfs unreadable"), 3, no_wait).is_err());
    }
}
