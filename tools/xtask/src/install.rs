// Copyright (c) 2026 Piotr Gorski
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! `xtask install`: put the data files the scheduling profiles need where
//! `services/PROFILES.md` says they go: the unit, its configuration, the
//! shipped profile list and the polkit policy.
//!
//! It copies those four files and nothing else. It installs no binaries
//! (a package does that; `cargo install` alone puts scxcli in
//! `~/.cargo/bin`, not where the policy names it), never builds, never calls
//! `systemctl`, and never touches a running unit, so it works in a
//! package build with `--destdir` as well as on a live machine.
//!
//! The runtime layout is not relocatable: `scx_profiles` reads
//! `/usr/share/scx/profiles.json`, the unit reads `/etc/default/scx`,
//! and scxtui expects scxcli at the path the policy names,
//! `/usr/bin/scxcli`. So those paths are fixed here too, and only the
//! directories that vary between distributions (the systemd unit
//! directory and the polkit actions directory) can be set. The policy is
//! installed verbatim; the install checks that every action in it still
//! names the fixed path, since a policy that named another path would
//! make every change in scxtui ask for a password.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use cargo_metadata::MetadataCommand;
use clap::Args;

/// Where the contract puts scxcli, and what every action in the policy
/// must name.
const SCXCLI_PATH: &str = "/usr/bin/scxcli";
/// `scx_profiles::profile::SHIPPED_PATH`.
const PROFILES_PATH: &str = "/usr/share/scx/profiles.json";
/// `EnvironmentFile=` of `services/scx.service`.
const CONFIG_PATH: &str = "/etc/default/scx";

const POLICY_PATH_KEY: &str = "org.freedesktop.policykit.exec.path\">";

#[derive(Args)]
pub struct InstallArgs {
    /// Staging root; every installed path is placed under it (DESTDIR)
    #[arg(long, value_name = "DIR")]
    destdir: Option<PathBuf>,

    /// Repository checkout to take the files from; without it the
    /// workspace root is asked of cargo (as `cargo metadata --no-deps`)
    #[arg(long, value_name = "DIR")]
    source_dir: Option<PathBuf>,

    /// Directory for the systemd unit
    #[arg(long, default_value = "/usr/lib/systemd/system", value_name = "DIR")]
    unitdir: PathBuf,

    /// Directory for the polkit policy
    #[arg(
        long,
        default_value = "/usr/share/polkit-1/actions",
        value_name = "DIR"
    )]
    polkitdir: PathBuf,
}

/// The files in the repository that get installed.
struct Sources {
    service: PathBuf,
    config: PathBuf,
    profiles: PathBuf,
    policy: PathBuf,
}

impl Sources {
    fn from_workspace(root: &Path) -> Self {
        Sources {
            service: root.join("services/scx.service"),
            config: root.join("services/scx"),
            profiles: root.join("services/profiles.json"),
            policy: root.join("tools/scxcli/org.sched_ext.scxcli.policy"),
        }
    }
}

/// The installed layout, as final paths (without DESTDIR).
struct Layout {
    unitdir: PathBuf,
    polkitdir: PathBuf,
}

impl Layout {
    fn from_args(a: &InstallArgs) -> Result<Self> {
        Ok(Layout {
            unitdir: checked_dir("--unitdir", &a.unitdir)?,
            polkitdir: checked_dir("--polkitdir", &a.polkitdir)?,
        })
    }
}

/// A directory the install writes under must be absolute and plain:
/// no `.` or `..`, so joining it under DESTDIR cannot leave DESTDIR,
/// and no empty segments. The string is checked, not the normalised
/// components, so `/usr/./lib` is refused as written rather than
/// silently cleaned.
fn checked_dir(flag: &str, dir: &Path) -> Result<PathBuf> {
    let s = dir
        .to_str()
        .with_context(|| format!("{flag} is not valid UTF-8"))?;
    let Some(rest) = s.strip_prefix('/') else {
        bail!("{flag} must be an absolute path, got {s}");
    };
    if rest
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        bail!("{flag} must not contain `.`, `..` or empty segments: {s}");
    }
    Ok(dir.to_path_buf())
}

/// One file to write: its contents, read up front, its final path and
/// its mode.
#[derive(Debug)]
struct Item {
    data: Vec<u8>,
    dst: PathBuf,
    mode: u32,
    /// On a live system the file is the administrator's once it exists
    /// and is left alone. Under DESTDIR it is the package's file.
    keep_existing: bool,
}

pub fn install_command(args: InstallArgs) -> Result<()> {
    let root = match &args.source_dir {
        Some(d) => d.clone(),
        // --no-deps: the install phase must not resolve or fetch
        // anything, only find the checkout. The shared metadata of the
        // other commands is not used, since it resolves dependencies.
        None => MetadataCommand::new()
            .no_deps()
            .exec()
            .context("finding the workspace root; pass --source-dir to install without cargo")?
            .workspace_root
            .into_std_path_buf(),
    };
    let sources = Sources::from_workspace(&root);
    let layout = Layout::from_args(&args)?;
    let items = prepare(&sources, &layout)?;
    write_all(&items, args.destdir.as_deref())
}

/// Reads every source and checks the policy before anything is written,
/// so a missing file or a wrong policy fails with nothing changed.
fn prepare(src: &Sources, layout: &Layout) -> Result<Vec<Item>> {
    let read = |p: &Path| fs::read(p).with_context(|| format!("reading {}", p.display()));

    let policy = read(&src.policy)?;
    check_policy(std::str::from_utf8(&policy).context("policy is not UTF-8")?)?;

    Ok(vec![
        Item {
            data: read(&src.service)?,
            dst: layout.unitdir.join("scx.service"),
            mode: 0o644,
            keep_existing: false,
        },
        Item {
            data: read(&src.config)?,
            dst: PathBuf::from(CONFIG_PATH),
            mode: 0o644,
            keep_existing: true,
        },
        Item {
            data: read(&src.profiles)?,
            dst: PathBuf::from(PROFILES_PATH),
            mode: 0o644,
            keep_existing: false,
        },
        Item {
            data: policy,
            dst: layout.polkitdir.join("org.sched_ext.scxcli.policy"),
            mode: 0o644,
            keep_existing: false,
        },
    ])
}

/// Every `<action>` in the policy must carry exactly one `exec.path`
/// annotation naming the fixed scxcli path, and there must be at least
/// one action. pkexec matches an action on that path, so an action
/// without one, or with another, is not covered by the contract.
fn check_policy(policy: &str) -> Result<()> {
    let mut actions = 0;
    for block in policy.split("<action ").skip(1) {
        actions += 1;
        let id = block
            .split_once("id=\"")
            .and_then(|(_, r)| r.split('"').next())
            .unwrap_or("?");
        let block = block.split("</action>").next().unwrap_or(block);
        let paths: Vec<&str> = block
            .split(POLICY_PATH_KEY)
            .skip(1)
            .map(|r| r.split('<').next().unwrap_or(""))
            .collect();
        match paths.as_slice() {
            [p] if *p == SCXCLI_PATH => {}
            [p] => bail!(
                "org.sched_ext.scxcli.policy: action {id} names {p}, the contract names {SCXCLI_PATH}"
            ),
            [] => bail!("org.sched_ext.scxcli.policy: action {id} names no scxcli path"),
            _ => bail!("org.sched_ext.scxcli.policy: action {id} names more than one path"),
        }
    }
    if actions == 0 {
        bail!("org.sched_ext.scxcli.policy declares no action");
    }
    Ok(())
}

fn write_all(items: &[Item], destdir: Option<&Path>) -> Result<()> {
    for item in items {
        let dst = match destdir {
            Some(d) => d.join(item.dst.strip_prefix("/").unwrap_or(&item.dst)),
            None => item.dst.clone(),
        };
        if item.keep_existing && destdir.is_none() && entry_exists(&dst)? {
            println!("kept    {} (exists)", dst.display());
            continue;
        }
        install_bytes(&item.data, &dst, item.mode)?;
        println!("install {} ({:o})", dst.display(), item.mode);
    }
    Ok(())
}

/// Whether anything is at the path: a file, a directory, or a symlink
/// whether or not its target exists. `Path::exists` follows the link and
/// would call a dangling one absent, and the rename would then replace
/// the administrator's link with a file.
fn entry_exists(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("checking {}", p.display())),
    }
}

/// Creates the missing directories of `dir`, each 0700 at creation and
/// widened to 0755 once it exists, so the mode does not depend on the
/// umask (`mkdir` applies it to the requested mode: under 077 a 0755
/// request yields 0700, and `scxcli list` as a user could not read
/// `/usr/share/scx`). Directories that already exist are left as they
/// are, whatever their mode: those are the administrator's.
fn ensure_dir(dir: &Path) -> Result<()> {
    let mut cur = PathBuf::new();
    for c in dir.components() {
        cur.push(c);
        if entry_exists(&cur)? {
            continue;
        }
        match fs::DirBuilder::new().mode(0o700).create(&cur) {
            Ok(()) => fs::set_permissions(&cur, fs::Permissions::from_mode(0o755))
                .with_context(|| format!("setting the mode of {}", cur.display()))?,
            // Another install, or anyone, got there first; it exists now.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("creating {}", cur.display())),
        }
    }
    Ok(())
}

/// Writes a fresh temporary file beside the target and renames it over
/// the target. The temporary is created with `create_new`, so it never
/// opens an existing file or follows a symlink, under a name unique to
/// this process and call, so two installs do not share it; it starts at
/// 0600 whatever the umask and gets its mode before the rename, so there
/// is no moment at which another user can write what root will install.
/// A failed write removes the temporary and leaves the old file whole.
fn install_bytes(data: &[u8], dst: &Path, mode: u32) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let parent = dst
        .parent()
        .with_context(|| format!("{} has no parent directory", dst.display()))?;
    ensure_dir(parent)?;

    let name = dst
        .file_name()
        .with_context(|| format!("{} has no file name", dst.display()))?;
    let tmp = parent.join(format!(
        ".{}.{}.{}.xtask-tmp",
        name.to_string_lossy(),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    // The open is outside the cleanup: a temporary that already exists
    // (a previous install interrupted, the pid reused) is not this
    // install's to remove, and create_new refuses it rather than
    // reusing it.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;

    let write = |f: &mut fs::File| -> Result<()> {
        f.write_all(data)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, dst)?;
        Ok(())
    };
    if let Err(e) = write(&mut f) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("installing {}", dst.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "<policyconfig>\n\
        <action id=\"org.sched_ext.scxcli.apply\">\n\
        <annotate key=\"org.freedesktop.policykit.exec.path\">/usr/bin/scxcli</annotate>\n\
        <annotate key=\"org.freedesktop.policykit.exec.argv1\">apply</annotate>\n\
        </action>\n\
        <action id=\"org.sched_ext.scxcli.run\">\n\
        <annotate key=\"org.freedesktop.policykit.exec.path\">/usr/bin/scxcli</annotate>\n\
        <annotate key=\"org.freedesktop.policykit.exec.argv1\">run</annotate>\n\
        </action>\n\
        </policyconfig>\n";

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "xtask-install-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn fixture(root: &Path) -> Sources {
        let w = |rel: &str, body: &str| -> PathBuf {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, body).unwrap();
            p
        };
        Sources {
            service: w("services/scx.service", "[Unit]\n"),
            config: w("services/scx", "SCX_SCHEDULER=scx_cosmos\n"),
            profiles: w("services/profiles.json", "{}\n"),
            policy: w("tools/scxcli/org.sched_ext.scxcli.policy", POLICY),
        }
    }

    fn default_layout() -> Layout {
        Layout::from_args(&InstallArgs {
            destdir: None,
            source_dir: None,
            unitdir: "/usr/lib/systemd/system".into(),
            polkitdir: "/usr/share/polkit-1/actions".into(),
        })
        .unwrap()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    const INSTALLED: [&str; 4] = [
        "usr/lib/systemd/system/scx.service",
        "etc/default/scx",
        "usr/share/scx/profiles.json",
        "usr/share/polkit-1/actions/org.sched_ext.scxcli.policy",
    ];

    fn no_tmp_left(root: &Path) -> bool {
        fn walk(d: &Path) -> bool {
            fs::read_dir(d).unwrap().all(|e| {
                let e = e.unwrap();
                let n = e.file_name().to_string_lossy().to_string();
                !n.ends_with(".xtask-tmp") && (!e.path().is_dir() || walk(&e.path()))
            })
        }
        walk(root)
    }

    #[test]
    fn installs_the_four_files_under_destdir_with_modes() {
        let root = scratch("destdir");
        let src = fixture(&root);
        let destdir = root.join("pkg");

        let items = prepare(&src, &default_layout()).unwrap();
        write_all(&items, Some(&destdir)).unwrap();

        for rel in INSTALLED {
            let p = destdir.join(rel);
            assert!(p.is_file(), "{rel} not installed");
            assert_eq!(mode(&p), 0o644, "{rel} mode");
        }
        assert_eq!(
            fs::read_to_string(destdir.join(INSTALLED[3])).unwrap(),
            POLICY
        );
        assert!(!destdir.join("usr/bin").exists(), "binaries installed");
        assert!(no_tmp_left(&destdir));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unit_and_policy_directories_can_move() {
        let root = scratch("dirs");
        let src = fixture(&root);
        let destdir = root.join("pkg");
        let layout = Layout::from_args(&InstallArgs {
            destdir: None,
            source_dir: None,
            unitdir: "/lib/systemd/system".into(),
            polkitdir: "/usr/local/share/polkit-1/actions".into(),
        })
        .unwrap();

        write_all(&prepare(&src, &layout).unwrap(), Some(&destdir)).unwrap();

        assert!(destdir.join("lib/systemd/system/scx.service").is_file());
        assert!(
            destdir
                .join("usr/local/share/polkit-1/actions/org.sched_ext.scxcli.policy")
                .is_file()
        );
        // The fixed paths do not move with them.
        assert!(destdir.join("etc/default/scx").is_file());
        assert!(destdir.join("usr/share/scx/profiles.json").is_file());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn directories_that_could_leave_destdir_are_refused() {
        for bad in [
            "relative/dir",
            "/usr/../etc",
            "/usr/./lib",
            "/../etc",
            "/usr//lib",
            "/",
        ] {
            assert!(
                checked_dir("--unitdir", Path::new(bad)).is_err(),
                "{bad} accepted"
            );
        }
        assert!(checked_dir("--unitdir", Path::new("/usr/lib/systemd/system")).is_ok());
    }

    #[test]
    fn a_missing_source_writes_nothing() {
        let root = scratch("missing");
        let src = fixture(&root);
        fs::remove_file(&src.profiles).unwrap();
        let destdir = root.join("pkg");

        let err = prepare(&src, &default_layout()).unwrap_err();

        assert!(err.to_string().contains("profiles.json"), "{err}");
        assert!(!destdir.exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_policy_naming_another_path_is_refused_before_any_write() {
        let root = scratch("policy");
        let src = fixture(&root);
        fs::write(
            &src.policy,
            POLICY.replacen("/usr/bin/scxcli", "/usr/local/bin/scxcli", 1),
        )
        .unwrap();

        let err = prepare(&src, &default_layout()).unwrap_err();

        assert!(err.to_string().contains("/usr/local/bin/scxcli"), "{err}");
        assert!(!root.join("pkg").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_policy_with_no_action_is_refused() {
        assert!(check_policy("<policyconfig/>\n").is_err());
        assert!(check_policy(POLICY).is_ok());
    }

    #[test]
    fn an_action_without_a_path_is_refused() {
        // The second action keeps its argv1 but loses its exec.path: a
        // policy that only counted annotations would pass it.
        let policy = POLICY.replacen(
            "<annotate key=\"org.freedesktop.policykit.exec.path\">/usr/bin/scxcli</annotate>\n\
             <annotate key=\"org.freedesktop.policykit.exec.argv1\">run</annotate>",
            "<annotate key=\"org.freedesktop.policykit.exec.argv1\">run</annotate>",
            1,
        );
        assert_ne!(policy, POLICY);
        let err = check_policy(&policy).unwrap_err();
        assert!(
            err.to_string().contains("org.sched_ext.scxcli.run"),
            "{err}"
        );
    }

    #[test]
    fn an_action_with_two_paths_is_refused() {
        let policy = POLICY.replacen(
            "<annotate key=\"org.freedesktop.policykit.exec.argv1\">apply</annotate>",
            "<annotate key=\"org.freedesktop.policykit.exec.path\">/usr/bin/scxcli</annotate>",
            1,
        );
        assert!(check_policy(&policy).is_err());
    }

    #[test]
    fn a_live_install_preserves_a_dangling_config_symlink() {
        let root = scratch("dangling");
        let src = fixture(&root);
        let sys = root.join("sys");
        let mut items = prepare(&src, &default_layout()).unwrap();
        for it in &mut items {
            it.dst = sys.join(it.dst.strip_prefix("/").unwrap());
        }
        let cfg = sys.join("etc/default/scx");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(sys.join("etc/scx/my-config"), &cfg).unwrap();
        assert!(!cfg.exists(), "the link must be dangling for this test");

        write_all(&items, None).unwrap();

        let md = fs::symlink_metadata(&cfg).unwrap();
        assert!(
            md.file_type().is_symlink(),
            "the link was replaced by a file"
        );
        assert!(!cfg.exists(), "the link was written through");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn existing_directories_keep_their_mode() {
        let root = scratch("dirmode");
        let private = root.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();

        ensure_dir(&private.join("new/deeper")).unwrap();

        assert_eq!(mode(&private), 0o700, "an existing directory was widened");
        assert_eq!(mode(&private.join("new")), 0o755);
        assert_eq!(mode(&private.join("new/deeper")), 0o755);
        fs::remove_dir_all(&root).unwrap();
    }

    /// Re-runs one test in a child under umask 077 and checks that the
    /// child ran exactly that test, so the mode is pinned down rather
    /// than inherited from whatever umask the suite happens to run with.
    #[test]
    fn new_directories_are_0755_under_umask_077() {
        if std::env::var_os("XTASK_UMASK_CHILD").is_some() {
            let root = scratch("umask");
            let dir = root.join("usr/share/scx");
            ensure_dir(&dir).unwrap();
            assert_eq!(mode(&dir), 0o755);
            assert_eq!(mode(&root.join("usr/share")), 0o755);
            fs::remove_dir_all(&root).unwrap();
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("umask 077 && exec \"$0\" --exact \"$1\" --nocapture")
            .arg(&exe)
            .arg("install::tests::new_directories_are_0755_under_umask_077")
            .env("XTASK_UMASK_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
    }

    #[test]
    fn a_live_install_keeps_an_existing_configuration() {
        let root = scratch("live");
        let src = fixture(&root);
        // A "live" system is simulated by rewriting the item paths under
        // the scratch directory, since the fixed paths are absolute.
        let sys = root.join("sys");
        let mut items = prepare(&src, &default_layout()).unwrap();
        for it in &mut items {
            it.dst = sys.join(it.dst.strip_prefix("/").unwrap());
        }
        let cfg = sys.join("etc/default/scx");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(&cfg, "SCX_SCHEDULER=scx_lavd\n").unwrap();

        write_all(&items, None).unwrap();

        assert_eq!(
            fs::read_to_string(&cfg).unwrap(),
            "SCX_SCHEDULER=scx_lavd\n"
        );
        assert!(sys.join("usr/lib/systemd/system/scx.service").is_file());
        assert!(sys.join("usr/share/scx/profiles.json").is_file());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_temporary_this_install_did_not_create_is_not_removed() {
        let root = scratch("stale-tmp");
        let dst = root.join("scx.service");
        // Every temporary of this process shares the pid; plant one for
        // every sequence number this call could take.
        let planted: Vec<PathBuf> = (0..64)
            .map(|n| root.join(format!(".scx.service.{}.{n}.xtask-tmp", std::process::id())))
            .collect();
        for p in &planted {
            fs::write(p, "stale").unwrap();
        }

        let err = install_bytes(b"[Unit]\n", &dst, 0o644).unwrap_err();

        assert!(err.to_string().contains("creating"), "{err}");
        assert!(!dst.exists());
        for p in &planted {
            assert_eq!(
                fs::read_to_string(p).unwrap(),
                "stale",
                "{} removed",
                p.display()
            );
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn concurrent_installs_into_one_destdir_both_finish() {
        let root = scratch("concurrent");
        let src = fixture(&root);
        let destdir = root.join("pkg");
        let items = std::sync::Arc::new(prepare(&src, &default_layout()).unwrap());

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let items = items.clone();
                let destdir = destdir.clone();
                std::thread::spawn(move || write_all(&items, Some(&destdir)))
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap();
        }

        for rel in INSTALLED {
            assert!(destdir.join(rel).is_file(), "{rel}");
        }
        assert!(no_tmp_left(&destdir));
        fs::remove_dir_all(&root).unwrap();
    }
}
