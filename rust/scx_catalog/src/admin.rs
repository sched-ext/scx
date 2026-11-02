// SPDX-License-Identifier: GPL-2.0

//! The administrator's override, written and removed: the one path
//! that changes which profiles `start` offers without a password.
//! Everything here needs root.
//!
//! The override replaces the shipped catalog whole, so a client edits
//! the catalog in use (or the shipped one, to start a fresh copy) and
//! sends the whole file back. Nothing here merges, and nothing here
//! restarts a scheduler: a profile whose command changed is the
//! client's to start again, with `start ID`.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::catalog::{ADMIN_PATH, Catalog, Loaded, load, load_shipped};
use crate::files::{Ident, NEW_FILE_MODE, judge, lstat};

/// The most a catalog file may be: well past any real one, and short
/// of what an unattended `pkexec scxcli catalog save` should swallow
/// from a pipe.
pub const MAX_CATALOG_BYTES: usize = 64 * 1024;

/// The mode `/etc/scx` is created with when it is missing: root's,
/// readable by everyone, so that `list` as any user finds the override.
const DIR_MODE: u32 = 0o755;

/// The catalog in use, or the shipped one, rendered for a client to
/// edit and send back whole.
pub fn show(shipped: bool) -> Result<String> {
    let loaded: Loaded = if shipped { load_shipped()? } else { load()? };
    loaded.catalog.render()
}

/// Reads a catalog from `input`, at most [`MAX_CATALOG_BYTES`], and
/// returns its text once it parses: the administrator's rules, custom
/// profiles included, since this is the file they are allowed in. The
/// parse comes before any write, so a bad file changes nothing.
pub fn read_catalog(mut input: impl Read) -> Result<(Catalog, String)> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_CATALOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("cannot read the catalog from standard input")?;
    if bytes.len() > MAX_CATALOG_BYTES {
        bail!("the catalog is larger than {MAX_CATALOG_BYTES} bytes; refusing to save it");
    }
    let text = String::from_utf8(bytes).context("the catalog is not UTF-8")?;
    let catalog = Catalog::parse(&text)?;
    // Written as the crate renders it, not as it came: one layout for
    // every file this tool writes, and a round trip a client can rely
    // on.
    let text = catalog.render()?;
    Ok((catalog, text))
}

/// Writes `catalog` as the override, rendered here, so that what
/// reaches the file is a catalog that validated and nothing else.
/// Creates `/etc/scx` when it is missing; refuses a directory or file
/// that the write rules refuse, since writing root's catalog into a
/// place someone else controls would be handing them the password-free
/// `start`.
pub fn save(catalog: &Catalog) -> Result<()> {
    save_at(Path::new(ADMIN_PATH), catalog, true)
}

/// Removes the override, so the shipped catalog is in use again.
/// `Ok(false)` when there was none. A file that is a symlink is
/// removed as a link, which is the broken configuration it was; a
/// directory that is one is refused.
pub fn reset() -> Result<bool> {
    reset_at(Path::new(ADMIN_PATH))
}

/// The rules for writing into a directory, stricter than for reading
/// out of one. [`judge`] lets a sticky world-writable directory
/// through for a read, since nobody else can replace root's file in
/// one; but anybody can create an entry in one, a symlink under the
/// name about to be written included, between any check and the
/// write. So a directory written into is root's and writable by
/// nobody else, sticky or not.
pub(crate) fn judge_for_write(dir: &Path, ident: Ident) -> Result<()> {
    if ident.symlink {
        bail!(
            "{} is a symlink; refusing to write the catalog through it",
            dir.display()
        );
    }
    if ident.uid != 0 {
        bail!(
            "{} is owned by uid {}, not root; refusing to write the catalog into it",
            dir.display(),
            ident.uid
        );
    }
    if ident.mode & 0o022 != 0 {
        bail!(
            "{} is writable by group or others (mode {:04o}); refusing to write the catalog \
into it",
            dir.display(),
            ident.mode
        );
    }
    Ok(())
}

/// `trusted` applies the write rules to the directory and the file;
/// a test on a scratch tree, owned by whoever runs it, turns them off
/// and keeps the structural refusals, which do not depend on the
/// owner.
pub(crate) fn save_at(path: &Path, catalog: &Catalog, trusted: bool) -> Result<()> {
    // The fields are public, so a catalog that parsed can be one that
    // no longer validates by the time it gets here; the file holds
    // only what passes the rules, whoever built the value.
    catalog.validate().context("refusing to save the catalog")?;
    let text = catalog.render()?;
    let Some(dir) = path.parent() else {
        bail!("{} has no directory", path.display());
    };
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!(
                "{} is a symlink; refusing to write the catalog through it",
                dir.display()
            );
        }
        Ok(meta) if !meta.is_dir() => {
            bail!("{} is not a directory", dir.display());
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => create_dir(dir)?,
        Err(err) => return Err(err).with_context(|| format!("cannot stat {}", dir.display())),
    }
    let file = match fs::symlink_metadata(path) {
        Ok(meta) => Some(Ident::of(&meta)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).with_context(|| format!("cannot stat {}", path.display())),
    };
    if file.is_some_and(|f| f.symlink) {
        bail!(
            "{} is a symlink; refusing to write the catalog through it",
            path.display()
        );
    }
    if trusted {
        // The directory by the write rules; a file already there by
        // the read rules, so that one planted by someone else is not
        // replaced as if it were root's.
        let dir_ident = lstat(dir)?;
        judge_for_write(dir, dir_ident).context("refusing to save the catalog")?;
        if let Some(file) = file {
            judge((dir, dir_ident), (path, file)).context("refusing to save the catalog")?;
        }
    }
    write_catalog(dir, path, &text)
}

/// `/etc/scx`, made root's 0755 in two steps: created closed (0700,
/// which the umask cannot widen), then opened to the mode the reads
/// need, so there is no moment at which another user could put an
/// entry in it.
fn create_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
        .with_context(|| format!("cannot set the mode of {}", dir.display()))
}

/// The write itself: a scratch file in `dir`, [`NEW_FILE_MODE`],
/// filled, synced and renamed over `path`. No step follows a link:
/// the scratch file is created under a fresh name, and `rename`
/// replaces whatever directory entry `path` is, a symlink that
/// appeared since the check included, rather than writing through it.
/// The previous file's mode is not kept: what this tool installs is
/// readable by every user, since `list` as any user reads it.
fn write_catalog(dir: &Path, path: &Path, text: &str) -> Result<()> {
    let tmp = tempfile::Builder::new()
        .prefix(".scx-catalog-")
        .tempfile_in(dir)
        .with_context(|| format!("cannot create a temporary file in {}", dir.display()))?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(NEW_FILE_MODE))
        .with_context(|| format!("cannot set the mode of {}", tmp.path().display()))?;
    tmp.as_file()
        .write_all(text.as_bytes())
        .and_then(|()| tmp.as_file().sync_all())
        .with_context(|| format!("cannot write {}", tmp.path().display()))?;
    tmp.persist(path)
        .map(drop)
        .with_context(|| format!("cannot move the new file into {}", path.display()))?;
    // The rename is visible at once; this is what makes it durable,
    // so that a crash right after `catalog save` does not bring the
    // old file back.
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("cannot sync {}", dir.display()))
}

pub(crate) fn reset_at(path: &Path) -> Result<bool> {
    if let Some(dir) = path.parent()
        && fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink())
    {
        bail!(
            "{} is a symlink; refusing to remove the catalog through it",
            dir.display()
        );
    }
    match fs::remove_file(path) {
        Ok(()) => {
            // Durable the same way the save is: the removal is what
            // puts the shipped catalog back in use, and a crash right
            // after must not undo it.
            if let Some(dir) = path.parent() {
                fs::File::open(dir)
                    .and_then(|d| d.sync_all())
                    .with_context(|| format!("cannot sync {}", dir.display()))?;
            }
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("cannot remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(ids: &str) -> String {
        format!(r#"{{"version":2,"recommended":[{{"id":"default","label":"D"}}{ids}]}}"#)
    }

    const LATENCY: &str = r#",{"id":"latency","label":"L","sched":"scx_eevdf","args":["-v"]}"#;

    #[test]
    fn a_catalog_is_read_whole_parsed_and_rendered_before_any_write() {
        let (catalog, rendered) = read_catalog(text(LATENCY).as_bytes()).unwrap();
        assert!(catalog.has_custom_profiles());
        assert_eq!(rendered, catalog.render().unwrap());
        assert!(rendered.ends_with('\n'));
        for (what, bad) in [
            ("not json", "{".to_owned()),
            (
                "not a catalog",
                text(r#",{"id":"scx_x","label":"X","args":["-v"]}"#),
            ),
            ("too big", " ".repeat(MAX_CATALOG_BYTES) + &text("")),
        ] {
            assert!(read_catalog(bad.as_bytes()).is_err(), "{what}");
        }
        let err = read_catalog(&[0xff, 0xfe][..]).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err:#}");
        // Exactly the limit is fine; the refusal names the size.
        let padded = " ".repeat(MAX_CATALOG_BYTES - text("").len()) + &text("");
        assert_eq!(padded.len(), MAX_CATALOG_BYTES);
        read_catalog(padded.as_bytes()).unwrap();
        let err = read_catalog(vec![b' '; MAX_CATALOG_BYTES + 1].as_slice()).unwrap_err();
        assert!(err.to_string().contains("larger"), "{err:#}");
    }

    #[test]
    fn save_creates_the_directory_writes_0644_and_reset_removes_it() {
        let root = tempfile::tempdir().unwrap();
        let etc = root.path().join("scx");
        let path = etc.join("catalog.json");
        let (catalog, rendered) = read_catalog(text(LATENCY).as_bytes()).unwrap();
        save_at(&path, &catalog, false).unwrap();
        assert_eq!(
            fs::metadata(&etc).unwrap().permissions().mode() & 0o7777,
            DIR_MODE
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            NEW_FILE_MODE
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), rendered);
        // A second save replaces the file, and brings a file made
        // private back to the mode every user can read.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (plain_catalog, plain) = read_catalog(text("").as_bytes()).unwrap();
        save_at(&path, &plain_catalog, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), plain);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            NEW_FILE_MODE
        );
        assert!(
            fs::read_dir(&etc).unwrap().count() == 1,
            "no scratch file left"
        );
        // A value that parsed and was then made invalid is refused,
        // and the file on disk is left as it was.
        let (mut broken, _) = read_catalog(text(LATENCY).as_bytes()).unwrap();
        broken.recommended.clear();
        let err = save_at(&path, &broken, false).unwrap_err();
        assert!(format!("{err:#}").contains("empty"), "{err:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), plain);
        assert_eq!(fs::read_dir(&etc).unwrap().count(), 1);

        assert!(reset_at(&path).unwrap());
        assert!(!path.exists());
        assert!(
            !reset_at(&path).unwrap(),
            "nothing to remove is not an error"
        );
        assert!(etc.is_dir(), "the directory stays");
    }

    #[test]
    fn symlinks_are_refused_and_the_trust_rules_apply_to_what_is_there() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked = root.path().join("scx");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let through = linked.join("catalog.json");
        let (catalog, rendered) = read_catalog(text("").as_bytes()).unwrap();
        let err = save_at(&through, &catalog, false).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err:#}");
        let err = reset_at(&through).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err:#}");
        assert!(!real.join("catalog.json").exists());

        // The file as a symlink: not written through, but removed as
        // the link it is.
        let path = real.join("catalog.json");
        std::os::unix::fs::symlink(root.path().join("elsewhere.json"), &path).unwrap();
        let err = save_at(&path, &catalog, false).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err:#}");
        // A link that appears after the check and before the write is
        // what the write itself must survive: the rename replaces the
        // link as a directory entry and the target is untouched.
        let elsewhere = root.path().join("elsewhere.json");
        fs::write(&elsewhere, "theirs").unwrap();
        write_catalog(&real, &path, &rendered).unwrap();
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), rendered);
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "theirs");
        assert!(reset_at(&path).unwrap());
        assert!(fs::symlink_metadata(&path).is_err());

        // A directory in the way of the file's directory is an error,
        // not something to write into.
        let file_not_dir = root.path().join("file");
        fs::write(&file_not_dir, "").unwrap();
        let err = save_at(&file_not_dir.join("catalog.json"), &catalog, false).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err:#}");

        // With the trust rules on, a scratch tree owned by this user
        // (not root) is refused before anything is written, unless the
        // test runs as root, in which case the rules pass.
        let trusted = root.path().join("trusted");
        fs::create_dir(&trusted).unwrap();
        let result = save_at(&trusted.join("catalog.json"), &catalog, true);
        let uid = fs::metadata(&trusted).unwrap().uid();
        if uid == 0 {
            result.unwrap();
        } else {
            let err = result.unwrap_err();
            assert!(format!("{err:#}").contains("not root"), "{err:#}");
            assert!(!trusted.join("catalog.json").exists());
        }
    }

    /// The five commits as one cycle: an override with a profile is
    /// saved, read back, started by id, the configuration that start
    /// writes resumes as that profile, and once the profile's options
    /// change in a saved override the same configuration is refused.
    /// The override is read with `load_file`, since the trust rules
    /// want root's files and this runs as whoever runs the tests.
    #[test]
    fn a_profile_saved_started_and_resumed_is_refused_once_it_changes() {
        use std::os::unix::fs::PermissionsExt as _;

        use crate::catalog::load_file;
        use crate::start::{plan, resumable};
        use crate::systemd::UnitEnvironment;

        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let exe = bin.join("scx_eevdf");
        fs::write(&exe, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        let dirs = vec![bin];
        let path = root.path().join("etc").join("catalog.json");

        let profile = |args: &str| {
            format!(r#",{{"id":"latency","label":"L","sched":"scx_eevdf","args":[{args}]}}"#)
        };
        let (catalog, _) =
            read_catalog(text(&profile(r#""--slice-us","1600""#)).as_bytes()).unwrap();
        save_at(&path, &catalog, false).unwrap();
        let loaded = load_file(&path).unwrap();
        assert!(loaded.catalog.has_custom_profiles());

        // `start latency` decides from the saved override.
        let started = plan(&loaded.catalog, "latency", &dirs).unwrap();
        let (sched, args) = started.launch.clone().unwrap();
        assert_eq!(sched, exe.to_string_lossy());
        assert_eq!(args, ["--slice-us", "1600"]);

        // What start writes is what resume reads: the resolved path and
        // the options in the canonical form.
        let mut env = UnitEnvironment::default();
        env.vars.insert("SCX_SCHEDULER".into(), "scx_eevdf".into());
        env.vars.insert("SCX_FLAGS".into(), args.join(" "));
        let resumed = resumable(&loaded.catalog, &env, &dirs).unwrap();
        assert_eq!(resumed.profile.as_deref(), Some("latency"));
        assert_eq!(resumed.args, args);

        // The administrator changes the profile; the old configuration
        // is no longer anything the catalog approves.
        let (changed, _) =
            read_catalog(text(&profile(r#""--slice-us","3000""#)).as_bytes()).unwrap();
        save_at(&path, &changed, false).unwrap();
        let reloaded = load_file(&path).unwrap();
        let err = resumable(&reloaded.catalog, &env, &dirs).unwrap_err();
        assert!(format!("{err:#}").contains("no profile"), "{err:#}");
        // And `start latency` now means the new command.
        let again = plan(&reloaded.catalog, "latency", &dirs).unwrap();
        assert_eq!(again.launch.unwrap().1, ["--slice-us", "3000"]);

        // Reset: the override is gone and the profile with it.
        assert!(reset_at(&path).unwrap());
        assert!(load_file(&path).is_err());
    }

    /// Reading tolerates a sticky world-writable directory; writing
    /// into one does not, since anyone can add an entry there under
    /// the name about to be written.
    #[test]
    fn the_write_rules_refuse_what_the_read_rules_let_through() {
        let d = Path::new("/etc/scx");
        let ident = |mode, uid, symlink| Ident { uid, mode, symlink };
        let file = ident(0o644, 0, false);
        judge_for_write(d, ident(0o755, 0, false)).unwrap();
        judge_for_write(d, ident(0o700, 0, false)).unwrap();
        // Sticky and world-writable: a read trusts it, a write does not.
        judge(
            (d, ident(0o1777, 0, false)),
            (d.join("catalog.json").as_path(), file),
        )
        .unwrap();
        for (what, bad) in [
            ("sticky world-writable", ident(0o1777, 0, false)),
            ("group-writable", ident(0o775, 0, false)),
            ("not root's", ident(0o755, 1000, false)),
            ("a symlink", ident(0o755, 0, true)),
        ] {
            let err = judge_for_write(d, bad).unwrap_err().to_string();
            assert!(err.contains("refusing"), "{what}: {err}");
        }
    }

    use std::os::unix::fs::MetadataExt;
}
