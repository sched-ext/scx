// SPDX-License-Identifier: GPL-2.0

//! Atomic file replacement that keeps a file's identity: through a
//! scratch file in the same directory and a rename, so a failure midway
//! leaves the file as it was, with an existing file's owner, POSIX access
//! ACL and mode carried over. Lifted from scxtui, where the environment
//! file has been rewritten this way. And the trust rules for the
//! administrator's catalog.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Opens a configuration file for reading, telling a missing file
/// (`Ok(None)`) from a symlink whose target is missing, which is an
/// existing but broken configuration and an error: silently falling
/// back to the shipped catalog would replace what the administrator
/// set up.
///
/// With `no_dir_link`, a directory that is a symlink is refused before
/// the file is even looked for: with a dangling one the file would read
/// as absent and the broken configuration as none. That is for the
/// administrator's file; the shipped one may live behind a packaging
/// symlink.
pub(crate) fn open_config(path: &Path, no_dir_link: bool) -> Result<Option<fs::File>> {
    if no_dir_link
        && let Some(dir) = path.parent()
        && fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink())
    {
        bail!(
            "{} is a symlink; refusing to look for the catalog through it",
            dir.display()
        );
    }
    match fs::File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
                bail!(
                    "{} is a symlink whose target does not exist; fix or remove it",
                    path.display()
                );
            }
            Ok(None)
        }
        Err(err) => Err(err).with_context(|| format!("cannot open {}", path.display())),
    }
}

/// What the trust rules look at, taken from an inode. Gathered by
/// [`check_trusted`] and judged by [`judge`], so the rules are tested
/// without root or a real filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ident {
    pub uid: u32,
    /// The full `st_mode` permission bits, sticky included.
    pub mode: u32,
    pub symlink: bool,
}

impl Ident {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            uid: meta.uid(),
            mode: meta.permissions().mode() & 0o7777,
            symlink: meta.file_type().is_symlink(),
        }
    }
}

/// The rules: neither the directory nor the file may be a symlink,
/// both must be root's, and neither may be writable by group or
/// others, except a sticky world-writable directory, since others
/// cannot replace root's file in one. Pure over the identities, so a
/// test supplies them.
pub(crate) fn judge(dir: (&Path, Ident), file: (&Path, Ident)) -> Result<()> {
    let entries = [("directory", dir), ("file", file)];
    // Symlinks first, on both levels: that is the structural refusal,
    // reported before owner and mode whatever the order on disk.
    for (_, (p, ident)) in entries {
        if ident.symlink {
            bail!(
                "{} is a symlink; refusing to use the catalog in it",
                p.display()
            );
        }
    }
    for (what, (p, ident)) in entries {
        if ident.uid != 0 {
            bail!(
                "{} is owned by uid {}, not root; refusing to use the catalog in it",
                p.display(),
                ident.uid
            );
        }
        let sticky_ok = what == "directory" && ident.mode & 0o1000 != 0;
        if ident.mode & 0o022 != 0 && !sticky_ok {
            bail!(
                "{what} {} is writable by group or others (mode {:04o}); refusing to use the \
catalog in it",
                p.display(),
                ident.mode
            );
        }
    }
    Ok(())
}

fn lstat(path: &Path) -> Result<Ident> {
    fs::symlink_metadata(path)
        .map(|meta| Ident::of(&meta))
        .with_context(|| format!("cannot stat {}", path.display()))
}

/// Refuses a configuration file that someone other than root could have
/// written. For the catalog that `start` offers without a password,
/// such a file is not the administrator's.
///
/// The directory's metadata is read without following links. Whether
/// the path is a symlink is read the same way, and the file's owner
/// and mode come from the open handle, so it is the inode that is then
/// read, not whatever the path points at by then. See [`judge`] for
/// the rules.
pub(crate) fn check_trusted(path: &Path, file: &fs::File) -> Result<()> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    let mut ident = Ident::of(
        &file
            .metadata()
            .with_context(|| format!("cannot stat {}", path.display()))?,
    );
    ident.symlink = lstat(path)?.symlink;
    judge((dir, lstat(dir)?), (path, ident))
}

/// Replaces `path` with what `render` makes of its current contents. A
/// missing file renders from an empty string and is created with
/// [`NEW_FILE_MODE`] whatever the umask; an existing file keeps its
/// identity. Any other read failure aborts: rewriting a file whose
/// contents could not be read would silently drop everything in it. A
/// file that changes between the read and the rename is not
/// overwritten either.
pub(crate) fn rewrite_file(path: &Path, render: impl FnOnce(&str) -> Result<String>) -> Result<()> {
    let path = resolve_target(path)?;
    let original = read_or_absent(&path)?;
    let text = render(original.as_deref().unwrap_or(""))?;
    let existing = existing_metadata(&path)?;
    let mut tmp = scratch_file(&path, existing.is_some())?;
    tmp.write_all(text.as_bytes())
        .and_then(|()| tmp.as_file().sync_all())
        .with_context(|| format!("cannot write {}", tmp.path().display()))?;
    if let Some(meta) = &existing {
        carry_identity(&path, meta, &tmp)?;
    }
    if read_or_absent(&path)? != original {
        bail!(
            "{} changed while it was being rewritten; nothing written, retry",
            path.display()
        );
    }
    tmp.persist(&path)
        .map(drop)
        .with_context(|| format!("cannot move the new file into {}", path.display()))
}

fn read_or_absent(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| {
            format!(
                "cannot read {}; refusing to rewrite a file that could not be read",
                path.display()
            )
        }),
    }
}

/// The file behind a symlink, not the link: renaming over the link
/// would replace it with a regular file. A missing file is itself,
/// unless what is missing is the target of a link that is there.
fn resolve_target(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(real) => Ok(real),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
                bail!(
                    "{} is a symlink whose target does not exist; create the target first",
                    path.display()
                );
            }
            Ok(path.to_path_buf())
        }
        Err(err) => Err(err).with_context(|| format!("cannot resolve {}", path.display())),
    }
}

fn existing_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("cannot read the attributes of {}", path.display()))
        }
    }
}

/// The mode a file that did not exist before gets: readable by every
/// user, writable by the owner only. Set explicitly after creation,
/// so the caller's umask can neither widen it (a root process under
/// umask 000 must not leave a world-writable file whose contents run
/// as root) nor narrow it below what unprivileged reads need.
pub(crate) const NEW_FILE_MODE: u32 = 0o644;

/// A unique scratch file in `path`'s directory, so that the rename is
/// atomic within one filesystem and two writers never share one. It
/// stays 0600 while an existing file's identity is copied onto it; a
/// new file gets [`NEW_FILE_MODE`].
fn scratch_file(path: &Path, existing: bool) -> Result<tempfile::NamedTempFile> {
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    let tmp = tempfile::Builder::new()
        .prefix(".scx-catalog-")
        .tempfile_in(dir)
        .with_context(|| format!("cannot create a temporary file in {}", dir.display()))?;
    if !existing {
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(NEW_FILE_MODE))
            .with_context(|| format!("cannot set the mode of {}", tmp.path().display()))?;
    }
    Ok(tmp)
}

/// Owner, ACL, then mode, in that order, so that there is no window in
/// which the file is accessible to the wrong principals. Other xattrs
/// (a `security.selinux` label) are the new inode's, from the
/// directory's default labelling.
fn carry_identity(path: &Path, meta: &fs::Metadata, tmp: &tempfile::NamedTempFile) -> Result<()> {
    std::os::unix::fs::chown(tmp.path(), Some(meta.uid()), Some(meta.gid()))
        .with_context(|| format!("cannot preserve ownership of {}", path.display()))?;
    copy_access_acl(path, tmp.path())?;
    tmp.as_file()
        .set_permissions(meta.permissions())
        .with_context(|| format!("cannot preserve permissions from {}", path.display()))
}

const ACCESS_ACL: &str = "system.posix_acl_access";

/// Carries the original's POSIX access ACL over, or strips one the
/// replacement inherited from the directory's default ACL when the
/// original had none. A filesystem without xattrs has no ACLs to
/// preserve; std folds ENOTSUP into `ErrorKind::Unsupported`.
fn copy_access_acl(from: &Path, to: &Path) -> Result<()> {
    let not_supported = |err: &std::io::Error| err.kind() == ErrorKind::Unsupported;
    let acl = match xattr::get(from, ACCESS_ACL) {
        Ok(acl) => acl,
        Err(err) if not_supported(&err) => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("cannot read the ACL of {}", from.display()));
        }
    };
    match acl {
        Some(acl) => xattr::set(to, ACCESS_ACL, &acl)
            .with_context(|| format!("cannot preserve the ACL of {}", from.display())),
        None => match xattr::get(to, ACCESS_ACL) {
            Ok(Some(_)) => xattr::remove(to, ACCESS_ACL)
                .with_context(|| format!("cannot drop the inherited ACL of {}", to.display())),
            Ok(None) => Ok(()),
            Err(err) if not_supported(&err) => Ok(()),
            Err(err) => {
                Err(err).with_context(|| format!("cannot inspect the ACL of {}", to.display()))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("scx_catalog-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rewrite_sees_the_old_text_and_keeps_the_mode() {
        let dir = scratch_dir("rewrite");
        let path = dir.join("f");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        rewrite_file(&path, |old| Ok(format!("{old}new\n"))).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "old\nnew\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(
            fs::read_dir(&dir).unwrap().count() == 1,
            "no scratch file left"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The file this crate creates (the unit's environment file) comes
    /// out 0644 under umask 000 and 077 alike. The umask is process
    /// wide, so the check runs in a child process (this test
    /// re-executed by its full path) and the test process's umask is
    /// left alone. The child's output is checked for exactly one test
    /// run, so a wrong filter cannot pass as a green run.
    #[test]
    fn new_files_are_0644_whatever_the_umask() {
        const NAME: &str = "files::tests::new_files_are_0644_whatever_the_umask";
        if std::env::var_os("SCX_CATALOG_UMASK_CHILD").is_some() {
            let dir = scratch_dir(&format!("umask-{}", std::process::id()));
            let env = dir.join("scx");
            rewrite_file(&env, |old| {
                assert_eq!(old, "");
                Ok("SCX_SCHEDULER=x\n".into())
            })
            .unwrap();
            let mode = fs::metadata(&env).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, NEW_FILE_MODE, "{}", env.display());
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        for umask in ["000", "077"] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("umask {umask} && exec \"$0\" --exact {NAME}"))
                .arg(std::env::current_exe().unwrap())
                .env("SCX_CATALOG_UMASK_CHILD", "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("test result: ok. 1 passed"),
                "umask {umask}:\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// The rules, judged on identities a test supplies, so they run
    /// the same as any user.
    #[test]
    fn trust_rules_accept_root_owned_unwritable_entries_and_nothing_else() {
        let d = Path::new("/etc/scx");
        let f = Path::new("/etc/scx/catalog.json");
        let good_dir = Ident {
            uid: 0,
            mode: 0o755,
            symlink: false,
        };
        let good_file = Ident {
            uid: 0,
            mode: 0o644,
            symlink: false,
        };
        judge((d, good_dir), (f, good_file)).unwrap();
        let msg = |ident_dir, ident_file| {
            judge((d, ident_dir), (f, ident_file))
                .unwrap_err()
                .to_string()
        };
        assert!(
            msg(
                Ident {
                    symlink: true,
                    ..good_dir
                },
                good_file
            )
            .contains("symlink")
        );
        assert!(
            msg(
                good_dir,
                Ident {
                    symlink: true,
                    ..good_file
                }
            )
            .contains("symlink")
        );
        assert!(
            msg(
                Ident {
                    uid: 1000,
                    ..good_dir
                },
                good_file
            )
            .contains("not root")
        );
        assert!(
            msg(
                good_dir,
                Ident {
                    uid: 1000,
                    ..good_file
                }
            )
            .contains("not root")
        );
        assert!(
            msg(
                Ident {
                    mode: 0o775,
                    ..good_dir
                },
                good_file
            )
            .contains("writable")
        );
        assert!(
            msg(
                good_dir,
                Ident {
                    mode: 0o664,
                    ..good_file
                }
            )
            .contains("writable")
        );
        assert!(
            msg(
                good_dir,
                Ident {
                    mode: 0o646,
                    ..good_file
                }
            )
            .contains("writable")
        );
        // A sticky world-writable directory (like /tmp) is fine to read
        // root's file from, since others cannot replace it there.
        let sticky = Ident {
            mode: 0o1777,
            ..good_dir
        };
        judge((d, sticky), (f, good_file)).unwrap();
        // A symlink is reported before owner or mode, whichever the
        // other entry's state.
        assert!(
            msg(
                Ident {
                    uid: 1000,
                    ..good_dir
                },
                Ident {
                    symlink: true,
                    ..good_file
                }
            )
            .contains("symlink")
        );
    }

    /// The gathering side: what the checks read from the filesystem.
    /// Symlinks are detected without root; the owner rules are
    /// exercised through `judge` above, and here only as far as any
    /// user can see them (a scratch directory is the test user's, so
    /// as non-root the checks refuse it for that reason).
    #[test]
    fn trust_checks_read_symlinks_without_following_them() {
        let dir = scratch_dir("trust-fs");
        let file = dir.join("catalog.json");
        fs::write(&file, "{}").unwrap();
        let open = |path: &Path| fs::File::open(path).unwrap();

        let linked = dir.join("linked.json");
        std::os::unix::fs::symlink(&file, &linked).unwrap();
        assert!(
            check_trusted(&linked, &open(&linked))
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        let linked_dir = dir.join("linked-dir");
        std::os::unix::fs::symlink(&dir, &linked_dir).unwrap();
        let through = linked_dir.join("catalog.json");
        assert!(
            check_trusted(&through, &open(&through))
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );

        // A plain file in a plain directory is judged on owner and mode
        // alone: as root that passes, as any other user it is "not
        // root", never a symlink complaint.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let outcome = check_trusted(&file, &open(&file));
        if fs::metadata(&dir).unwrap().uid() == 0 {
            outcome.unwrap();
        } else {
            assert!(outcome.unwrap_err().to_string().contains("not root"));
        }

        // A missing file is "none", a dangling symlink an error, and so
        // is a directory that is a symlink, dangling or not.
        assert!(open_config(&dir.join("absent"), true).unwrap().is_none());
        let dangling = dir.join("dangling.json");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        assert!(
            open_config(&dangling, true)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        let dangling_dir = dir.join("dangling-dir");
        std::os::unix::fs::symlink(dir.join("no-such-dir"), &dangling_dir).unwrap();
        assert!(
            open_config(&dangling_dir.join("catalog.json"), true)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert!(
            open_config(&linked_dir.join("catalog.json"), true)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        // The shipped catalog may live behind a directory symlink.
        assert!(
            open_config(&linked_dir.join("catalog.json"), false)
                .unwrap()
                .is_some()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_is_rewritten_through_its_target() {
        let dir = scratch_dir("symlink");
        let target = dir.join("target");
        let link = dir.join("link");
        fs::write(&target, "a\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        rewrite_file(&link, |_| Ok("b\n".into())).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "b\n");

        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        assert!(rewrite_file(&dangling, |_| Ok("c\n".into())).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_concurrent_change_is_not_overwritten() {
        let dir = scratch_dir("race");
        let path = dir.join("f");
        fs::write(&path, "one\n").unwrap();
        let err = rewrite_file(&path, |_| {
            fs::write(&path, "two\n").unwrap();
            Ok("three\n".into())
        })
        .unwrap_err();
        assert!(err.to_string().contains("changed"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
