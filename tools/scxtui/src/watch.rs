// SPDX-License-Identifier: GPL-2.0

//! inotify on the files that decide the profiles and the next start:
//! the two profile files and the unit's environment file. Each is
//! replaced by a rename (scxcli writes through a scratch file), so the
//! watch is on the directories, for the names in question. A change
//! triggers one `scxcli list` on the next tick instead of a timer.
//!
//! The unit's state and the kernel's are not files inotify can watch,
//! so those keep the slow poll in the event loop.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchMask};

pub struct Watcher {
    inotify: Inotify,
    /// Watch descriptor -> the file names of interest in that directory.
    names: Vec<(inotify::WatchDescriptor, HashSet<OsString>)>,
    buffer: Vec<u8>,
}

impl Watcher {
    /// Watches the directories of `files`. A directory that does not
    /// exist yet (`/etc/scx` before the first `profiles save`) is
    /// skipped, and the periodic poll covers it.
    pub fn new(files: &[PathBuf]) -> Result<Self> {
        let inotify = Inotify::init().context("inotify init failed")?;
        let mut names: Vec<(inotify::WatchDescriptor, HashSet<OsString>)> = Vec::new();
        for file in files {
            let (Some(dir), Some(name)) = (file.parent(), file.file_name()) else {
                continue;
            };
            if !dir.is_dir() {
                continue;
            }
            match inotify.watches().add(
                dir,
                WatchMask::CLOSE_WRITE
                    | WatchMask::MOVED_TO
                    | WatchMask::CREATE
                    | WatchMask::DELETE,
            ) {
                Ok(wd) => match names.iter_mut().find(|(w, _)| *w == wd) {
                    Some((_, set)) => {
                        set.insert(name.to_owned());
                    }
                    None => {
                        names.push((wd, HashSet::from([name.to_owned()])));
                    }
                },
                Err(err) => {
                    return Err(err).with_context(|| format!("cannot watch {}", dir.display()));
                }
            }
        }
        Ok(Self {
            inotify,
            names,
            buffer: vec![0; 4096],
        })
    }

    /// Whether any watched file changed since the last call. Never
    /// blocks.
    pub fn changed(&mut self) -> bool {
        let Ok(events) = self.inotify.read_events(&mut self.buffer) else {
            return false;
        };
        let mut changed = false;
        for event in events {
            if event.mask.contains(EventMask::Q_OVERFLOW) {
                changed = true;
                continue;
            }
            let Some(name) = event.name else { continue };
            if self
                .names
                .iter()
                .any(|(wd, set)| *wd == event.wd && set.contains(name))
            {
                changed = true;
            }
        }
        changed
    }

    /// The files worth watching for a listing.
    pub fn files_for(config: Option<&Path>) -> Vec<PathBuf> {
        let mut files = vec![
            PathBuf::from(crate::model::ADMIN_PATH),
            PathBuf::from(crate::model::SHIPPED_PATH),
        ];
        if let Some(config) = config {
            files.push(config.to_path_buf());
        }
        files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn a_rename_into_a_watched_name_is_a_change_and_other_names_are_not() {
        let dir = std::env::temp_dir().join(format!("scxtui-watch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("profiles.json");
        let mut watcher = Watcher::new(&[file.clone(), dir.join("missing-dir").join("x")]).unwrap();
        assert!(!watcher.changed());

        fs::write(dir.join("other"), "x").unwrap();
        assert!(!watcher.changed(), "an unrelated file is ignored");

        let tmp = dir.join(".scratch");
        fs::write(&tmp, "{}").unwrap();
        fs::rename(&tmp, &file).unwrap();
        assert!(watcher.changed(), "a rename into place is seen");
        assert!(!watcher.changed(), "and reported once");

        fs::write(&file, "{ }").unwrap();
        assert!(watcher.changed(), "an in-place write is seen");
        let _ = fs::remove_dir_all(&dir);
    }
}
