// SPDX-License-Identifier: GPL-2.0

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Read process membership from the host's unified cgroup hierarchy.
pub(crate) struct CgroupReader {
    mount_point: PathBuf,
}

impl CgroupReader {
    /// Locate the host cgroup v2 mount from mountinfo.
    pub(crate) fn discover() -> Result<Self> {
        let file = File::open("/proc/self/mountinfo").context("open /proc/self/mountinfo")?;
        let mount_point =
            parse_cgroup2_mount(BufReader::new(file))?.context("root cgroup v2 mount not found")?;
        Ok(Self { mount_point })
    }

    /// Return the exact, non-root cgroup directory for a process.
    pub(crate) fn process_cgroup(&self, tgid: u32) -> Result<Option<PathBuf>> {
        let path = format!("/proc/{tgid}/cgroup");
        let file = File::open(&path).with_context(|| format!("open {path}"))?;
        let cgroup_path = parse_process_cgroup(BufReader::new(file))?;
        let Some(relative) = relative_cgroup_path(&cgroup_path)? else {
            return Ok(None);
        };
        Ok(Some(self.mount_point.join(relative)))
    }

    /// Return all process IDs in an exact cgroup (not its descendants).
    pub(crate) fn processes(&self, cgroup: &Path) -> Result<HashSet<u32>> {
        let type_path = cgroup.join("cgroup.type");
        let cgroup_type = std::fs::read_to_string(&type_path)
            .with_context(|| format!("read {}", type_path.display()))?;
        if cgroup_type.trim_end() != "domain" {
            bail!(
                "cgroup {} is not an exact domain: unsupported cgroup type {:?}",
                cgroup.display(),
                cgroup_type.trim_end()
            );
        }

        let path = cgroup.join("cgroup.procs");
        let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        parse_cgroup_procs(BufReader::new(file))
    }
}

fn parse_process_cgroup(reader: impl BufRead) -> Result<PathBuf> {
    let mut unified = None;

    for line in reader.lines() {
        let line = line.context("read process cgroup entry")?;
        let Some(path) = line.strip_prefix("0::") else {
            continue;
        };
        if unified.is_some() {
            bail!("multiple cgroup v2 entries");
        }
        if path.ends_with(" (deleted)") {
            bail!("cgroup was deleted");
        }
        unified = Some(PathBuf::from(path));
    }

    unified.context("cgroup v2 entry not found")
}

fn relative_cgroup_path(path: &Path) -> Result<Option<PathBuf>> {
    if !path.is_absolute() {
        bail!("cgroup path is not absolute: {}", path.display());
    }
    let relative = path
        .strip_prefix(Path::new("/"))
        .context("strip cgroup root")?;
    if relative.as_os_str().is_empty() {
        return Ok(None);
    }
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("invalid cgroup path: {}", path.display());
    }
    Ok(Some(relative.to_path_buf()))
}

fn parse_cgroup_procs(reader: impl BufRead) -> Result<HashSet<u32>> {
    let mut processes = HashSet::new();

    for line in reader.lines() {
        let line = line.context("read cgroup.procs entry")?;
        let value = line.trim();
        if value.is_empty() {
            continue;
        }
        let tgid = value
            .parse::<u32>()
            .with_context(|| format!("invalid process ID in cgroup.procs: {value}"))?;
        if tgid == 0 {
            bail!("invalid process ID in cgroup.procs: 0");
        }
        processes.insert(tgid);
    }

    Ok(processes)
}

fn parse_cgroup2_mount(reader: impl BufRead) -> Result<Option<PathBuf>> {
    for line in reader.lines() {
        let line = line.context("read mountinfo entry")?;
        let Some((mount_fields, fs_fields)) = line.split_once(" - ") else {
            continue;
        };
        let mount_fields: Vec<_> = mount_fields.split_whitespace().collect();
        let mut fs_fields = fs_fields.split_whitespace();
        if mount_fields.len() < 5 || fs_fields.next() != Some("cgroup2") {
            continue;
        }
        // Require the hierarchy root so process cgroup paths resolve beneath
        // this mount without namespace-specific path translation.
        if mount_fields[3] != "/" {
            continue;
        }
        return Ok(Some(decode_mount_path(mount_fields[4])?));
    }

    Ok(None)
}

fn decode_mount_path(value: &str) -> Result<PathBuf> {
    let mut input = value.chars();
    let mut output = String::with_capacity(value.len());

    while let Some(character) = input.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }

        let mut digits = [0u16; 3];
        for digit in &mut digits {
            let Some(character @ '0'..='7') = input.next() else {
                bail!("invalid mountinfo path escape: {value}");
            };
            *digit = u16::from(character as u8 - b'0');
        }
        let decoded = (digits[0] << 6) | (digits[1] << 3) | digits[2];
        if decoded > u16::from(u8::MAX) {
            bail!("mountinfo path escape is out of range: {value}");
        }
        let decoded = decoded as u8;
        if !decoded.is_ascii() {
            bail!("non-ASCII mountinfo path escape is unsupported: {value}");
        }
        output.push(char::from(decoded));
    }

    Ok(PathBuf::from(output))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn parses_unified_cgroup_entry() {
        let input = b"7:cpu:/legacy\n0::/services/inference\n";
        assert_eq!(
            parse_process_cgroup(Cursor::new(input)).unwrap(),
            PathBuf::from("/services/inference")
        );
    }

    #[test]
    fn rejects_deleted_or_missing_cgroup() {
        assert!(parse_process_cgroup(Cursor::new(b"0::/gone (deleted)\n")).is_err());
        assert!(parse_process_cgroup(Cursor::new(b"7:cpu:/legacy\n")).is_err());
        assert!(parse_process_cgroup(Cursor::new(b"0::/one\n0::/two\n")).is_err());
    }

    #[test]
    fn rejects_root_and_unsafe_paths() {
        assert_eq!(relative_cgroup_path(Path::new("/")).unwrap(), None);
        assert!(relative_cgroup_path(Path::new("relative")).is_err());
        assert!(relative_cgroup_path(Path::new("/safe/../unsafe")).is_err());
    }

    #[test]
    fn parses_cgroup2_mount_and_escapes() {
        let input = b"10 1 0:1 / /old rw - cgroup cgroup rw\n\
                      39 30 0:33 / /sys/fs/cgroup\\040root rw - cgroup2 cgroup2 rw\n";
        assert_eq!(
            parse_cgroup2_mount(Cursor::new(input)).unwrap(),
            Some(PathBuf::from("/sys/fs/cgroup root"))
        );
    }

    #[test]
    fn decodes_utf8_mount_path() {
        assert_eq!(
            decode_mount_path("/sys/fs/cgroup-é\\040root").unwrap(),
            PathBuf::from("/sys/fs/cgroup-é root")
        );
        assert!(decode_mount_path("/sys/fs/cgroup\\377root").is_err());
    }

    #[test]
    fn ignores_non_root_cgroup2_mount() {
        let input = b"39 30 0:33 /slice /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        assert_eq!(parse_cgroup2_mount(Cursor::new(input)).unwrap(), None);
    }

    #[test]
    fn parses_and_deduplicates_cgroup_procs() {
        let input = b"10\n20\n10\n";
        assert_eq!(
            parse_cgroup_procs(Cursor::new(input)).unwrap(),
            HashSet::from([10, 20])
        );
        assert!(parse_cgroup_procs(Cursor::new(b"not-a-pid\n")).is_err());
    }
}
