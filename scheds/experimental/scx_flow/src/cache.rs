// SPDX-License-Identifier: GPL-2.0
//! Cache sizes of each CPU, read from sysfs.
//!
//! scx_utils reports which CPUs share a cache but folds the sizes into a
//! single per-CPU share, so the size of every level comes from the cache
//! directories the kernel exports for each CPU.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const SYSFS_CPU_DIR: &str = "/sys/devices/system/cpu";

/// Cache sizes seen by one CPU, in kibibytes. Zero means unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuCaches {
    pub l1d_kb: u32,
    pub l1i_kb: u32,
    pub l2_kb: u32,
    pub l3_kb: u32,
}

/// Size as sysfs prints it, such as "512K" or "16M", in kibibytes.
fn parse_size_kb(text: &str) -> Option<u32> {
    let text = text.trim();
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let value: u64 = text[..digits].parse().ok()?;
    let kb = match &text[digits..] {
        "K" => value,
        "M" => value * 1024,
        "G" => value * 1024 * 1024,
        "" => value.div_ceil(1024),
        _ => return None,
    };
    u32::try_from(kb).ok()
}

/// Read the cache sizes from one CPU's sysfs cache directory.
fn read_cache_dir(dir: &Path) -> CpuCaches {
    let mut caches = CpuCaches::default();
    let Ok(entries) = fs::read_dir(dir) else {
        return caches;
    };

    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("index") {
            continue;
        }
        let read = |name: &str| fs::read_to_string(entry.path().join(name)).ok();
        let (Some(level), Some(kind), Some(kb)) = (
            read("level"),
            read("type"),
            read("size").and_then(|s| parse_size_kb(&s)),
        ) else {
            continue;
        };
        match (level.trim(), kind.trim()) {
            ("1", "Data") => caches.l1d_kb = kb,
            ("1", "Instruction") => caches.l1i_kb = kb,
            ("2", _) => caches.l2_kb = kb,
            ("3", _) => caches.l3_kb = kb,
            _ => {}
        }
    }
    caches
}

/// Cache sizes of each of @cpus.
pub fn read_cpu_caches(cpus: impl Iterator<Item = usize>) -> BTreeMap<usize, CpuCaches> {
    cpus.map(|cpu| {
        let dir = Path::new(SYSFS_CPU_DIR).join(format!("cpu{cpu}/cache"));
        (cpu, read_cache_dir(&dir))
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sysfs-like cache directory with the given (level, type, size)
    /// entries, removed again when dropped.
    struct FakeCacheDir(std::path::PathBuf);

    impl FakeCacheDir {
        fn new(name: &str, entries: &[(&str, &str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!("scx_flow_{name}_{}", std::process::id()));
            for (i, (level, kind, size)) in entries.iter().enumerate() {
                let index = dir.join(format!("index{i}"));
                fs::create_dir_all(&index).unwrap();
                fs::write(index.join("level"), format!("{level}\n")).unwrap();
                fs::write(index.join("type"), format!("{kind}\n")).unwrap();
                fs::write(index.join("size"), format!("{size}\n")).unwrap();
            }
            Self(dir)
        }
    }

    impl Drop for FakeCacheDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sizes_parse_with_units() {
        assert_eq!(parse_size_kb("32K"), Some(32));
        assert_eq!(parse_size_kb("16384K\n"), Some(16384));
        assert_eq!(parse_size_kb("96M"), Some(98304));
        assert_eq!(parse_size_kb("1G"), Some(1048576));
        assert_eq!(parse_size_kb("1025"), Some(2));
        assert_eq!(parse_size_kb("1.5M"), None);
        assert_eq!(parse_size_kb("K"), None);
        assert_eq!(parse_size_kb(""), None);
    }

    #[test]
    fn levels_are_told_apart() {
        let dir = FakeCacheDir::new(
            "levels",
            &[
                ("1", "Data", "48K"),
                ("1", "Instruction", "32K"),
                ("2", "Unified", "1024K"),
                ("3", "Unified", "98304K"),
            ],
        );
        assert_eq!(
            read_cache_dir(&dir.0),
            CpuCaches {
                l1d_kb: 48,
                l1i_kb: 32,
                l2_kb: 1024,
                l3_kb: 98304,
            }
        );
    }

    #[test]
    fn missing_or_broken_entries_read_as_unknown() {
        let dir = FakeCacheDir::new(
            "broken",
            &[("2", "Unified", "lots"), ("3", "Unified", "8M")],
        );
        assert_eq!(
            read_cache_dir(&dir.0),
            CpuCaches {
                l3_kb: 8192,
                ..Default::default()
            }
        );
        assert_eq!(
            read_cache_dir(Path::new("/nonexistent/scx_flow")),
            CpuCaches::default()
        );
    }
}
