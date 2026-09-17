// SPDX-License-Identifier: GPL-2.0
/*
 * Package energy reads
 *
 * Discovers the RAPL package zone by name, samples the energy
 * counter on the snapshot tick, and turns counter wraps into
 * plain joule deltas. Missing files yield fallback values with
 * no trap, so the scheduler keeps running with the probe parked
 * in the unavailable state.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use log::warn;

/* Powercap tree holding the energy zones. */
pub const DEFAULT_BASE: &str = "/sys/class/powercap";
/* Range used when the range file is missing. Holds the */
/* package range seen on the measured host in microjoules. */
pub const FALLBACK_MAX_RANGE_UJ: u64 = 65_532_610_987;
/* Pause between the two startup reads. Idle burn near 7 */
/* joules a second moves the counter well past any file */
/* granularity in this window, so a stuck counter stands out. */
pub const STARTUP_PAUSE: Duration = Duration::from_millis(100);

/* Read one sysfs file trimmed. Bad input yields nothing. */
fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/*
 * Join one zone name under the base dir. Accepts letters, digits, dash,
 * underscore, colon, and dot. Intel RAPL with index forms then pass.
 * Anything else yields nothing, so parent climbs, separators, and absolute
 * paths stay out with no trap.
 */
pub fn zone_path(base: &Path, zone: &str) -> Option<PathBuf> {
    if zone.is_empty() {
        return None;
    }
    if !zone
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.')
    {
        return None;
    }
    if zone == "." || zone == ".." || zone.contains("..") {
        return None;
    }
    Some(base.join(zone))
}

/*
 * Find the package zone under the base dir. Scans every entry and reads its
 * name file, so no index is assumed. The first entry whose name opens with
 * package wins in sorted order, so repeated scans agree. Core, uncore, and
 * nameless entries stay out. Nothing here reads the enabled file, since the
 * counter advances while enabled reads zero on the measured host.
 */
#[allow(dead_code)]
pub fn discover_package_zone(base: &Path) -> Option<PathBuf> {
    discover_package_zones(base).into_iter().next()
}

/*
 * Find all package zones under the base dir in sorted
 * order. Sums per zone deltas with per zone wrap, so
 * two package hosts count both with no bias. Single
 * package hosts return one entry with no behavior shift.
 * Links count as dirs, since sysfs entries are links.
 */
pub fn discover_package_zones(base: &Path) -> Vec<PathBuf> {
    let rd = match std::fs::read_dir(base) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = match zone_path(base, &name) {
            Some(v) => v,
            None => continue,
        };
        if std::fs::metadata(&dir).map(|m| m.is_dir()).unwrap_or(false) {
            names.push(name);
        }
    }
    names.sort();
    let mut out = Vec::new();
    for name in &names {
        let dir = base.join(name);
        let label = read_trimmed(&dir.join("name")).unwrap_or_default();
        if label.starts_with("package") {
            out.push(dir);
        }
    }
    out
}

/*
 * Range of one zone in microjoules. Missing and broken files yield the fallback
 * with a warn log, so the probe keeps honest deltas on hosts with odd firmware.
 */
pub fn read_max_range(zone: &Path) -> u64 {
    read_trimmed(&zone.join("max_energy_range_uj"))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or_else(|| {
            warn!("RAPL range unreadable, using fallback");
            FALLBACK_MAX_RANGE_UJ
        })
}

/* One raw counter read in microjoules. */
pub fn read_energy_uj(energy: &Path) -> Option<u64> {
    read_trimmed(energy)?.parse::<u64>().ok()
}

/*
 * Delta between two counter reads in microjoules. Equal reads yield zero. A
 * backward step is one wrap, so the delta is a modular single wrap correction
 * against the true max with the tail and the head. A delta past half the max
 * cannot come from one second of burn and marks the interval invalid with
 * nothing. Zero max yields nothing with no divide.
 */
pub fn energy_delta_uj(new: u64, old: u64, max_range: u64) -> Option<u64> {
    if max_range == 0 {
        return None;
    }
    let delta = if new >= old {
        new - old
    } else {
        (max_range - old).saturating_add(new)
    };
    if delta > max_range / 2 {
        return None;
    }
    Some(delta)
}

/*
 * True when the counter proves it moves. Needs two good reads with a positive
 * delta inside half the max, so a stuck file and a wild jump both fail the
 * check.
 */
pub fn increment_ok(first: Option<u64>, second: Option<u64>, max_range: u64) -> bool {
    match (first, second) {
        (Some(a), Some(b)) => energy_delta_uj(b, a, max_range).is_some_and(|d| d > 0),
        _ => false,
    }
}

/*
 * One package zone state with its own range and base. Per zone wrap keeps each
 * counter honest, the sample sums all zones after every zone proves valid.
 */
struct ZoneState {
    energy: PathBuf,
    max_range_uj: u64,
    prev_uj: u64,
}

/*
 * Open package reader. Holds one entry per package zone with the energy file,
 * the range, and the last read for deltas. Open fails with nothing when
 * discovery, range, and the increment check do not all pass, and the caller
 * parks the probe in the unavailable state.
 */
pub struct RaplReader {
    zones: Vec<ZoneState>,
}

impl RaplReader {
    /* Open with the stock base dir. */
    pub fn open_default() -> Option<Self> {
        Self::open(Path::new(DEFAULT_BASE))
    }

    /* Open under one base dir. Tests pass a fake tree. */
    pub fn open(base: &Path) -> Option<Self> {
        let dirs = discover_package_zones(base);
        if dirs.is_empty() {
            return None;
        }
        let mut zones = Vec::with_capacity(dirs.len());
        let mut firsts = Vec::with_capacity(dirs.len());
        let mut seconds = Vec::with_capacity(dirs.len());
        for dir in &dirs {
            let max_range_uj = read_max_range(dir);
            let energy = dir.join("energy_uj");
            let first = read_energy_uj(&energy);
            firsts.push(first);
            zones.push(ZoneState {
                energy,
                max_range_uj,
                prev_uj: 0,
            });
        }
        std::thread::sleep(STARTUP_PAUSE);
        for (i, z) in zones.iter().enumerate() {
            let second = read_energy_uj(&z.energy);
            seconds.push(second);
            if !increment_ok(firsts[i], second, z.max_range_uj) {
                warn!("RAPL counter idle, probe unavailable");
                return None;
            }
        }
        for (i, z) in zones.iter_mut().enumerate() {
            z.prev_uj = seconds[i].unwrap_or(0);
        }
        Some(Self { zones })
    }

    /*
     * One summed delta since the last call in microjoules. Every zone must read
     * well with a valid wrap delta, else nothing moves and no base moves, so
     * the next good read still covers the gap with no poison. A bad read and an
     * invalid delta yield nothing.
     */
    pub fn sample(&mut self) -> Option<u64> {
        let mut nows = Vec::with_capacity(self.zones.len());
        for z in &self.zones {
            nows.push(read_energy_uj(&z.energy)?);
        }
        let mut sum = 0u64;
        for (z, now) in self.zones.iter().zip(nows.iter()) {
            sum = sum.saturating_add(energy_delta_uj(*now, z.prev_uj, z.max_range_uj)?);
        }
        for (z, now) in self.zones.iter_mut().zip(nows.iter()) {
            z.prev_uj = *now;
        }
        Some(sum)
    }

    /* Reader for tests with a fixed base. */
    #[cfg(test)]
    pub fn for_test(energy: PathBuf, max_range_uj: u64, prev_uj: u64) -> Self {
        Self {
            zones: vec![ZoneState {
                energy,
                max_range_uj,
                prev_uj,
            }],
        }
    }

    /* Reader for tests with fixed bases per package. */
    #[cfg(test)]
    pub fn for_test_multi(entries: Vec<(PathBuf, u64, u64)>) -> Self {
        Self {
            zones: entries
                .into_iter()
                .map(|(energy, max_range_uj, prev_uj)| ZoneState {
                    energy,
                    max_range_uj,
                    prev_uj,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /* One fake zone with the given files. */
    fn fake_zone(dir: &Path, zone: &str, name: &str, energy: &str, range: Option<&str>) -> PathBuf {
        let z = dir.join(zone);
        fs::create_dir_all(&z).unwrap();
        fs::write(z.join("name"), name).unwrap();
        fs::write(z.join("energy_uj"), energy).unwrap();
        if let Some(r) = range {
            fs::write(z.join("max_energy_range_uj"), r).unwrap();
        }
        z
    }

    /* Fresh scratch dir per test. */
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("flow_rapl_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /* Discovery finds the package at a high index. */
    #[test]
    fn discovers_package_without_hardcoded_index() {
        let d = scratch("discover");
        fake_zone(
            &d,
            "intel-rapl:3",
            "package-3\n",
            "1000\n",
            Some("65532610987\n"),
        );
        fake_zone(&d, "intel-rapl:7", "core\n", "500\n", Some("65532610987\n"));
        let got = discover_package_zone(&d).unwrap();
        assert_eq!(got, d.join("intel-rapl:3"));
        let _ = fs::remove_dir_all(&d);
    }

    /* Discovery follows sysfs links to the package zone. */
    #[test]
    fn discovers_package_through_symlinks() {
        use std::os::unix::fs::symlink;
        let d = scratch("symlink");
        let real = d.join("real");
        let top = real.join("intel-rapl");
        fs::create_dir_all(&top).unwrap();
        let pkg = real.join("intel-rapl:0");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("name"), "package-0\n").unwrap();
        fs::write(pkg.join("energy_uj"), "1000\n").unwrap();
        fs::write(pkg.join("max_energy_range_uj"), "65532610987\n").unwrap();
        let sub = pkg.join("intel-rapl:0:0");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("name"), "core\n").unwrap();
        fs::write(sub.join("energy_uj"), "500\n").unwrap();
        fs::write(sub.join("max_energy_range_uj"), "65532610987\n").unwrap();
        symlink(&top, d.join("intel-rapl")).unwrap();
        symlink(&pkg, d.join("intel-rapl:0")).unwrap();
        symlink(&sub, d.join("intel-rapl:0:0")).unwrap();
        for zone in ["intel-rapl", "intel-rapl:0", "intel-rapl:0:0"] {
            assert!(
                fs::symlink_metadata(d.join(zone))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{zone} must be a link"
            );
        }
        let got = discover_package_zones(&d);
        assert_eq!(got, vec![d.join("intel-rapl:0")]);
        assert_eq!(discover_package_zone(&d), Some(d.join("intel-rapl:0")));
        let _ = fs::remove_dir_all(&d);
    }

    /* Core named entries stay out of the pick. */
    #[test]
    fn ignores_core_named_entries() {
        let d = scratch("coreonly");
        fake_zone(&d, "intel-rapl:0", "core\n", "500\n", Some("65532610987\n"));
        assert!(discover_package_zone(&d).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    /* Missing tree yields nothing with no trap. */
    #[test]
    fn missing_tree_returns_none() {
        let d = std::env::temp_dir().join("flow_rapl_absent_xyz");
        let _ = fs::remove_dir_all(&d);
        assert!(discover_package_zone(&d).is_none());
        assert!(RaplReader::open(&d).is_none());
    }

    /* Broken range falls back to the measured value. */
    #[test]
    fn max_range_fallback_matches_measured() {
        let d = scratch("range");
        let z = fake_zone(&d, "intel-rapl:0", "package-0\n", "1000\n", None);
        assert_eq!(read_max_range(&z), 65_532_610_987);
        assert_eq!(read_max_range(&z), FALLBACK_MAX_RANGE_UJ);
        fs::write(z.join("max_energy_range_uj"), "junk\n").unwrap();
        assert_eq!(read_max_range(&z), FALLBACK_MAX_RANGE_UJ);
        fs::write(z.join("max_energy_range_uj"), "0\n").unwrap();
        assert_eq!(read_max_range(&z), FALLBACK_MAX_RANGE_UJ);
        fs::write(z.join("max_energy_range_uj"), "1000000\n").unwrap();
        assert_eq!(read_max_range(&z), 1_000_000);
        let _ = fs::remove_dir_all(&d);
    }

    /* Plain forward delta passes through. */
    #[test]
    fn delta_plain_forward_step() {
        assert_eq!(
            energy_delta_uj(7_000_000, 0, FALLBACK_MAX_RANGE_UJ),
            Some(7_000_000)
        );
        assert_eq!(energy_delta_uj(1000, 1000, FALLBACK_MAX_RANGE_UJ), Some(0));
    }

    /* Observed load8 single wrap maps to the logged joules. */
    #[test]
    fn delta_observed_load8_wrap() {
        let got = energy_delta_uj(15_300_142, 65_497_730_024, 65_532_610_987);
        assert_eq!(got, Some(50_181_105));
    }

    /* Past half the max the interval is invalid. */
    #[test]
    fn delta_past_half_range_is_invalid() {
        let max = 65_532_610_987;
        let half = max / 2;
        assert_eq!(energy_delta_uj(half, 0, max), Some(half));
        assert_eq!(energy_delta_uj(half + 1, 0, max), None);
        assert_eq!(energy_delta_uj(99, 100, max), None);
        assert_eq!(energy_delta_uj(5, 5, 0), None);
    }

    /* Increment needs a positive move inside half the max. */
    #[test]
    fn increment_needs_positive_move() {
        let max = FALLBACK_MAX_RANGE_UJ;
        assert!(increment_ok(Some(100), Some(200), max));
        assert!(increment_ok(Some(65_497_730_024), Some(15_300_142), max));
        assert!(!increment_ok(Some(100), Some(100), max));
        assert!(!increment_ok(Some(100), None, max));
        assert!(!increment_ok(None, Some(100), max));
        assert!(!increment_ok(Some(0), Some(max / 2 + 1), max));
    }

    /* Traversal names stay out of the tree. */
    #[test]
    fn zone_path_rejects_traversal() {
        let base = Path::new("/sys/class/powercap");
        assert!(zone_path(base, "intel-rapl:0").is_some());
        assert!(zone_path(base, "intel-rapl:0:0").is_some());
        for bad in [
            "", ".", "..", "../x", "a/b", "a\\b", "/etc", "x y", "x;y", "..rapl",
        ] {
            assert!(zone_path(base, bad).is_none(), "name {bad} must fail");
        }
    }

    /* Static file fails open with the unavailable path. */
    #[test]
    fn open_static_file_is_unavailable() {
        let d = scratch("static");
        fake_zone(
            &d,
            "intel-rapl:0",
            "package-0\n",
            "1000\n",
            Some("65532610987\n"),
        );
        assert!(RaplReader::open(&d).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    /* Moving counter opens and samples deltas. */
    #[test]
    fn open_moving_counter_samples() {
        let d = scratch("moving");
        let z = fake_zone(
            &d,
            "intel-rapl:0",
            "package-0\n",
            "1000\n",
            Some("65532610987\n"),
        );
        let path = z.join("energy_uj");
        let tick = path.clone();
        /* Hold movement for 2s, far past the 100ms startup pause, */
        /* so a loaded runner still sees a live counter. */
        let writer = std::thread::spawn(move || {
            for _ in 0..400 {
                std::thread::sleep(Duration::from_millis(5));
                let cur: u64 = fs::read_to_string(&tick)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                let _ = fs::write(&tick, format!("{}\n", cur + 1000));
            }
        });
        let mut r = RaplReader::open(&d).expect("moving counter must open");
        std::thread::sleep(Duration::from_millis(30));
        let _ = fs::write(&path, "999999999\n");
        let mut d1 = None;
        for _ in 0..50 {
            d1 = r.sample();
            if d1.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(d1.is_some());
        let _ = writer.join();
        let _ = fs::remove_dir_all(&d);
    }

    /* Sample advances the base and keeps deltas honest. */
    #[test]
    fn sample_advances_base() {
        let d = scratch("sample");
        let z = fake_zone(
            &d,
            "intel-rapl:0",
            "package-0\n",
            "5000\n",
            Some("1000000\n"),
        );
        let mut r = RaplReader::for_test(z.join("energy_uj"), 1_000_000, 1000);
        assert_eq!(r.sample(), Some(4000));
        assert_eq!(r.sample(), Some(0));
        fs::write(z.join("energy_uj"), "junk\n").unwrap();
        assert_eq!(r.sample(), None);
        let _ = fs::remove_dir_all(&d);
    }

    /* Two packages sum per zone deltas with per zone wrap. */
    #[test]
    fn two_packages_sum_with_per_zone_wrap() {
        let d = scratch("twopkg");
        let z0 = fake_zone(
            &d,
            "intel-rapl:0",
            "package-0\n",
            "5000\n",
            Some("1000000\n"),
        );
        let z1 = fake_zone(
            &d,
            "intel-rapl:1",
            "package-1\n",
            "8000\n",
            Some("1000000\n"),
        );
        let zones = discover_package_zones(&d);
        assert_eq!(zones.len(), 2);
        assert_eq!(zones[0], d.join("intel-rapl:0"));
        assert_eq!(zones[1], d.join("intel-rapl:1"));
        let mut r = RaplReader::for_test_multi(vec![
            (z0.join("energy_uj"), 1_000_000, 1000),
            (z1.join("energy_uj"), 1_000_000, 2000),
        ]);
        assert_eq!(r.sample(), Some(4000 + 6000));
        fs::write(z0.join("energy_uj"), "999990\n").unwrap();
        fs::write(z1.join("energy_uj"), "9000\n").unwrap();
        let mut r2 = RaplReader::for_test_multi(vec![
            (z0.join("energy_uj"), 1_000_000, 999_995),
            (z1.join("energy_uj"), 1_000_000, 8000),
        ]);
        fs::write(z0.join("energy_uj"), "5\n").unwrap();
        assert_eq!(r2.sample(), Some(10 + 1000));
        fs::write(z1.join("energy_uj"), "junk\n").unwrap();
        assert_eq!(r2.sample(), None);
        let _ = fs::remove_dir_all(&d);
    }
}
