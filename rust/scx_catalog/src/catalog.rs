// SPDX-License-Identifier: GPL-2.0

//! The catalog file: which schedulers scx recommends, which it keeps
//! out of the lists, and where the file lives. See
//! `services/CATALOG.md` for the contract.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::files::{check_trusted, open_config};

/// The file format version this crate reads.
pub const FORMAT_VERSION: u32 = 1;

/// The administrator's override, used whole when present.
pub const ADMIN_PATH: &str = "/etc/scx/catalog.json";
/// The catalog scx ships.
pub const SHIPPED_PATH: &str = "/usr/share/scx/catalog.json";

/// The id of the entry that means "the kernel's own scheduler": no
/// sched_ext scheduler runs.
pub const DEFAULT_ID: &str = "default";

/// One recommended entry: `default`, or a scheduler by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
}

impl Recommendation {
    /// The scheduler this entry starts, or `None` for `default`.
    pub fn sched(&self) -> Option<&str> {
        (self.id != DEFAULT_ID).then_some(self.id.as_str())
    }
}

/// The whole file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    /// The entries a user picks from, `default` first.
    pub recommended: Vec<Recommendation>,
    /// Schedulers kept out of every list: ones that do not start
    /// without a configuration file, or that are test tools. `run`
    /// still starts them.
    #[serde(default)]
    pub hidden: Vec<String>,
    /// Schedulers the maintainers call stable, by name. A recommended
    /// scheduler counts as stable without being listed here. Said
    /// explicitly, never assumed from where a scheduler lives in the
    /// tree or how it got installed: a scheduler the catalog does not
    /// name is unknown to it.
    #[serde(default)]
    pub stable: Vec<String>,
    /// Schedulers the catalog does not call stable and says so: the
    /// ones under `scheds/experimental`, and any other whose authors
    /// say it is not for production. Listed after the stable ones and
    /// marked, so that the full list says what a user is reaching for.
    /// A hidden scheduler may be experimental as well.
    #[serde(default)]
    pub experimental: Vec<String>,
}

/// What the catalog says about an installed scheduler, for the full
/// list. The order is the list's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Named in `stable`, or recommended.
    Stable,
    /// Named in `experimental`.
    Experimental,
    /// Named nowhere: installed, but the catalog says nothing about it,
    /// and neither does the list.
    Unknown,
}

/// A loaded catalog and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub catalog: Catalog,
    pub source: PathBuf,
}

impl Catalog {
    /// Parses and validates a file's text.
    pub fn parse(text: &str) -> Result<Self> {
        let catalog: Self = serde_json::from_str(text).context("invalid catalog file")?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Serialises the catalog the way the shipped file is written.
    pub fn render(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    pub fn get(&self, id: &str) -> Option<&Recommendation> {
        self.recommended.iter().find(|r| r.id == id)
    }

    pub fn is_recommended(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn is_hidden(&self, name: &str) -> bool {
        self.hidden.iter().any(|h| h == name)
    }

    pub fn tier(&self, name: &str) -> Tier {
        if self.is_recommended(name) || self.stable.iter().any(|e| e == name) {
            Tier::Stable
        } else if self.experimental.iter().any(|e| e == name) {
            Tier::Experimental
        } else {
            Tier::Unknown
        }
    }

    /// The rules of `services/CATALOG.md`, all of them, so that a file
    /// that passes here is one every tool accepts.
    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            bail!(
                "catalog file version {} is not supported (expected {FORMAT_VERSION})",
                self.version
            );
        }
        let Some(first) = self.recommended.first() else {
            bail!("the recommended list is empty");
        };
        if first.id != DEFAULT_ID {
            bail!(
                "the first recommended entry must be {DEFAULT_ID:?}, found {:?}",
                first.id
            );
        }
        for (idx, entry) in self.recommended.iter().enumerate() {
            validate_entry(entry)
                .with_context(|| format!("recommended entry {} ({:?})", idx + 1, entry.id))?;
            if self.recommended[..idx].iter().any(|r| r.id == entry.id) {
                bail!("recommended entry {:?} appears more than once", entry.id);
            }
        }
        for (idx, name) in self.hidden.iter().enumerate() {
            validate_name(name).with_context(|| format!("hidden entry {}", idx + 1))?;
            if self.hidden[..idx].contains(name) {
                bail!("hidden entry {name:?} appears more than once");
            }
            if self.is_recommended(name) {
                bail!("{name:?} is both recommended and hidden");
            }
        }
        for (idx, name) in self.stable.iter().enumerate() {
            validate_name(name).with_context(|| format!("stable entry {}", idx + 1))?;
            if self.stable[..idx].contains(name) {
                bail!("stable entry {name:?} appears more than once");
            }
        }
        for (idx, name) in self.experimental.iter().enumerate() {
            validate_name(name).with_context(|| format!("experimental entry {}", idx + 1))?;
            if self.experimental[..idx].contains(name) {
                bail!("experimental entry {name:?} appears more than once");
            }
            if self.is_recommended(name) {
                bail!("{name:?} is both recommended and experimental");
            }
            if self.stable.contains(name) {
                bail!("{name:?} is both stable and experimental");
            }
        }
        Ok(())
    }
}

fn validate_entry(entry: &Recommendation) -> Result<()> {
    if entry.id != DEFAULT_ID {
        validate_name(&entry.id)?;
    }
    validate_text("label", &entry.label, 1, 64)?;
    validate_text("description", &entry.description, 0, 256)
}

fn validate_text(what: &str, text: &str, min: usize, max: usize) -> Result<()> {
    let len = text.chars().count();
    if len < min || len > max {
        bail!("{what} must be {min} to {max} characters, has {len}");
    }
    if let Some(bad) = text.chars().find(|c| c.is_control()) {
        bail!("{what} contains the control character {bad:?}");
    }
    Ok(())
}

/// A bare `scx_*` name, as the catalog and `start` take it: the
/// executable is found in systemd's default search path, never named by
/// path.
pub fn validate_name(name: &str) -> Result<()> {
    if name.contains('/') {
        bail!("invalid scheduler {name:?}: a bare scx_* name, not a path");
    }
    validate_sched(name)
}

/// A bare `scx_*` name, or an absolute path with such a basename, as
/// `run` takes it. Whether the path's directory is on systemd's search
/// path is checked when it is resolved, since that needs the live
/// system.
pub fn validate_sched(sched: &str) -> Result<()> {
    let name = if sched.starts_with('/') {
        if sched.ends_with('/') || sched.contains("//") {
            bail!("scheduler path {sched:?} must be plain, without a trailing or doubled '/'");
        }
        // systemd's compiled-in search path only ever holds these
        // trees. Whether the directory is on it is checked against the
        // live system when the scheduler is started; this rejects the
        // rest (`/tmp`, `/home`) without one.
        if !(sched.starts_with("/usr/")
            || sched.starts_with("/bin/")
            || sched.starts_with("/sbin/"))
        {
            bail!("scheduler path {sched:?} is not under /usr, /bin or /sbin");
        }
        let path = Path::new(sched);
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            bail!("scheduler path {sched:?} must be plain, without '.' or '..'");
        }
        match path.file_name().and_then(|n| n.to_str()) {
            Some(name) if path.parent().is_some_and(|dir| dir != Path::new("/")) => name,
            _ => bail!("scheduler path {sched:?} has no directory and file name"),
        }
    } else {
        sched
    };
    let ok = name.starts_with("scx_")
        && name.len() > 4
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        bail!(
            "invalid scheduler {sched:?}: an scx_* name of ASCII letters, digits, '_' and '-', \
or an absolute path to one"
        );
    }
    Ok(())
}

/// 1 to 256 characters of ASCII letters, digits and `-_=.,:/+`.
pub fn validate_arg(arg: &str) -> Result<()> {
    let ok = (1..=256).contains(&arg.len())
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_=.,:/+".contains(c));
    if !ok {
        bail!("invalid option {arg:?}: 1 to 256 ASCII letters, digits and -_=.,:/+");
    }
    Ok(())
}

/// The basename of a scheduler given as a name or a path.
pub fn sched_name(value: &str) -> String {
    Path::new(value)
        .file_name()
        .map_or_else(|| value.to_owned(), |n| n.to_string_lossy().into_owned())
}

/// Where the catalog is read from: the first of the candidates that
/// exists.
pub fn candidates() -> [&'static Path; 2] {
    [Path::new(ADMIN_PATH), Path::new(SHIPPED_PATH)]
}

/// Loads the catalog in use: the administrator's file when present,
/// else the shipped one. A file that exists but does not validate is an
/// error, never silently skipped for the next candidate: using the
/// shipped catalog instead of the one the administrator wrote would
/// offer schedulers they chose to hide.
pub fn load() -> Result<Loaded> {
    // The administrator's catalog decides what `start` offers without
    // a password, so a copy that someone other than root could have
    // written is refused rather than used.
    load_checked(&candidates(), Some(Path::new(ADMIN_PATH)))
}

/// A catalog file named by the caller, for listing: a checkout's
/// `services/catalog.json`, say, to see what it would show before it
/// is installed. Read as is, without the trust rules, since nothing
/// privileged follows from it; `start` and `resume` always consult the
/// installed catalog.
pub fn load_file(path: &Path) -> Result<Loaded> {
    use std::io::Read;
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|mut file| file.read_to_string(&mut text))
        .with_context(|| format!("cannot read {}", path.display()))?;
    let catalog =
        Catalog::parse(&text).with_context(|| format!("cannot load {}", path.display()))?;
    Ok(Loaded {
        catalog,
        source: path.to_path_buf(),
    })
}

/// The shipped catalog, ignoring any override.
pub fn load_shipped() -> Result<Loaded> {
    load_from(&[Path::new(SHIPPED_PATH)])
}

/// Whether an administrator's file is in use.
pub fn is_customized() -> bool {
    is_customized_at(Path::new(ADMIN_PATH))
}

/// Not `exists`, which follows symlinks: a dangling link, of the file
/// or of its directory, is still something the administrator put there.
fn is_customized_at(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
        || path
            .parent()
            .is_some_and(|dir| fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()))
}

pub(crate) fn load_from(paths: &[&Path]) -> Result<Loaded> {
    load_checked(paths, None)
}

/// Loads the first of `paths` that exists. A path equal to `trusted`
/// must pass [`check_trusted`] on the handle it is read from. A file
/// that exists but cannot be read, parsed or trusted is an error, and
/// so is a symlink whose target is missing: never a fallback to the
/// next candidate.
fn load_checked(paths: &[&Path], trusted: Option<&Path>) -> Result<Loaded> {
    use std::io::Read;
    for path in paths {
        let strict = trusted == Some(*path);
        let Some(mut file) = open_config(path, strict)? else {
            continue;
        };
        if strict {
            check_trusted(path, &file)?;
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let catalog =
            Catalog::parse(&text).with_context(|| format!("cannot load {}", path.display()))?;
        return Ok(Loaded {
            catalog,
            source: path.to_path_buf(),
        });
    }
    bail!(
        "no catalog file found (looked for {})",
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> Recommendation {
        Recommendation {
            id: id.into(),
            label: id.into(),
            description: String::new(),
        }
    }

    fn catalog(ids: &[&str], hidden: &[&str]) -> Catalog {
        Catalog {
            version: FORMAT_VERSION,
            recommended: ids.iter().map(|id| entry(id)).collect(),
            hidden: hidden.iter().map(|s| (*s).to_owned()).collect(),
            stable: Vec::new(),
            experimental: Vec::new(),
        }
    }

    fn with_experimental(mut c: Catalog, names: &[&str]) -> Catalog {
        c.experimental = names.iter().map(|s| (*s).to_owned()).collect();
        c
    }

    fn with_stable(mut c: Catalog, names: &[&str]) -> Catalog {
        c.stable = names.iter().map(|s| (*s).to_owned()).collect();
        c
    }

    /// The tier is what the catalog says, never a default: a scheduler
    /// named nowhere (one built from a branch and dropped into
    /// /usr/local/bin, say) is unknown, not stable.
    #[test]
    fn a_scheduler_the_catalog_does_not_name_is_unknown_not_stable() {
        let c = with_stable(
            with_experimental(catalog(&["default", "scx_cosmos"], &[]), &["scx_flow"]),
            &["scx_bpfland"],
        );
        c.validate().unwrap();
        assert_eq!(
            c.tier("scx_cosmos"),
            Tier::Stable,
            "recommended counts as stable"
        );
        assert_eq!(c.tier("scx_bpfland"), Tier::Stable);
        assert_eq!(c.tier("scx_flow"), Tier::Experimental);
        assert_eq!(c.tier("scx_rake"), Tier::Unknown);
        assert_eq!(c.tier("scx_chaos"), Tier::Unknown);
        assert!(Tier::Stable < Tier::Experimental && Tier::Experimental < Tier::Unknown);
        // Stable entries are names and unique; one may not be
        // experimental too.
        assert!(
            with_stable(catalog(&["default"], &[]), &["bpfland"])
                .validate()
                .is_err()
        );
        let err = with_stable(catalog(&["default"], &[]), &["scx_bpfland", "scx_bpfland"])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("more than once"));
        let err = with_stable(
            with_experimental(catalog(&["default"], &[]), &["scx_flow"]),
            &["scx_flow"],
        )
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("both stable and experimental"));
    }

    #[test]
    fn experimental_entries_are_names_unique_and_not_recommended() {
        let c = with_experimental(
            catalog(&["default", "scx_cosmos"], &["scx_nitosis"]),
            &["scx_flow", "scx_nitosis"],
        );
        c.validate().unwrap();
        assert_eq!(c.tier("scx_flow"), Tier::Experimental);
        assert_eq!(c.tier("scx_cosmos"), Tier::Stable);
        // Hidden and experimental may overlap (nitosis is both); a
        // recommended scheduler is stable by definition.
        for bad in ["default", "flow", "/usr/bin/scx_flow"] {
            assert!(
                with_experimental(catalog(&["default"], &[]), &[bad])
                    .validate()
                    .is_err(),
                "{bad:?}"
            );
        }
        let err = with_experimental(catalog(&["default"], &[]), &["scx_flow", "scx_flow"])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("more than once"));
        let err = with_experimental(catalog(&["default", "scx_flow"], &[]), &["scx_flow"])
            .validate()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("both recommended and experimental")
        );
        // Round trip keeps the field; it may be left out.
        assert_eq!(Catalog::parse(&c.render().unwrap()).unwrap(), c);
    }

    #[test]
    fn a_valid_catalog_round_trips() {
        let c = catalog(&["default", "scx_cosmos", "scx_lavd"], &["scx_layered"]);
        let text = c.render().unwrap();
        assert_eq!(Catalog::parse(&text).unwrap(), c);
        assert_eq!(c.get("scx_lavd").unwrap().sched(), Some("scx_lavd"));
        assert_eq!(c.get("default").unwrap().sched(), None);
        assert!(c.is_recommended("scx_cosmos"));
        assert!(!c.is_recommended("scx_bpfland"));
        assert!(c.is_hidden("scx_layered"));
        assert!(!c.is_hidden("scx_cosmos"));
    }

    #[test]
    fn default_must_be_first() {
        let err = catalog(&["scx_lavd", "default"], &[])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("first"));
        assert!(catalog(&[], &[]).validate().is_err());
        assert!(
            catalog(&["scx_lavd"], &[])
                .validate()
                .unwrap_err()
                .to_string()
                .contains("first")
        );
    }

    #[test]
    fn entries_are_scheduler_names_and_unique() {
        for bad in [
            "",
            "lavd",
            "scx_",
            "Gaming",
            "/usr/bin/scx_lavd",
            "scx_lavd x",
        ] {
            assert!(
                catalog(&["default", bad], &[]).validate().is_err(),
                "{bad:?}"
            );
        }
        catalog(&["default", "scx_lavd-git"], &[])
            .validate()
            .unwrap();
        let err = catalog(&["default", "scx_lavd", "scx_lavd"], &[])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("more than once"));
        let err = catalog(&["default", "default"], &[])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("more than once"));
    }

    #[test]
    fn hidden_entries_are_names_unique_and_not_recommended() {
        catalog(&["default"], &["scx_layered", "scx_mitosis"])
            .validate()
            .unwrap();
        for bad in ["default", "layered", "/usr/bin/scx_layered"] {
            assert!(catalog(&["default"], &[bad]).validate().is_err(), "{bad:?}");
        }
        let err = catalog(&["default"], &["scx_layered", "scx_layered"])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("more than once"));
        let err = catalog(&["default", "scx_lavd"], &["scx_lavd"])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn schedulers_are_names_or_plain_absolute_paths() {
        validate_sched("scx_lavd").unwrap();
        validate_sched("/usr/local/bin/scx_lavd-git").unwrap();
        for bad in [
            "",
            "scx_",
            "lavd",
            "scx_lavd x",
            "scx_$(id)",
            "/scx_lavd",
            "/tmp/scx_lavd",
            "/home/me/bin/scx_lavd",
            "/usr/bin/../scx_lavd",
            "usr/bin/scx_lavd",
            "/usr/bin/scx_lavd/",
        ] {
            assert!(validate_sched(bad).is_err(), "{bad:?}");
        }
        validate_name("scx_lavd").unwrap();
        assert!(validate_name("/usr/bin/scx_lavd").is_err());
        assert_eq!(sched_name("/usr/bin/scx_lavd"), "scx_lavd");
        assert_eq!(sched_name("scx_lavd"), "scx_lavd");
    }

    #[test]
    fn options_come_from_the_allowlist() {
        for ok in ["-s", "20000", "--pinned-slice-us=500", "a,b:c/d+e"] {
            validate_arg(ok).unwrap();
        }
        for bad in ["", "-s 5", "$HOME", "'x'", "a;b", "a\nb", "*", "--x=y|z"] {
            assert!(validate_arg(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unknown_keys_and_other_versions_are_errors() {
        assert!(Catalog::parse(r#"{"version":2,"recommended":[]}"#).is_err());
        assert!(
            Catalog::parse(
                r#"{"version":1,"recommended":[{"id":"default","label":"D","action":"stop"}]}"#
            )
            .is_err()
        );
        assert!(
            Catalog::parse(r#"{"version":1,"recommended":[{"id":"default","label":"D"}],"x":1}"#)
                .is_err()
        );
        // `hidden` may be left out.
        Catalog::parse(r#"{"version":1,"recommended":[{"id":"default","label":"D"}]}"#).unwrap();
    }

    #[test]
    fn text_fields_are_bounded() {
        let mut e = entry("default");
        e.label = String::new();
        assert!(validate_entry(&e).is_err());
        e.label = "x".repeat(65);
        assert!(validate_entry(&e).is_err());
        e.label = "ok".into();
        e.description = "tab\there".into();
        assert!(validate_entry(&e).is_err());
        e.description = "zażółć gęślą jaźń".into();
        validate_entry(&e).unwrap();
    }

    #[test]
    fn a_named_file_loads_as_is_and_a_missing_or_bad_one_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        fs::write(
            &path,
            catalog(&["default", "scx_lavd"], &[]).render().unwrap(),
        )
        .unwrap();
        let loaded = load_file(&path).unwrap();
        assert_eq!(
            (loaded.source.as_path(), loaded.catalog.recommended.len()),
            (path.as_path(), 2)
        );
        assert!(load_file(&dir.path().join("absent.json")).is_err());
        fs::write(&path, "{").unwrap();
        assert!(load_file(&path).is_err());
    }

    #[test]
    fn load_against_scratch_files() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let admin = dir.join("etc").join("catalog.json");
        let shipped = dir.join("share").join("catalog.json");
        fs::create_dir_all(shipped.parent().unwrap()).unwrap();
        let c = catalog(&["default", "scx_lavd"], &[]);
        fs::write(&shipped, c.render().unwrap()).unwrap();

        let loaded = load_from(&[&admin, &shipped]).unwrap();
        assert_eq!(loaded.source, shipped);
        assert!(!is_customized_at(&admin));

        let custom = catalog(&["default", "scx_rusty"], &["scx_lavd"]);
        fs::create_dir_all(admin.parent().unwrap()).unwrap();
        fs::write(&admin, custom.render().unwrap()).unwrap();
        let loaded = load_from(&[&admin, &shipped]).unwrap();
        assert_eq!(
            (loaded.source.as_path(), &loaded.catalog),
            (admin.as_path(), &custom)
        );
        assert!(is_customized_at(&admin));

        // A broken override is an error, not a fallback to the shipped
        // catalog.
        fs::write(&admin, "{").unwrap();
        assert!(load_from(&[&admin, &shipped]).is_err());
        // So is an override that is a symlink to nothing: the admin set
        // something up and it is broken, which is not the same as none.
        fs::remove_file(&admin).unwrap();
        std::os::unix::fs::symlink(admin.with_file_name("missing.json"), &admin).unwrap();
        let err = load_from(&[&admin, &shipped]).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        fs::remove_file(&admin).unwrap();
        // And a trusted path that is a symlink to a valid file is refused.
        std::os::unix::fs::symlink(&shipped, &admin).unwrap();
        let err = load_checked(&[&admin, &shipped], Some(&admin)).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        fs::remove_file(&admin).unwrap();
        // A trusted directory that is a dangling symlink is a broken
        // configuration, not an absent one.
        let etc = admin.parent().unwrap().to_path_buf();
        fs::remove_dir_all(&etc).unwrap();
        std::os::unix::fs::symlink(dir.join("no-such-dir"), &etc).unwrap();
        let err = load_checked(&[&admin, &shipped], Some(&admin)).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert!(is_customized_at(&admin));
        fs::remove_file(&etc).unwrap();

        assert_eq!(load_from(&[&admin, &shipped]).unwrap().source, shipped);
        assert!(load_from(&[&admin]).is_err());
    }
}
