// SPDX-License-Identifier: GPL-2.0

//! The profile file: its schema, the rules every load and save enforce,
//! and where it lives. See `services/PROFILES.md` for the contract.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::files::{check_trusted, check_write_target, ensure_dir, open_config, replace_file};

/// The file format version this crate reads and writes.
pub const FORMAT_VERSION: u32 = 2;

/// The administrator's override, used whole when present.
pub const ADMIN_PATH: &str = "/etc/scx/profiles.json";
/// The list scx ships.
pub const SHIPPED_PATH: &str = "/usr/share/scx/profiles.json";

/// The id of the profile that means "the kernel's own scheduler".
pub const DEFAULT_ID: &str = "default";
/// The `default` profile's record, fixed: the contract says it cannot
/// be edited, and that covers the whole record, not only its action.
pub const DEFAULT_LABEL: &str = "Default";
pub const DEFAULT_DESCRIPTION: &str = "Use the kernel's default scheduler.";
/// Ids a profile can never have: the marker `run` writes.
pub const RESERVED_IDS: [&str; 1] = [crate::envfile::CUSTOM_MARKER];

/// What a profile without a scheduler does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Stop the unit and run nothing.
    Stop,
}

/// One profile. Either `action` or `sched` is set, never both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sched: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

impl Profile {
    /// The scheduler's basename, for a profile that has one.
    pub fn sched_name(&self) -> Option<String> {
        self.sched.as_deref().map(sched_name)
    }
}

/// The whole file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profiles {
    pub version: u32,
    pub profiles: Vec<Profile>,
}

/// A loaded list and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub profiles: Profiles,
    pub source: PathBuf,
}

impl Profiles {
    /// Parses and validates a file's text.
    pub fn parse(text: &str) -> Result<Self> {
        let profiles: Self = serde_json::from_str(text).context("invalid profiles file")?;
        profiles.validate()?;
        Ok(profiles)
    }

    /// Serialises the list the way `save` writes it.
    pub fn render(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// The first profile whose scheduler (by basename) and arguments are
    /// exactly these, for files written without a marker.
    pub fn matching(&self, sched: &str, args: &[String]) -> Option<&Profile> {
        let sched = sched_name(sched);
        self.profiles
            .iter()
            .find(|p| p.sched_name().as_deref() == Some(sched.as_str()) && p.args == args)
    }

    /// The rules of `services/PROFILES.md`, all of them, so that a
    /// list that passes here is one every tool accepts.
    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            bail!(
                "profiles file version {} is not supported (expected {FORMAT_VERSION})",
                self.version
            );
        }
        let Some(first) = self.profiles.first() else {
            bail!("the profiles list is empty");
        };
        if first.id != DEFAULT_ID {
            bail!(
                "the first profile must be {DEFAULT_ID:?}, found {:?}",
                first.id
            );
        }
        if first.action != Some(Action::Stop) {
            bail!("the {DEFAULT_ID:?} profile must have action \"stop\"");
        }
        if first.label != DEFAULT_LABEL || first.description != DEFAULT_DESCRIPTION {
            bail!(
                "the {DEFAULT_ID:?} profile cannot be edited: its label is {DEFAULT_LABEL:?} and \
its description {DEFAULT_DESCRIPTION:?}"
            );
        }
        for (idx, profile) in self.profiles.iter().enumerate() {
            validate_profile(profile)
                .with_context(|| format!("profile {} ({:?})", idx + 1, profile.id))?;
            if self.profiles[..idx].iter().any(|p| p.id == profile.id) {
                bail!("profile id {:?} appears more than once", profile.id);
            }
        }
        Ok(())
    }
}

fn validate_profile(profile: &Profile) -> Result<()> {
    validate_id(&profile.id)?;
    validate_text("label", &profile.label, 1, 64)?;
    validate_text("description", &profile.description, 0, 256)?;
    match (&profile.action, &profile.sched) {
        (Some(_), Some(_)) => bail!("has both \"action\" and \"sched\""),
        (None, None) => bail!("has neither \"action\" nor \"sched\""),
        (Some(_), None) => {
            if profile.id != DEFAULT_ID {
                bail!(
                    "only the {DEFAULT_ID:?} profile may have an \"action\"; a profile that \
stops the unit would be indistinguishable from it"
                );
            }
            if !profile.args.is_empty() {
                bail!("an action profile takes no \"args\"");
            }
        }
        (None, Some(sched)) => {
            validate_sched(sched)?;
            for arg in &profile.args {
                validate_arg(arg)?;
            }
        }
    }
    Ok(())
}

/// 1 to 64 characters of lowercase ASCII letters, digits and `-`,
/// starting with a letter.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = (1..=64).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!(
            "invalid profile id {id:?}: 1 to 64 lowercase ASCII letters, digits and '-', \
starting with a letter"
        );
    }
    if RESERVED_IDS.contains(&id) {
        bail!("profile id {id:?} is reserved");
    }
    Ok(())
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

/// A bare `scx_*` name, or an absolute path with such a basename. Whether
/// the path's directory is on systemd's search path is checked when it
/// is resolved, since that needs the live system.
pub fn validate_sched(sched: &str) -> Result<()> {
    let name = if sched.starts_with('/') {
        if sched.ends_with('/') || sched.contains("//") {
            bail!("scheduler path {sched:?} must be plain, without a trailing or doubled '/'");
        }
        // systemd's compiled-in search path only ever holds these
        // trees. Whether the directory is on it is checked against the
        // live system when the profile is applied; this rejects the
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

/// Where the list is read from: the first of the candidates that exists.
pub fn candidates() -> [&'static Path; 2] {
    [Path::new(ADMIN_PATH), Path::new(SHIPPED_PATH)]
}

/// Loads the list in use: the administrator's file when present, else
/// the shipped one. A file that exists but does not validate is an
/// error, never silently skipped for the next candidate: running the
/// shipped list instead of the one the administrator wrote would start
/// schedulers they did not configure.
pub fn load() -> Result<Loaded> {
    // The administrator's list decides what `apply` runs without a
    // password, so a copy that someone other than root could have
    // written is refused rather than used.
    load_checked(&candidates(), Some(Path::new(ADMIN_PATH)))
}

/// The shipped list, ignoring any override.
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
        let profiles =
            Profiles::parse(&text).with_context(|| format!("cannot load {}", path.display()))?;
        return Ok(Loaded {
            profiles,
            source: path.to_path_buf(),
        });
    }
    bail!(
        "no profiles file found (looked for {})",
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Validates and writes the administrator's file.
pub fn save(profiles: &Profiles) -> Result<()> {
    save_to(profiles, Path::new(ADMIN_PATH))
}

pub(crate) fn save_to(profiles: &Profiles, path: &Path) -> Result<()> {
    profiles.validate()?;
    if let Some(dir) = path.parent() {
        ensure_dir(dir)?;
    }
    // The write is refused where a later read would refuse the file:
    // a privileged write must not trust a directory the load does not.
    check_write_target(path)?;
    write_list(profiles, path)
}

/// The write itself, after the checks: validated, rendered, replaced
/// atomically.
pub(crate) fn write_list(profiles: &Profiles, path: &Path) -> Result<()> {
    profiles.validate()?;
    replace_file(path, &profiles.render()?)
}

/// Removes the administrator's file, so the shipped list is used again.
/// A file that is not there is already reset.
pub fn reset() -> Result<()> {
    reset_at(Path::new(ADMIN_PATH))
}

pub(crate) fn reset_at(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("cannot remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop(id: &str) -> Profile {
        Profile {
            id: id.into(),
            label: if id == DEFAULT_ID {
                DEFAULT_LABEL.into()
            } else {
                id.into()
            },
            description: if id == DEFAULT_ID {
                DEFAULT_DESCRIPTION.into()
            } else {
                String::new()
            },
            action: Some(Action::Stop),
            sched: None,
            args: Vec::new(),
        }
    }

    fn sched(id: &str, sched: &str, args: &[&str]) -> Profile {
        Profile {
            id: id.into(),
            label: id.into(),
            description: String::new(),
            action: None,
            sched: Some(sched.into()),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn list(profiles: Vec<Profile>) -> Profiles {
        Profiles {
            version: FORMAT_VERSION,
            profiles,
        }
    }

    #[test]
    fn a_valid_list_round_trips() {
        let p = list(vec![
            stop("default"),
            sched("gaming", "scx_lavd", &["--performance"]),
        ]);
        let text = p.render().unwrap();
        assert_eq!(Profiles::parse(&text).unwrap(), p);
        assert_eq!(p.get("gaming").unwrap().sched_name().unwrap(), "scx_lavd");
        assert_eq!(
            p.matching("/usr/bin/scx_lavd", &["--performance".into()])
                .unwrap()
                .id,
            "gaming"
        );
        assert!(p.matching("scx_lavd", &[]).is_none());
    }

    #[test]
    fn default_must_be_first_and_stop() {
        let err = list(vec![sched("gaming", "scx_lavd", &[]), stop("default")])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("first"));
        let err = list(vec![sched("default", "scx_lavd", &[])])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("stop"));
        assert!(list(Vec::new()).validate().is_err());
    }

    #[test]
    fn ids_are_checked_and_unique() {
        for bad in ["", "Gaming", "1a", "a b", "a_b", &"a".repeat(65)] {
            assert!(validate_id(bad).is_err(), "{bad:?}");
        }
        validate_id("low-latency2").unwrap();
        assert!(validate_id("custom").is_err(), "reserved for `run`");
        let mut relabelled = list(vec![stop("default")]);
        relabelled.profiles[0].label = "My default".into();
        assert!(relabelled.validate().is_err(), "default's record is fixed");
        let err = list(vec![
            stop("default"),
            sched("x", "scx_lavd", &[]),
            sched("x", "scx_lavd", &[]),
        ])
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("more than once"));
        let err = list(vec![stop("default"), stop("quiet")])
            .validate()
            .unwrap_err();
        assert!(format!("{err:#}").contains("only the"), "{err:#}");
    }

    #[test]
    fn action_and_sched_are_exclusive() {
        let mut both = sched("x", "scx_lavd", &[]);
        both.action = Some(Action::Stop);
        assert!(validate_profile(&both).is_err());
        let mut neither = stop("default");
        neither.action = None;
        assert!(validate_profile(&neither).is_err());
        let mut stop_with_args = stop("default");
        stop_with_args.args.push("-v".into());
        assert!(validate_profile(&stop_with_args).is_err());
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
        assert!(Profiles::parse(r#"{"version":1,"profiles":[]}"#).is_err());
        assert!(
            Profiles::parse(
                r#"{"version":2,"profiles":[{"id":"default","label":"D","action":"stop","mode":1}]}"#
            )
            .is_err()
        );
        assert!(
            Profiles::parse(
                r#"{"version":2,"profiles":[{"id":"default","label":"D","action":"restart"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn text_fields_are_bounded() {
        let mut p = stop("default");
        p.label = String::new();
        assert!(validate_profile(&p).is_err());
        p.label = "x".repeat(65);
        assert!(validate_profile(&p).is_err());
        p.label = "ok".into();
        p.description = "tab\there".into();
        assert!(validate_profile(&p).is_err());
        p.description = "zażółć gęślą jaźń".into();
        validate_profile(&p).unwrap();
    }

    #[test]
    fn load_save_reset_against_scratch_files() {
        let dir = std::env::temp_dir().join(format!("scx_profiles-lsr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let admin = dir.join("etc").join("profiles.json");
        let shipped = dir.join("share").join("profiles.json");
        fs::create_dir_all(shipped.parent().unwrap()).unwrap();
        let p = list(vec![stop("default"), sched("gaming", "scx_lavd", &[])]);
        fs::write(&shipped, p.render().unwrap()).unwrap();

        let loaded = load_from(&[&admin, &shipped]).unwrap();
        assert_eq!(loaded.source, shipped);

        let mut custom = p.clone();
        custom.profiles.push(sched("mine", "scx_rusty", &["-v"]));
        // The round trip, without the trust check: a scratch directory
        // belongs to whoever runs the tests. `save_to` is exercised
        // separately.
        fs::create_dir_all(admin.parent().unwrap()).unwrap();
        write_list(&custom, &admin).unwrap();
        let loaded = load_from(&[&admin, &shipped]).unwrap();
        assert_eq!(
            (loaded.source.as_path(), &loaded.profiles),
            (admin.as_path(), &custom)
        );

        // A broken override is an error, not a fallback to the shipped list.
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

        reset_at(&admin).unwrap();
        reset_at(&admin).unwrap();
        assert_eq!(load_from(&[&admin, &shipped]).unwrap().source, shipped);
        assert!(load_from(&[&admin]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_refuses_an_invalid_list_and_an_untrusted_directory() {
        let dir = std::env::temp_dir().join(format!("scx_profiles-inv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("etc").join("profiles.json");
        assert!(save_to(&list(Vec::new()), &path).is_err());
        assert!(!path.exists());
        assert!(write_list(&list(Vec::new()), &path).is_err());

        // A valid list goes through `save_to` only where the trust rules
        // allow: the directory `save_to` creates is 0755, so as root the
        // save succeeds, and as any other user it is refused for the
        // owner, with nothing written.
        let valid = list(vec![stop("default")]);
        let outcome = save_to(&valid, &path);
        if std::os::unix::fs::MetadataExt::uid(&fs::metadata(&dir).unwrap()) == 0 {
            outcome.unwrap();
            assert!(path.exists());
        } else {
            assert!(format!("{:#}", outcome.unwrap_err()).contains("not root"));
            assert!(!path.exists());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
