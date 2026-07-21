use std::collections::HashSet;
use std::ffi::OsString;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};

struct UndefOkMetadata {
    long: &'static str,
    note: &'static str,
}

pub struct IgnoredUndefOkFlag {
    pub long: String,
    pub note: Option<&'static str>,
}

pub struct ParsedArgs<T> {
    pub opts: T,
    pub ignored_undefok_flags: Vec<IgnoredUndefOkFlag>,
}

const KNOWN_UNDEFOK_FLAGS: &[UndefOkMetadata] = &[
    UndefOkMetadata {
        long: "reconfiguration-interval-s",
        note: "accepted for CLI compatibility during rollout; cell reconfiguration is driven internally, not by a CLI interval",
    },
    UndefOkMetadata {
        long: "rebalance-cpus-interval-s",
        note: "accepted for CLI compatibility during rollout; CPU rebalancing cadence is controlled by the remaining active knobs",
    },
];

fn lookup_known_undefok_flag(name: &str) -> Option<&'static UndefOkMetadata> {
    KNOWN_UNDEFOK_FLAGS
        .iter()
        .find(|undefok| undefok.long == name)
}

fn normalize_undefok_name(name: &str) -> Result<String> {
    let normalized = name.trim().trim_start_matches('-');
    if normalized.is_empty() {
        bail!("--undefok entries must not be empty");
    }
    if normalized.contains('=') {
        bail!("--undefok entry {name:?} must name a flag, not include a value");
    }
    Ok(normalized.to_owned())
}

fn collect_configured_undefok_flags(args: &[OsString]) -> Result<HashSet<String>> {
    let mut configured = HashSet::new();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            continue;
        };

        let value = if let Some(value) = arg_str.strip_prefix("--undefok=") {
            value
        } else if arg_str == "--undefok" {
            let next = iter
                .next()
                .ok_or_else(|| anyhow!("--undefok requires a comma-separated value"))?;
            next.to_str()
                .ok_or_else(|| anyhow!("--undefok value must be valid UTF-8"))?
        } else {
            continue;
        };

        for raw_name in value.split(',') {
            configured.insert(normalize_undefok_name(raw_name)?);
        }
    }

    Ok(configured)
}

fn validate_undefok_flags<T: CommandFactory>(configured: &HashSet<String>) -> Result<()> {
    let active_longs: HashSet<String> = T::command()
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_owned))
        .collect();

    for configured_name in configured {
        if active_longs.contains(configured_name) {
            bail!(
                "--undefok entry --{} conflicts with an active clap option",
                configured_name
            );
        }
    }

    Ok(())
}

fn filter_undefok_args(
    args: Vec<OsString>,
    configured_undefok_flags: &HashSet<String>,
) -> (Vec<OsString>, Vec<IgnoredUndefOkFlag>) {
    let mut filtered = Vec::with_capacity(args.len());
    let mut ignored_undefok_flags = Vec::new();
    let mut iter = args.into_iter().peekable();

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            filtered.push(arg);
            continue;
        };

        if arg_str == "--undefok" {
            filtered.push(arg);
            if let Some(next) = iter.next() {
                filtered.push(next);
            }
            continue;
        }

        if arg_str.starts_with("--undefok=") {
            filtered.push(arg);
            continue;
        }

        if !arg_str.starts_with("--") || arg_str == "--" {
            filtered.push(arg);
            continue;
        }

        let body = &arg_str[2..];
        let (name, has_inline_value) = match body.split_once('=') {
            Some((name, _)) => (name, true),
            None => (body, false),
        };

        if !configured_undefok_flags.contains(name) {
            filtered.push(arg);
            continue;
        }

        ignored_undefok_flags.push(IgnoredUndefOkFlag {
            long: name.to_owned(),
            note: lookup_known_undefok_flag(name).map(|undefok| undefok.note),
        });

        if !has_inline_value {
            let should_consume_value = iter
                .peek()
                .and_then(|next| next.to_str())
                .is_some_and(|next| !next.starts_with('-'));
            if should_consume_value {
                let _ = iter.next();
            }
        }
    }

    (filtered, ignored_undefok_flags)
}

pub fn parse_args<T>() -> Result<ParsedArgs<T>>
where
    T: Parser + CommandFactory,
{
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    let configured_undefok_flags = collect_configured_undefok_flags(&raw_args)?;
    validate_undefok_flags::<T>(&configured_undefok_flags)?;

    let (filtered_args, ignored_undefok_flags) =
        filter_undefok_args(raw_args, &configured_undefok_flags);
    let opts = T::try_parse_from(filtered_args).context("parsing command-line arguments")?;

    Ok(ParsedArgs {
        opts,
        ignored_undefok_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn os_vec(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.into_string().expect("test args must be valid UTF-8"))
            .collect()
    }

    #[derive(Debug, Parser)]
    struct NoOverlapOpts {
        #[clap(long, value_delimiter = ',')]
        undefok: Vec<String>,
        #[clap(long)]
        monitor_interval_s: Option<u64>,
    }

    #[test]
    fn collects_inline_undefok_entries() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=reconfiguration-interval-s,rebalance-cpus-interval-s",
        ]))
        .expect("inline undefok should parse");

        assert!(configured.contains("reconfiguration-interval-s"));
        assert!(configured.contains("rebalance-cpus-interval-s"));
    }

    #[test]
    fn collects_separate_undefok_value() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok",
            "reconfiguration-interval-s",
        ]))
        .expect("separate undefok should parse");

        assert!(configured.contains("reconfiguration-interval-s"));
    }

    #[test]
    fn filters_configured_undefok_flag_with_inline_value() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=reconfiguration-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_mitosis",
                "--undefok=reconfiguration-interval-s",
                "--reconfiguration-interval-s=10",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_mitosis",
                "--undefok=reconfiguration-interval-s",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].long, "reconfiguration-interval-s");
        assert!(ignored[0].note.is_some());
    }

    #[test]
    fn filters_configured_undefok_flag_with_separate_value() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=rebalance-cpus-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_mitosis",
                "--undefok=rebalance-cpus-interval-s",
                "--rebalance-cpus-interval-s",
                "5",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_mitosis",
                "--undefok=rebalance-cpus-interval-s",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].long, "rebalance-cpus-interval-s");
    }

    #[test]
    fn missing_undefok_value_does_not_consume_next_flag() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=rebalance-cpus-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_mitosis",
                "--undefok=rebalance-cpus-interval-s",
                "--rebalance-cpus-interval-s",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_mitosis",
                "--undefok=rebalance-cpus-interval-s",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert_eq!(ignored.len(), 1);
    }

    #[test]
    fn unknown_flags_are_left_for_clap_when_not_listed_in_undefok() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=reconfiguration-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_mitosis",
                "--undefok=reconfiguration-interval-s",
                "--unknown-flag",
                "value",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_mitosis",
                "--undefok=reconfiguration-interval-s",
                "--unknown-flag",
                "value",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn validation_accepts_non_overlapping_flags() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=reconfiguration-interval-s",
        ]))
        .expect("undefok should parse");

        validate_undefok_flags::<NoOverlapOpts>(&configured)
            .expect("non-overlapping undefok should validate");
    }

    #[test]
    fn validation_rejects_active_flag_in_undefok() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=monitor-interval-s",
        ]))
        .expect("undefok should parse");

        let err = validate_undefok_flags::<NoOverlapOpts>(&configured)
            .expect_err("active option in undefok should fail");
        assert!(
            err.to_string()
                .contains("--undefok entry --monitor-interval-s conflicts"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_empty_undefok_entry() {
        let err = collect_configured_undefok_flags(&os_vec(&[
            "scx_mitosis",
            "--undefok=reconfiguration-interval-s,",
        ]))
        .expect_err("empty undefok entry should fail");

        assert!(
            err.to_string()
                .contains("--undefok entries must not be empty"),
            "unexpected error: {err}"
        );
    }
}
