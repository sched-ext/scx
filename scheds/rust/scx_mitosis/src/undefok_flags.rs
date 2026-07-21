use std::collections::HashSet;
use std::ffi::OsString;

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser};

pub struct UndefOkFlag {
    pub long: &'static str,
    pub takes_value: bool,
    // Short operator-facing explanation shown when we accept a flag only for
    // compatibility during a CLI transition.
    pub note: &'static str,
}

pub struct ParsedArgs<T> {
    pub opts: T,
    pub ignored_undefok_flags: Vec<&'static UndefOkFlag>,
}

const UNDEFOK_FLAGS: &[UndefOkFlag] = &[
    UndefOkFlag {
        long: "reconfiguration-interval-s",
        takes_value: true,
        note: "accepted for CLI compatibility during rollout; cell reconfiguration is driven internally, not by a CLI interval",
    },
    UndefOkFlag {
        long: "rebalance-cpus-interval-s",
        takes_value: true,
        note: "accepted for CLI compatibility during rollout; CPU rebalancing cadence is controlled by the remaining active knobs",
    },
];

fn validate_undefok_flags<T: CommandFactory>() -> Result<()> {
    let mut undefok_names = HashSet::new();
    for undefok in UNDEFOK_FLAGS {
        if !undefok_names.insert(undefok.long) {
            bail!("duplicate undefok flag entry --{}", undefok.long);
        }
    }

    let active_longs: HashSet<String> = T::command()
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_owned))
        .collect();

    for undefok in UNDEFOK_FLAGS {
        if active_longs.contains(undefok.long) {
            bail!(
                "undefok flag --{} still exists in active clap options",
                undefok.long
            );
        }
    }

    Ok(())
}

fn lookup_undefok_flag(name: &str) -> Option<&'static UndefOkFlag> {
    UNDEFOK_FLAGS.iter().find(|undefok| undefok.long == name)
}

fn filter_undefok_args(args: Vec<OsString>) -> (Vec<OsString>, Vec<&'static UndefOkFlag>) {
    let mut filtered = Vec::with_capacity(args.len());
    let mut ignored_undefok_flags = Vec::new();
    let mut iter = args.into_iter().peekable();

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            filtered.push(arg);
            continue;
        };

        if !arg_str.starts_with("--") || arg_str == "--" {
            filtered.push(arg);
            continue;
        }

        let body = &arg_str[2..];
        let (name, has_inline_value) = match body.split_once('=') {
            Some((name, _)) => (name, true),
            None => (body, false),
        };

        let Some(undefok) = lookup_undefok_flag(name) else {
            filtered.push(arg);
            continue;
        };

        ignored_undefok_flags.push(undefok);

        if undefok.takes_value && !has_inline_value {
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
    validate_undefok_flags::<T>()?;

    let raw_args: Vec<OsString> = std::env::args_os().collect();
    let (filtered_args, ignored_undefok_flags) = filter_undefok_args(raw_args);
    let opts = T::try_parse_from(filtered_args)?;

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
        #[clap(long)]
        monitor_interval_s: Option<u64>,
    }

    #[test]
    fn filters_undefok_flag_with_inline_value() {
        let (filtered, ignored) = filter_undefok_args(os_vec(&[
            "scx_mitosis",
            "--reconfiguration-interval-s=10",
            "--monitor-interval-s",
            "2",
        ]));

        assert_eq!(
            strings(filtered),
            vec!["scx_mitosis", "--monitor-interval-s", "2"]
        );
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].long, "reconfiguration-interval-s");
    }

    #[test]
    fn filters_undefok_flag_with_separate_value() {
        let (filtered, ignored) = filter_undefok_args(os_vec(&[
            "scx_mitosis",
            "--rebalance-cpus-interval-s",
            "5",
            "--monitor-interval-s",
            "2",
        ]));

        assert_eq!(
            strings(filtered),
            vec!["scx_mitosis", "--monitor-interval-s", "2"]
        );
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].long, "rebalance-cpus-interval-s");
    }

    #[test]
    fn missing_undefok_value_does_not_consume_next_flag() {
        let (filtered, ignored) = filter_undefok_args(os_vec(&[
            "scx_mitosis",
            "--rebalance-cpus-interval-s",
            "--monitor-interval-s",
            "2",
        ]));

        assert_eq!(
            strings(filtered),
            vec!["scx_mitosis", "--monitor-interval-s", "2"]
        );
        assert_eq!(ignored.len(), 1);
    }

    #[test]
    fn unknown_flags_are_left_for_clap() {
        let (filtered, ignored) = filter_undefok_args(os_vec(&[
            "scx_mitosis",
            "--unknown-flag",
            "value",
            "--monitor-interval-s",
            "2",
        ]));

        assert_eq!(
            strings(filtered),
            vec![
                "scx_mitosis",
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
        validate_undefok_flags::<NoOverlapOpts>().expect("non-overlapping flags should validate");
    }

    #[derive(Debug, Parser)]
    struct OverlapOpts {
        #[clap(long)]
        reconfiguration_interval_s: Option<u64>,
    }

    #[test]
    fn validation_rejects_overlapping_flags() {
        let err = validate_undefok_flags::<OverlapOpts>().expect_err("overlap should fail");
        assert!(
            err.to_string()
                .contains("undefok flag --reconfiguration-interval-s still exists"),
            "unexpected error: {err}"
        );
    }
}
