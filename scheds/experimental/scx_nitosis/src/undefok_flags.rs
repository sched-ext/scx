use std::collections::HashSet;
use std::ffi::OsString;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};

pub struct IgnoredUndefOkFlag {
    pub long: String,
}

pub struct ParsedArgs<T> {
    pub opts: T,
    pub ignored_undefok_flags: Vec<IgnoredUndefOkFlag>,
}

fn normalize_undefok_name(name: &str) -> Result<String> {
    let normalized = name.trim();
    if normalized.is_empty() {
        bail!("--undefok entries must not be empty");
    }
    if normalized.starts_with('-') {
        bail!("--undefok entries must not include leading dashes");
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

fn filter_undefok_args(
    args: Vec<OsString>,
    configured_undefok_flags: &HashSet<String>,
    active_longs: &HashSet<String>,
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

        if !configured_undefok_flags.contains(name) || active_longs.contains(name) {
            filtered.push(arg);
            continue;
        }

        ignored_undefok_flags.push(IgnoredUndefOkFlag {
            long: name.to_owned(),
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

fn parse_args_from<T>(raw_args: Vec<OsString>) -> Result<ParsedArgs<T>>
where
    T: Parser + CommandFactory,
{
    let configured_undefok_flags = collect_configured_undefok_flags(&raw_args)?;
    let active_longs: HashSet<String> = T::command()
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_owned))
        .collect();

    let (filtered_args, ignored_undefok_flags) =
        filter_undefok_args(raw_args, &configured_undefok_flags, &active_longs);
    let opts = T::try_parse_from(filtered_args).context("parsing command-line arguments")?;

    Ok(ParsedArgs {
        opts,
        ignored_undefok_flags,
    })
}

pub fn parse_args<T>() -> Result<ParsedArgs<T>>
where
    T: Parser + CommandFactory,
{
    parse_args_from(std::env::args_os().collect())
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
            "scx_nitosis",
            "--undefok=reconfiguration-interval-s,rebalance-cpus-interval-s",
        ]))
        .expect("inline undefok should parse");

        assert!(configured.contains("reconfiguration-interval-s"));
        assert!(configured.contains("rebalance-cpus-interval-s"));
    }

    #[test]
    fn collects_separate_undefok_value() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok",
            "reconfiguration-interval-s",
        ]))
        .expect("separate undefok should parse");

        assert!(configured.contains("reconfiguration-interval-s"));
    }

    #[test]
    fn filters_configured_undefok_flag_with_inline_value() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok=reconfiguration-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_nitosis",
                "--undefok=reconfiguration-interval-s",
                "--reconfiguration-interval-s=10",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
            &HashSet::from([String::from("monitor-interval-s")]),
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_nitosis",
                "--undefok=reconfiguration-interval-s",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].long, "reconfiguration-interval-s");
    }

    #[test]
    fn filters_configured_undefok_flag_with_separate_value() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok=rebalance-cpus-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_nitosis",
                "--undefok=rebalance-cpus-interval-s",
                "--rebalance-cpus-interval-s",
                "5",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
            &HashSet::from([String::from("monitor-interval-s")]),
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_nitosis",
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
            "scx_nitosis",
            "--undefok=rebalance-cpus-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_nitosis",
                "--undefok=rebalance-cpus-interval-s",
                "--rebalance-cpus-interval-s",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
            &HashSet::from([String::from("monitor-interval-s")]),
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_nitosis",
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
            "scx_nitosis",
            "--undefok=reconfiguration-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_nitosis",
                "--undefok=reconfiguration-interval-s",
                "--unknown-flag",
                "value",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
            &HashSet::from([String::from("monitor-interval-s")]),
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_nitosis",
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
    fn listed_flag_may_be_absent() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok=reconfiguration-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_nitosis",
                "--undefok=reconfiguration-interval-s",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
            &HashSet::from([String::from("monitor-interval-s")]),
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_nitosis",
                "--undefok=reconfiguration-interval-s",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn active_flag_may_be_listed_in_undefok_without_being_filtered() {
        let configured = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok=monitor-interval-s",
        ]))
        .expect("undefok should parse");

        let (filtered, ignored) = filter_undefok_args(
            os_vec(&[
                "scx_nitosis",
                "--undefok=monitor-interval-s",
                "--monitor-interval-s",
                "2",
            ]),
            &configured,
            &HashSet::from([String::from("monitor-interval-s")]),
        );

        assert_eq!(
            strings(filtered),
            vec![
                "scx_nitosis",
                "--undefok=monitor-interval-s",
                "--monitor-interval-s",
                "2"
            ]
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn rejects_empty_undefok_entry() {
        let err = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok=reconfiguration-interval-s,",
        ]))
        .expect_err("empty undefok entry should fail");

        assert!(
            err.to_string()
                .contains("--undefok entries must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_undefok_entry_with_leading_dashes() {
        let err = collect_configured_undefok_flags(&os_vec(&[
            "scx_nitosis",
            "--undefok=--reconfiguration-interval-s",
        ]))
        .expect_err("leading dashes in undefok entries should fail");

        assert!(
            err.to_string()
                .contains("--undefok entries must not include leading dashes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_from_keeps_active_flag_functional_when_listed_in_undefok() {
        let parsed = parse_args_from::<NoOverlapOpts>(os_vec(&[
            "scx_nitosis",
            "--undefok=monitor-interval-s",
            "--monitor-interval-s",
            "2",
        ]))
        .expect("active flags listed in undefok should still parse");

        assert_eq!(parsed.opts.undefok, vec!["monitor-interval-s"]);
        assert_eq!(parsed.opts.monitor_interval_s, Some(2));
        assert!(parsed.ignored_undefok_flags.is_empty());
    }

    #[test]
    fn parse_from_ignores_and_records_unknown_flag_listed_in_undefok() {
        let parsed = parse_args_from::<NoOverlapOpts>(os_vec(&[
            "scx_nitosis",
            "--undefok=reconfiguration-interval-s",
            "--reconfiguration-interval-s",
            "10",
            "--monitor-interval-s",
            "2",
        ]))
        .expect("unknown flags listed in undefok should be ignored");

        assert_eq!(parsed.opts.undefok, vec!["reconfiguration-interval-s"]);
        assert_eq!(parsed.opts.monitor_interval_s, Some(2));
        assert_eq!(parsed.ignored_undefok_flags.len(), 1);
        assert_eq!(
            parsed.ignored_undefok_flags[0].long,
            "reconfiguration-interval-s"
        );
    }

    #[test]
    fn parse_from_rejects_unknown_flag_not_listed_in_undefok() {
        let err = match parse_args_from::<NoOverlapOpts>(os_vec(&[
            "scx_nitosis",
            "--unknown-flag",
            "10",
        ])) {
            Ok(_) => panic!("unknown flags not listed in undefok should still fail"),
            Err(err) => err,
        };

        assert!(
            err.chain().any(|cause| cause
                .to_string()
                .contains("unexpected argument '--unknown-flag'")),
            "unexpected error: {err}"
        );
    }
}
