//! Compact formatting helpers for trace output.

use std::fmt;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

use crate::kfuncs::sim_clock;
use crate::types::TimeNs;

/// Wrapper that displays large round numbers compactly.
///
/// Exact multiples of powers of 1000 are shortened:
/// - `1_000` → `1K`
/// - `20_000_000` → `20M`
/// - `3_000_000_000` → `3B`
/// - `1_000_000_000_000` → `1T`
///
/// Non-round numbers pass through unchanged: `12345` → `12345`.
pub struct FmtN(pub u64);

impl fmt::Display for FmtN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self.0;
        const SUFFIXES: &[(u64, &str)] = &[
            (1_000_000_000_000, "T"),
            (1_000_000_000, "B"),
            (1_000_000, "M"),
            (1_000, "K"),
        ];
        for &(divisor, suffix) in SUFFIXES {
            if v >= divisor && v.is_multiple_of(divisor) {
                return write!(f, "{}{}", v / divisor, suffix);
            }
        }
        write!(f, "{v}")
    }
}

/// Whether a timestamp is a per-CPU local time or a global time.
#[derive(Debug, Clone, Copy)]
pub enum TsKind {
    Local,
    Global,
}

/// Timestamp formatter with underscore-grouped digits and `:L`/`:G` suffix.
///
/// Formats nanosecond timestamps for trace output with room for 12 digits
/// (up to ~15 seconds), grouped in 3s with underscores, right-aligned
/// in a 15-char field plus a 2-char suffix.
///
/// Examples:
/// - `0` → `              0:L`
/// - `10_000` → `         10_000:L`
/// - `20_000_000` → `     20_000_000:L`
/// - `999_999_000_000` → `999_999_000_000:G`
pub struct FmtTs {
    pub ns: TimeNs,
    pub kind: TsKind,
}

impl FmtTs {
    pub fn local(ns: TimeNs) -> Self {
        Self {
            ns,
            kind: TsKind::Local,
        }
    }

    pub fn global(ns: TimeNs) -> Self {
        Self {
            ns,
            kind: TsKind::Global,
        }
    }
}

/// Format a u64 with underscore grouping (groups of 3 from the right).
pub(crate) fn fmt_grouped(v: u64) -> String {
    let digits = v.to_string();
    let len = digits.len();
    if len <= 3 {
        return digits;
    }
    let mut result = String::with_capacity(len + (len - 1) / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push('_');
        }
        result.push(ch);
    }
    result
}

impl fmt::Display for FmtTs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let grouped = fmt_grouped(self.ns);
        let suffix = match self.kind {
            TsKind::Local => ":L",
            TsKind::Global => ":G",
        };
        // 15 chars for the grouped number, 2 for suffix = 17 total
        write!(f, "{:>15}{}", grouped, suffix)
    }
}

/// Custom event formatter that shows simulator virtual time instead of
/// wall-clock time and uses plain colored text (no italic/background).
pub struct SimFormat;

impl<S, N> FormatEvent<S, N> for SimFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Simulated timestamp
        let clock = sim_clock();
        write!(writer, "[{}] ", FmtTs::local(clock))?;

        // Level with color (no italic, no background)
        let level = *event.metadata().level();
        if writer.has_ansi_escapes() {
            let color = match level {
                Level::ERROR => "\x1b[31m", // red
                Level::WARN => "\x1b[33m",  // yellow
                Level::INFO => "\x1b[32m",  // green
                Level::DEBUG => "\x1b[34m", // blue
                Level::TRACE => "\x1b[35m", // magenta
            };
            write!(writer, "{color}{level:>5}\x1b[0m ")?;
        } else {
            write!(writer, "{level:>5} ")?;
        }

        // Collect fields and message
        let mut visitor = FieldCollector::default();
        event.record(&mut visitor);

        // Message first
        write!(writer, "{}", visitor.message)?;

        // Then fields as plain key=value (no italic ANSI)
        for (key, value) in &visitor.fields {
            write!(writer, " {key}={value}")?;
        }

        writeln!(writer)
    }
}

/// Visitor that collects the message and key-value fields from a tracing event.
#[derive(Default)]
struct FieldCollector {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_n() {
        assert_eq!(FmtN(0).to_string(), "0");
        assert_eq!(FmtN(999).to_string(), "999");
        assert_eq!(FmtN(1_000).to_string(), "1K");
        assert_eq!(FmtN(20_000).to_string(), "20K");
        assert_eq!(FmtN(1_500).to_string(), "1500");
        assert_eq!(FmtN(1_000_000).to_string(), "1M");
        assert_eq!(FmtN(20_000_000).to_string(), "20M");
        assert_eq!(FmtN(3_000_000_000).to_string(), "3B");
        assert_eq!(FmtN(1_000_000_000_000).to_string(), "1T");
        assert_eq!(FmtN(12345).to_string(), "12345");
        assert_eq!(FmtN(5_000_000).to_string(), "5M");
        assert_eq!(FmtN(100_000_000).to_string(), "100M");
    }

    #[test]
    fn test_fmt_grouped() {
        assert_eq!(fmt_grouped(0), "0");
        assert_eq!(fmt_grouped(999), "999");
        assert_eq!(fmt_grouped(1_000), "1_000");
        assert_eq!(fmt_grouped(10_000), "10_000");
        assert_eq!(fmt_grouped(20_000_000), "20_000_000");
        assert_eq!(fmt_grouped(999_999_000_000), "999_999_000_000");
        assert_eq!(fmt_grouped(1_234_567), "1_234_567");
    }

    #[test]
    fn test_fmt_ts() {
        assert_eq!(FmtTs::local(0).to_string(), "              0:L");
        assert_eq!(FmtTs::local(10_000).to_string(), "         10_000:L");
        assert_eq!(FmtTs::local(20_000_000).to_string(), "     20_000_000:L");
        assert_eq!(
            FmtTs::global(999_999_000_000).to_string(),
            "999_999_000_000:G"
        );
    }
}
