use std::fmt;
use std::sync::MutexGuard;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

use scx_simulator::{sim_clock, FmtN, SIM_LOCK};

/// Acquire the simulator lock and initialize tracing from `RUST_LOG`.
///
/// Returns the lock guard — hold it for the duration of the test.
/// `try_init()` is idempotent: first call in the process succeeds,
/// subsequent calls are silently ignored.
pub fn setup_test() -> MutexGuard<'static, ()> {
    let guard = SIM_LOCK.lock().unwrap();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .event_format(SimFormat)
        .try_init();
    guard
}

/// Custom event formatter that shows simulator virtual time instead of
/// wall-clock time and uses plain colored text (no italic/background).
struct SimFormat;

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
        write!(writer, "[{:>12}] ", FmtN(clock))?;

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
