use std::fmt;
use std::sync::MutexGuard;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

use scx_simulator::{sim_clock, FmtTs, SIM_LOCK};

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

/// Generate a suite of scheduler-generic tests.
///
/// `$make_sched` is a closure `|nr_cpus: u32| -> DynamicScheduler` that
/// constructs the scheduler under test. Tests that need multiple CPUs
/// pass the appropriate count; single-CPU tests pass 1.
///
/// Usage:
/// ```ignore
/// mod common;
/// common::scheduler_tests!(|n| DynamicScheduler::tickless(n));
/// ```
#[macro_export]
macro_rules! scheduler_tests {
    ($make_sched:expr) => {
        use std::collections::HashSet;

        /// Smoke test: single task on single CPU runs to completion.
        #[test]
        fn test_single_task_single_cpu() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(1)
                .task(TaskDef {
                    name: "worker".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(5_000_000)],
                        repeat: false,
                    },
                    start_time_ns: 0,
                })
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            assert!(trace.schedule_count(Pid(1)) > 0, "task was never scheduled");
            assert!(
                trace.events().iter().any(|e| matches!(
                    e.kind,
                    TraceKind::TaskCompleted { pid } if pid == Pid(1)
                )),
                "task did not complete"
            );
            let runtime = trace.total_runtime(Pid(1));
            assert!(runtime == 5_000_000, "expected 5ms runtime, got {runtime}ns");
        }

        /// Multiple tasks on a single CPU should all get scheduled.
        #[test]
        fn test_multiple_tasks_single_cpu() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(1)
                .task(TaskDef {
                    name: "t1".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(20_000_000)],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .task(TaskDef {
                    name: "t2".into(),
                    pid: Pid(2),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(20_000_000)],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            assert!(trace.schedule_count(Pid(1)) > 0, "task 1 was never scheduled");
            assert!(trace.schedule_count(Pid(2)) > 0, "task 2 was never scheduled");
            let rt1 = trace.total_runtime(Pid(1));
            let rt2 = trace.total_runtime(Pid(2));
            assert!(rt1 > 0, "task 1 got no runtime");
            assert!(rt2 > 0, "task 2 got no runtime");
        }

        /// Tasks on multiple CPUs should spread across CPUs.
        #[test]
        fn test_multiple_cpus() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(4)
                .task(TaskDef {
                    name: "t1".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(50_000_000)],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .task(TaskDef {
                    name: "t2".into(),
                    pid: Pid(2),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(50_000_000)],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(4)).run(scenario);

            assert!(trace.total_runtime(Pid(1)) > 0);
            assert!(trace.total_runtime(Pid(2)) > 0);

            let cpus_used: HashSet<CpuId> = trace
                .events()
                .iter()
                .filter_map(|e| match e.kind {
                    TraceKind::TaskScheduled { .. } => Some(e.cpu),
                    _ => None,
                })
                .collect();

            assert!(
                cpus_used.len() >= 2,
                "expected tasks to spread across CPUs, but only used {:?}",
                cpus_used
            );
        }

        /// Determinism: same scenario should produce identical traces.
        #[test]
        fn test_determinism() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let make_scenario = || {
                Scenario::builder()
                    .cpus(2)
                    .task(TaskDef {
                        name: "t1".into(),
                        pid: Pid(1),
                        nice: 0,
                        behavior: TaskBehavior {
                            phases: vec![Phase::Run(10_000_000)],
                            repeat: true,
                        },
                        start_time_ns: 0,
                    })
                    .task(TaskDef {
                        name: "t2".into(),
                        pid: Pid(2),
                        nice: -3,
                        behavior: TaskBehavior {
                            phases: vec![Phase::Run(10_000_000)],
                            repeat: true,
                        },
                        start_time_ns: 0,
                    })
                    .duration_ms(50)
                    .build()
            };

            let trace1 = Simulator::new(sched_factory(2)).run(make_scenario());
            let trace2 = Simulator::new(sched_factory(2)).run(make_scenario());

            assert_eq!(
                trace1.events().len(),
                trace2.events().len(),
                "traces have different lengths"
            );

            for (i, (e1, e2)) in trace1
                .events()
                .iter()
                .zip(trace2.events().iter())
                .enumerate()
            {
                assert_eq!(
                    e1.time_ns, e2.time_ns,
                    "event {i}: timestamps differ: {} vs {}",
                    e1.time_ns, e2.time_ns
                );
                assert_eq!(
                    e1.cpu, e2.cpu,
                    "event {i}: CPUs differ: {:?} vs {:?}",
                    e1.cpu, e2.cpu
                );
                assert_eq!(
                    e1.kind, e2.kind,
                    "event {i}: kinds differ: {:?} vs {:?}",
                    e1.kind, e2.kind
                );
            }
        }

        /// Equal-weight tasks on 1 CPU should get roughly equal runtime.
        #[test]
        fn test_equal_weight_fairness() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(1)
                .task(TaskDef {
                    name: "t1".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(100_000_000)],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .task(TaskDef {
                    name: "t2".into(),
                    pid: Pid(2),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![Phase::Run(100_000_000)],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .duration_ms(200)
                .build();

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            let rt1 = trace.total_runtime(Pid(1));
            let rt2 = trace.total_runtime(Pid(2));

            assert!(rt1 > 0, "task 1 got no runtime");
            assert!(rt2 > 0, "task 2 got no runtime");

            // Both should get at least 25% of total runtime
            let total = rt1 + rt2;
            assert!(
                rt1 >= total / 4 && rt2 >= total / 4,
                "expected both tasks to get at least 25% runtime: t1={rt1}ns, t2={rt2}ns"
            );
        }

        /// Sleep/wake cycle: task should run multiple times and accumulate
        /// the expected runtime across cycles.
        #[test]
        fn test_sleep_wake_cycle() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(1)
                .task(TaskDef {
                    name: "sleeper".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![
                            Phase::Run(5_000_000),    // run 5ms
                            Phase::Sleep(10_000_000), // sleep 10ms
                        ],
                        repeat: true,
                    },
                    start_time_ns: 0,
                })
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            let count = trace.schedule_count(Pid(1));
            assert!(count > 1, "expected multiple schedules, got {count}");

            // Runtime should be about 5ms per cycle, ~6-7 cycles in 100ms
            // (15ms per cycle => ~33ms total runtime)
            let runtime = trace.total_runtime(Pid(1));
            assert!(
                runtime > 20_000_000 && runtime < 40_000_000,
                "expected ~33ms runtime, got {runtime}ns"
            );
        }
    };
}
