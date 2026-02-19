//! Parser for rt-app JSON workload descriptions.
//!
//! Converts rt-app JSON files into simulator [`Scenario`] objects, enabling
//! the same workload to run both for real (via rt-app) and in simulation.
//!
//! # Supported rt-app features
//!
//! - `run` / `runtime` — CPU-bound work (mapped to [`Phase::Run`])
//! - `sleep` — fixed-duration sleep (mapped to [`Phase::Sleep`])
//! - `suspend` — self-suspend until resumed (mapped to `Phase::Sleep(u64::MAX)`)
//! - `resume` — wake another task (mapped to [`Phase::Wake`])
//! - `timer` — periodic timer (approximated as `Phase::Sleep(period)`)
//! - `priority` — nice value
//! - `loop` — repetition control
//! - `phases` — multi-phase task definitions
//! - `instance` — multiple task instances
//! - `cpus` — CPU affinity mask (parsed into `TaskDef::allowed_cpus`)
//! - `global.duration` — scenario duration
//!
//! # Limitations
//!
//! - JSON files with duplicate keys (common in rt-app) must be preprocessed
//!   with rt-app's `workgen` script or use suffixed keys (`"run0"`, `"run1"`).
//! - Unsupported events (`lock`, `unlock`, `wait`, `signal`, `broad`, `sync`,
//!   `mem`, `iorun`, `yield`, `barrier`, `fork`) are skipped with a warning.
//! - Cgroup (`taskgroup`) is not modeled.

use std::collections::HashMap;

use serde_json::{Map, Value};
use tracing::warn;

use crate::scenario::{
    sched_overhead_rbc_ns_from_env, seed_from_env, NoiseConfig, OverheadConfig, Scenario,
};
use crate::task::{Phase, RepeatMode, TaskBehavior, TaskDef};
use crate::types::{CpuId, Pid};

/// Errors from parsing rt-app JSON.
#[derive(Debug)]
pub enum RtAppError {
    /// JSON parse error.
    Json(serde_json::Error),
    /// Missing required field.
    MissingField(&'static str),
    /// Invalid field value.
    InvalidValue(String),
    /// Unresolved task reference in `resume`.
    UnresolvedResume(String),
}

impl std::fmt::Display for RtAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RtAppError::Json(e) => write!(f, "JSON parse error: {e}"),
            RtAppError::MissingField(field) => write!(f, "missing required field: {field}"),
            RtAppError::InvalidValue(msg) => write!(f, "invalid value: {msg}"),
            RtAppError::UnresolvedResume(name) => {
                write!(f, "unresolved resume target: {name:?}")
            }
        }
    }
}

impl From<serde_json::Error> for RtAppError {
    fn from(e: serde_json::Error) -> Self {
        RtAppError::Json(e)
    }
}

/// Strip C-style block comments (`/* ... */`) from input.
fn strip_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' {
            if chars.peek() == Some(&'*') {
                chars.next(); // consume '*'
                              // Skip until '*/'
                loop {
                    match chars.next() {
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next(); // consume '/'
                            break;
                        }
                        Some(_) => continue,
                        None => break, // unterminated comment, just stop
                    }
                }
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Identify which rt-app event type a key represents, using prefix matching.
///
/// Returns `None` for non-event keys (like `loop`, `cpus`, `policy`, etc.).
fn classify_event(key: &str) -> Option<&'static str> {
    // Order matters: check longer prefixes first to avoid "run" matching "runtime"
    const EVENT_PREFIXES: &[&str] = &[
        "runtime", "run", "sleep", "timer", "suspend", "resume", "lock", "unlock", "wait",
        "signal", "broad", "sync", "mem", "iorun", "yield", "barrier", "fork",
    ];
    EVENT_PREFIXES
        .iter()
        .find(|&&prefix| key.len() >= prefix.len() && &key[..prefix.len()] == prefix)
        .copied()
}

/// Non-event keys that are valid at phase/task level.
const TASK_PHASE_KEYS: &[&str] = &[
    "loop",
    "phases",
    "instance",
    "delay",
    "policy",
    "priority",
    "cpus",
    "nodes_membind",
    "taskgroup",
    "dl-runtime",
    "dl-period",
    "dl-deadline",
    "util_min",
    "util_max",
];

/// Parse events from a phase/task object's key-value pairs (in insertion order).
fn parse_events(
    obj: &Map<String, Value>,
    name_to_pid: &HashMap<String, Pid>,
) -> Result<Vec<Phase>, RtAppError> {
    let mut phases = Vec::new();

    for (key, value) in obj.iter() {
        // Skip non-event keys
        if TASK_PHASE_KEYS.contains(&key.as_str()) {
            continue;
        }

        let event_type = match classify_event(key) {
            Some(t) => t,
            None => {
                // Unknown key — might be a phase-level property we don't know about
                continue;
            }
        };

        match event_type {
            "run" | "runtime" => {
                let usec = value
                    .as_u64()
                    .or_else(|| value.as_i64().map(|v| v as u64))
                    .ok_or_else(|| RtAppError::InvalidValue(format!("{key}: expected integer")))?;
                phases.push(Phase::Run(usec * 1_000)); // usec → ns
            }
            "sleep" => {
                let usec = value
                    .as_u64()
                    .or_else(|| value.as_i64().map(|v| v as u64))
                    .ok_or_else(|| RtAppError::InvalidValue(format!("{key}: expected integer")))?;
                phases.push(Phase::Sleep(usec * 1_000));
            }
            "timer" => {
                // Timer: approximate as sleep for the period duration
                let period_usec = if let Some(obj) = value.as_object() {
                    obj.get("period").and_then(|v| v.as_u64()).unwrap_or(0)
                } else {
                    value.as_u64().unwrap_or(0)
                };
                if period_usec > 0 {
                    phases.push(Phase::Sleep(period_usec * 1_000));
                }
            }
            "suspend" => {
                // Self-suspend: sleep indefinitely until woken by resume
                phases.push(Phase::Sleep(u64::MAX));
            }
            "resume" => {
                let target_name = value
                    .as_str()
                    .ok_or_else(|| RtAppError::InvalidValue(format!("{key}: expected string")))?;
                let target_pid = name_to_pid
                    .get(target_name)
                    .ok_or_else(|| RtAppError::UnresolvedResume(target_name.to_string()))?;
                phases.push(Phase::Wake(*target_pid));
            }
            unsupported => {
                warn!(
                    event = unsupported,
                    key = key.as_str(),
                    "skipping unsupported rt-app event"
                );
            }
        }
    }

    Ok(phases)
}

/// Parse an rt-app CPU affinity string into a list of CPU IDs.
///
/// rt-app supports several formats:
/// - Single CPU: `"0"` or `0`
/// - Comma-separated: `"0,2,4"`
/// - Range: `"0-3"` (expands to 0,1,2,3)
/// - Mixed: `"0,2-4,6"` (expands to 0,2,3,4,6)
/// - JSON array: `[0, 1, 2]`
fn parse_cpus(value: &Value) -> Result<Option<Vec<CpuId>>, RtAppError> {
    match value {
        Value::String(s) => {
            let mut cpus = Vec::new();
            for part in s.split(',') {
                let part = part.trim();
                if let Some((start, end)) = part.split_once('-') {
                    let start: u32 = start.trim().parse().map_err(|_| {
                        RtAppError::InvalidValue(format!("cpus: invalid range start {start:?}"))
                    })?;
                    let end: u32 = end.trim().parse().map_err(|_| {
                        RtAppError::InvalidValue(format!("cpus: invalid range end {end:?}"))
                    })?;
                    for cpu in start..=end {
                        cpus.push(CpuId(cpu));
                    }
                } else {
                    let cpu: u32 = part.parse().map_err(|_| {
                        RtAppError::InvalidValue(format!("cpus: invalid cpu {part:?}"))
                    })?;
                    cpus.push(CpuId(cpu));
                }
            }
            if cpus.is_empty() {
                Ok(None)
            } else {
                Ok(Some(cpus))
            }
        }
        Value::Number(n) => {
            let cpu = n.as_u64().ok_or_else(|| {
                RtAppError::InvalidValue(format!("cpus: expected unsigned integer, got {n}"))
            })? as u32;
            Ok(Some(vec![CpuId(cpu)]))
        }
        Value::Array(arr) => {
            let mut cpus = Vec::new();
            for v in arr {
                let cpu = v.as_u64().ok_or_else(|| {
                    RtAppError::InvalidValue(format!("cpus: array element not an integer: {v}"))
                })? as u32;
                cpus.push(CpuId(cpu));
            }
            if cpus.is_empty() {
                Ok(None)
            } else {
                Ok(Some(cpus))
            }
        }
        _ => {
            warn!("cpus: unexpected type, ignoring");
            Ok(None)
        }
    }
}

/// Parse a single rt-app task object into one or more `TaskDef`s.
///
/// Multiple `TaskDef`s are produced when `instance > 1`.
fn parse_task(
    name: &str,
    obj: &Map<String, Value>,
    pid_start: &mut i32,
    name_to_pid: &HashMap<String, Pid>,
) -> Result<Vec<TaskDef>, RtAppError> {
    let instance_count = obj.get("instance").and_then(|v| v.as_u64()).unwrap_or(1) as u32;

    let nice = obj
        .get("priority")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .clamp(-20, 19) as i8;

    let loop_count = obj.get("loop").and_then(|v| v.as_i64()).unwrap_or(-1);

    // Parse CPU affinity
    let allowed_cpus = if let Some(cpus_val) = obj.get("cpus") {
        parse_cpus(cpus_val)?
    } else {
        None
    };

    if obj.contains_key("taskgroup") {
        warn!(
            task = name,
            "ignoring 'taskgroup' (not modeled in simulator)"
        );
    }

    // Parse phases
    let all_phases = if let Some(phases_val) = obj.get("phases") {
        // Multi-phase task: each sub-object is a named phase
        let phases_obj = phases_val
            .as_object()
            .ok_or_else(|| RtAppError::InvalidValue("phases: expected object".into()))?;

        let mut all = Vec::new();
        for (_phase_name, phase_val) in phases_obj.iter() {
            let phase_obj = phase_val
                .as_object()
                .ok_or_else(|| RtAppError::InvalidValue("phase: expected object".into()))?;

            let phase_loop = phase_obj.get("loop").and_then(|v| v.as_i64()).unwrap_or(1);

            let events = parse_events(phase_obj, name_to_pid)?;

            if phase_loop <= 0 || phase_loop == 1 {
                all.extend(events);
            } else {
                for _ in 0..phase_loop {
                    all.extend(events.clone());
                }
            }
        }
        all
    } else {
        // Single-phase task: events are directly in the task object
        parse_events(obj, name_to_pid)?
    };

    if all_phases.is_empty() {
        warn!(task = name, "task has no events, skipping");
        return Ok(Vec::new());
    }

    // Handle loop: -1 means repeat forever, N>1 uses RepeatMode::Count
    let (final_phases, repeat) = if loop_count < 0 {
        (all_phases, RepeatMode::Forever)
    } else if loop_count <= 1 {
        (all_phases, RepeatMode::Once)
    } else {
        (all_phases, RepeatMode::Count(loop_count as u32))
    };

    // Create task instances
    let mut defs = Vec::new();
    for i in 0..instance_count {
        let task_name = if instance_count == 1 {
            name.to_string()
        } else {
            format!("{name}-{i}")
        };
        let pid = Pid(*pid_start);
        *pid_start += 1;

        defs.push(TaskDef {
            name: task_name,
            pid,
            nice,
            behavior: TaskBehavior {
                phases: final_phases.clone(),
                repeat,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: allowed_cpus.clone(),
            parent_pid: None,
        });
    }

    Ok(defs)
}

/// Load an rt-app JSON workload and convert it to a simulator [`Scenario`].
///
/// # Arguments
///
/// * `json_str` — Raw JSON string (may contain C-style `/* */` comments).
/// * `nr_cpus` — Number of simulated CPUs (rt-app doesn't specify this).
///
/// # Example
///
/// ```rust,no_run
/// use scx_simulator::rtapp::load_rtapp;
///
/// let json = r#"{
///     "global": { "duration": 1 },
///     "tasks": {
///         "worker": {
///             "loop": -1,
///             "run": 5000,
///             "sleep": 5000
///         }
///     }
/// }"#;
///
/// let scenario = load_rtapp(json, 4).unwrap();
/// ```
pub fn load_rtapp(json_str: &str, nr_cpus: u32) -> Result<Scenario, RtAppError> {
    let cleaned = strip_comments(json_str);
    let root: Value = serde_json::from_str(&cleaned)?;
    let root_obj = root
        .as_object()
        .ok_or(RtAppError::MissingField("root object"))?;

    // Parse global settings
    let duration_ns = if let Some(global) = root_obj.get("global") {
        let dur_secs = global
            .get("duration")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        if dur_secs > 0 {
            dur_secs as u64 * 1_000_000_000
        } else {
            // Default: 10 seconds if not specified or infinite
            10_000_000_000
        }
    } else {
        10_000_000_000
    };

    let tasks_obj = root_obj
        .get("tasks")
        .and_then(|v| v.as_object())
        .ok_or(RtAppError::MissingField("tasks"))?;

    // First pass: assign PIDs to build name→pid map
    let mut name_to_pid: HashMap<String, Pid> = HashMap::new();
    let mut pid_counter: i32 = 1;
    for (task_name, task_val) in tasks_obj.iter() {
        let instance_count = task_val
            .as_object()
            .and_then(|o| o.get("instance"))
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;

        if instance_count == 1 {
            name_to_pid.insert(task_name.clone(), Pid(pid_counter));
            pid_counter += 1;
        } else {
            // Map the base name to the first instance
            name_to_pid.insert(task_name.clone(), Pid(pid_counter));
            for i in 0..instance_count {
                let inst_name = format!("{task_name}-{i}");
                name_to_pid.insert(inst_name, Pid(pid_counter));
                pid_counter += 1;
            }
        }
    }

    // Second pass: parse tasks with name→pid resolution
    let mut all_tasks: Vec<TaskDef> = Vec::new();
    let mut pid_counter: i32 = 1;
    for (task_name, task_val) in tasks_obj.iter() {
        let task_obj = task_val.as_object().ok_or_else(|| {
            RtAppError::InvalidValue(format!("task {task_name}: expected object"))
        })?;

        let defs = parse_task(task_name, task_obj, &mut pid_counter, &name_to_pid)?;
        all_tasks.extend(defs);
    }

    if all_tasks.is_empty() {
        return Err(RtAppError::InvalidValue(
            "no tasks with events found".into(),
        ));
    }

    Ok(Scenario {
        nr_cpus,
        smt_threads_per_core: 1,
        tasks: all_tasks,
        duration_ns,
        noise: NoiseConfig::from_env(),
        overhead: OverheadConfig::from_env(),
        seed: seed_from_env(),
        fixed_priority: false,
        sched_overhead_rbc_ns: sched_overhead_rbc_ns_from_env(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_comments() {
        assert_eq!(strip_comments("hello /* world */ foo"), "hello  foo");
        assert_eq!(strip_comments("no comments"), "no comments");
        assert_eq!(strip_comments("a /* b /* nested */ c"), "a  c");
    }

    #[test]
    fn test_classify_event() {
        assert_eq!(classify_event("run"), Some("run"));
        assert_eq!(classify_event("run0"), Some("run"));
        assert_eq!(classify_event("runtime"), Some("runtime"));
        assert_eq!(classify_event("runtime1"), Some("runtime"));
        assert_eq!(classify_event("sleep"), Some("sleep"));
        assert_eq!(classify_event("sleep0"), Some("sleep"));
        assert_eq!(classify_event("timer"), Some("timer"));
        assert_eq!(classify_event("suspend"), Some("suspend"));
        assert_eq!(classify_event("resume"), Some("resume"));
        assert_eq!(classify_event("lock"), Some("lock"));
        assert_eq!(classify_event("loop"), None);
        assert_eq!(classify_event("cpus"), None);
        assert_eq!(classify_event("priority"), None);
    }

    #[test]
    fn test_simple_workload() {
        let json = r#"{
            "global": { "duration": 1 },
            "tasks": {
                "worker": {
                    "loop": -1,
                    "run": 5000,
                    "sleep": 5000
                }
            }
        }"#;

        let scenario = load_rtapp(json, 2).unwrap();
        assert_eq!(scenario.nr_cpus, 2);
        assert_eq!(scenario.duration_ns, 1_000_000_000);
        assert_eq!(scenario.tasks.len(), 1);

        let task = &scenario.tasks[0];
        assert_eq!(task.name, "worker");
        assert_eq!(task.nice, 0);
        assert_eq!(task.behavior.repeat, RepeatMode::Forever);
        assert_eq!(task.behavior.phases.len(), 2);
        assert!(matches!(task.behavior.phases[0], Phase::Run(5_000_000)));
        assert!(matches!(task.behavior.phases[1], Phase::Sleep(5_000_000)));
    }

    #[test]
    fn test_suspend_resume() {
        let json = r#"{
            "tasks": {
                "producer": {
                    "loop": -1,
                    "run": 10000,
                    "resume": "consumer",
                    "sleep": 20000
                },
                "consumer": {
                    "loop": -1,
                    "suspend": "consumer",
                    "run": 5000
                }
            }
        }"#;

        let scenario = load_rtapp(json, 2).unwrap();
        assert_eq!(scenario.tasks.len(), 2);

        let producer = &scenario.tasks[0];
        assert_eq!(producer.name, "producer");
        assert_eq!(producer.behavior.phases.len(), 3);
        assert!(matches!(
            producer.behavior.phases[0],
            Phase::Run(10_000_000)
        ));
        assert!(matches!(producer.behavior.phases[1], Phase::Wake(Pid(2)))); // consumer pid
        assert!(matches!(
            producer.behavior.phases[2],
            Phase::Sleep(20_000_000)
        ));

        let consumer = &scenario.tasks[1];
        assert_eq!(consumer.name, "consumer");
        assert_eq!(consumer.behavior.phases.len(), 2);
        assert!(matches!(
            consumer.behavior.phases[0],
            Phase::Sleep(u64::MAX)
        )); // suspend
        assert!(matches!(consumer.behavior.phases[1], Phase::Run(5_000_000)));
    }

    #[test]
    fn test_multi_phase() {
        let json = r#"{
            "tasks": {
                "task1": {
                    "loop": -1,
                    "phases": {
                        "active": {
                            "loop": 2,
                            "run": 1000
                        },
                        "idle": {
                            "sleep": 5000
                        }
                    }
                }
            }
        }"#;

        let scenario = load_rtapp(json, 1).unwrap();
        let task = &scenario.tasks[0];
        // phase "active" with loop=2 should expand to 2 runs, then 1 sleep
        assert_eq!(task.behavior.phases.len(), 3);
        assert!(matches!(task.behavior.phases[0], Phase::Run(1_000_000)));
        assert!(matches!(task.behavior.phases[1], Phase::Run(1_000_000)));
        assert!(matches!(task.behavior.phases[2], Phase::Sleep(5_000_000)));
    }

    #[test]
    fn test_instances() {
        let json = r#"{
            "tasks": {
                "worker": {
                    "instance": 3,
                    "loop": -1,
                    "run": 10000
                }
            }
        }"#;

        let scenario = load_rtapp(json, 4).unwrap();
        assert_eq!(scenario.tasks.len(), 3);
        assert_eq!(scenario.tasks[0].name, "worker-0");
        assert_eq!(scenario.tasks[1].name, "worker-1");
        assert_eq!(scenario.tasks[2].name, "worker-2");
        // Each should have unique PIDs
        assert_ne!(scenario.tasks[0].pid, scenario.tasks[1].pid);
    }

    #[test]
    fn test_nice_priority() {
        let json = r#"{
            "tasks": {
                "high": { "priority": -19, "loop": -1, "run": 1000 },
                "low":  { "priority": 10, "loop": -1, "run": 1000 }
            }
        }"#;

        let scenario = load_rtapp(json, 1).unwrap();
        assert_eq!(scenario.tasks[0].nice, -19);
        assert_eq!(scenario.tasks[1].nice, 10);
    }

    #[test]
    fn test_comments_and_timer() {
        let json = r#"{
            /* This is a comment */
            "tasks": {
                "periodic": {
                    "loop": -1,
                    "run": 2000,
                    "timer": { "ref": "tick", "period": 16667 }
                }
            }
        }"#;

        let scenario = load_rtapp(json, 1).unwrap();
        let task = &scenario.tasks[0];
        assert_eq!(task.behavior.phases.len(), 2);
        assert!(matches!(task.behavior.phases[0], Phase::Run(2_000_000)));
        // timer period 16667 usec = 16667000 ns
        assert!(matches!(task.behavior.phases[1], Phase::Sleep(16_667_000)));
    }

    #[test]
    fn test_parse_cpus_string_single() {
        let v = serde_json::json!("0");
        let cpus = parse_cpus(&v).unwrap();
        assert_eq!(cpus, Some(vec![CpuId(0)]));
    }

    #[test]
    fn test_parse_cpus_string_list() {
        let v = serde_json::json!("0,2,4");
        let cpus = parse_cpus(&v).unwrap();
        assert_eq!(cpus, Some(vec![CpuId(0), CpuId(2), CpuId(4)]));
    }

    #[test]
    fn test_parse_cpus_string_range() {
        let v = serde_json::json!("1-3");
        let cpus = parse_cpus(&v).unwrap();
        assert_eq!(cpus, Some(vec![CpuId(1), CpuId(2), CpuId(3)]));
    }

    #[test]
    fn test_parse_cpus_string_mixed() {
        let v = serde_json::json!("0,2-4,6");
        let cpus = parse_cpus(&v).unwrap();
        assert_eq!(
            cpus,
            Some(vec![CpuId(0), CpuId(2), CpuId(3), CpuId(4), CpuId(6)])
        );
    }

    #[test]
    fn test_parse_cpus_number() {
        let v = serde_json::json!(3);
        let cpus = parse_cpus(&v).unwrap();
        assert_eq!(cpus, Some(vec![CpuId(3)]));
    }

    #[test]
    fn test_parse_cpus_array() {
        let v = serde_json::json!([0, 1, 3]);
        let cpus = parse_cpus(&v).unwrap();
        assert_eq!(cpus, Some(vec![CpuId(0), CpuId(1), CpuId(3)]));
    }

    #[test]
    fn test_parse_cpus_in_workload() {
        let json = r#"{
            "global": { "duration": 1 },
            "tasks": {
                "pinned": {
                    "loop": -1,
                    "cpus": "0,1",
                    "run": 5000
                }
            }
        }"#;

        let scenario = load_rtapp(json, 4).unwrap();
        let task = &scenario.tasks[0];
        assert_eq!(task.allowed_cpus, Some(vec![CpuId(0), CpuId(1)]));
    }
}
