//! VM-based real run infrastructure for scxsim.
//!
//! This module launches a virtme-ng VM to run the same rt-app workload
//! with a real sched_ext scheduler, enabling comparison between simulated
//! and real behavior.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Path to the rt-app binary.
const RTAPP_BIN: &str = "/home/newton/bin/rt-app";

/// Run the workload in a virtme-ng VM with the specified scheduler.
///
/// This function:
/// 1. Copies the workload file into the VM
/// 2. Launches vng with the specified number of CPUs
/// 3. Loads the scheduler and runs rt-app
/// 4. Captures and displays the output
pub fn run_vm(workload_path: &Path, scheduler: &str, nr_cpus: u32) -> Result<(), String> {
    // Validate prerequisites
    validate_prerequisites(scheduler)?;

    // The workload file path will be accessible inside the VM because vng
    // shares the host filesystem. Just use the absolute path.
    let workload_abs = workload_path
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize workload path: {e}"))?;

    eprintln!("=== Real VM Run ===");
    eprintln!("  scheduler:  scx_{scheduler}");
    eprintln!("  workload:   {}", workload_abs.display());
    eprintln!("  cpus:       {nr_cpus}");
    eprintln!();

    // Build the command to run inside the VM.
    // We need to:
    // 1. Start the scheduler in the background
    // 2. Give it time to attach
    // 3. Run rt-app
    // 4. Kill the scheduler
    let sched_bin = find_scheduler_binary(scheduler)?;
    let inner_cmd = format!(
        "{sched_bin} &\n\
         SCHED_PID=$!\n\
         sleep 1\n\
         echo '=== Running rt-app ==='\n\
         {RTAPP_BIN} {workload}\n\
         echo '=== rt-app completed ==='\n\
         kill $SCHED_PID 2>/dev/null || true\n\
         wait $SCHED_PID 2>/dev/null || true",
        sched_bin = sched_bin.display(),
        workload = workload_abs.display(),
    );

    // Launch vng
    let mut cmd = Command::new("vng");
    cmd.arg("--cpus")
        .arg(nr_cpus.to_string())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(&inner_cmd);

    eprintln!("Launching VM...");
    eprintln!("  vng --cpus {nr_cpus} -- sh -c '...'");
    eprintln!();

    let status = cmd
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("failed to launch vng: {e}"))?;

    if !status.success() {
        return Err(format!("vng exited with status: {status}"));
    }

    eprintln!();
    eprintln!("=== VM run completed ===");

    Ok(())
}

/// Validate that all prerequisites are available.
fn validate_prerequisites(scheduler: &str) -> Result<(), String> {
    // Check vng
    if !command_exists("vng") {
        return Err("vng (virtme-ng) not found in PATH".into());
    }

    // Check rt-app
    if !Path::new(RTAPP_BIN).exists() {
        return Err(format!("rt-app not found at {RTAPP_BIN}"));
    }

    // Check scheduler binary
    find_scheduler_binary(scheduler)?;

    Ok(())
}

/// Find the scheduler binary.
fn find_scheduler_binary(scheduler: &str) -> Result<PathBuf, String> {
    // Try common locations for the scheduler binary
    let candidates = [
        // Debug build in scx repo
        format!(
            "{}/target/debug/scx_{scheduler}",
            std::env::var("HOME").unwrap_or_default()
        ),
        // Installed system-wide
        format!("/usr/bin/scx_{scheduler}"),
        // In path
        format!("scx_{scheduler}"),
    ];

    // First check CARGO_MANIFEST_DIR relative path (during development)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    if !manifest_dir.is_empty() {
        // Navigate from scx_simulator to repo root
        let manifest_path = PathBuf::from(&manifest_dir);
        if let Some(crates_dir) = manifest_path.parent() {
            if let Some(sim_dir) = crates_dir.parent() {
                if let Some(rust_dir) = sim_dir.parent() {
                    if let Some(repo_root) = rust_dir.parent() {
                        let debug_path = repo_root.join(format!("target/debug/scx_{scheduler}"));
                        if debug_path.exists() {
                            return Ok(debug_path);
                        }
                    }
                }
            }
        }
    }

    // Check SCX_SCHED_BIN environment variable
    if let Ok(sched_bin) = std::env::var("SCX_SCHED_BIN") {
        let path = PathBuf::from(&sched_bin);
        if path.exists() {
            return Ok(path);
        }
    }

    // Try candidates
    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
        // Also try resolving from PATH
        if let Ok(output) = Command::new("which").arg(candidate).output() {
            if output.status.success() {
                let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !resolved.is_empty() {
                    return Ok(PathBuf::from(resolved));
                }
            }
        }
    }

    Err(format!(
        "scheduler binary scx_{scheduler} not found. Build it with:\n\
         cargo build -p scx_{scheduler}\n\n\
         Or set SCX_SCHED_BIN environment variable to the path of the scheduler binary."
    ))
}

/// Check if a command exists in PATH.
fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate an rt-app JSON workload file from a scenario.
///
/// This is the reverse of `load_rtapp`: given a parsed Scenario, generate
/// a JSON file that rt-app can execute to produce the same workload.
///
/// Note: This is a simplified generator that may not preserve all rt-app
/// features, but it handles the common run/sleep/wake patterns used in
/// simulation testing.
#[allow(dead_code)]
pub fn scenario_to_rtapp_json(scenario: &scx_simulator::Scenario) -> Result<String, String> {
    use scx_simulator::task::Phase;
    use serde_json::{json, Map, Value};

    let duration_secs = (scenario.duration_ns / 1_000_000_000) as i64;

    let mut tasks = Map::new();

    // Build a map of PID -> task name for wake references
    let mut pid_to_name: std::collections::HashMap<i32, &str> = std::collections::HashMap::new();
    for task in &scenario.tasks {
        pid_to_name.insert(task.pid.0, &task.name);
    }

    for task in &scenario.tasks {
        let mut task_obj = Map::new();

        // Set priority (nice value)
        task_obj.insert("priority".into(), json!(task.nice as i64));

        // Set loop count
        let loop_count: i64 = match task.behavior.repeat {
            scx_simulator::RepeatMode::Once => 1,
            scx_simulator::RepeatMode::Count(n) => n as i64,
            scx_simulator::RepeatMode::Forever => -1,
        };
        task_obj.insert("loop".into(), json!(loop_count));

        // Set CPU affinity if specified
        if let Some(ref cpus) = task.allowed_cpus {
            let cpu_list: Vec<u32> = cpus.iter().map(|c| c.0).collect();
            task_obj.insert("cpus".into(), json!(cpu_list));
        }

        // Convert phases to rt-app events
        // Use numbered suffixes for duplicate event types (run0, run1, etc.)
        let mut run_idx = 0;
        let mut sleep_idx = 0;

        for phase in &task.behavior.phases {
            match phase {
                Phase::Run(ns) => {
                    let usec = ns / 1_000;
                    let key = if run_idx == 0 {
                        "run".into()
                    } else {
                        format!("run{run_idx}")
                    };
                    task_obj.insert(key, json!(usec));
                    run_idx += 1;
                }
                Phase::Sleep(ns) => {
                    if *ns == u64::MAX {
                        // Suspend: self-suspend until woken
                        task_obj.insert("suspend".into(), json!(task.name.clone()));
                    } else {
                        let usec = ns / 1_000;
                        let key = if sleep_idx == 0 {
                            "sleep".into()
                        } else {
                            format!("sleep{sleep_idx}")
                        };
                        task_obj.insert(key, json!(usec));
                        sleep_idx += 1;
                    }
                }
                Phase::Wake(target_pid) => {
                    // Find the target task name
                    if let Some(target_name) = pid_to_name.get(&target_pid.0) {
                        task_obj.insert("resume".into(), json!(*target_name));
                    }
                }
            }
        }

        tasks.insert(task.name.clone(), Value::Object(task_obj));
    }

    let root = json!({
        "global": {
            "duration": duration_secs,
            "default_policy": "SCHED_OTHER",
            "calibration": 19
        },
        "tasks": tasks
    });

    serde_json::to_string_pretty(&root).map_err(|e| format!("failed to serialize JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scx_simulator::*;

    #[test]
    fn test_scenario_to_rtapp_json_basic() {
        let scenario = Scenario::builder()
            .cpus(2)
            .add_task(
                "worker",
                0,
                TaskBehavior {
                    phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
                    repeat: RepeatMode::Forever,
                },
            )
            .duration_ms(1000)
            .build();

        let json = scenario_to_rtapp_json(&scenario).unwrap();
        assert!(json.contains("\"worker\""));
        assert!(json.contains("\"run\""));
        assert!(json.contains("\"sleep\""));
        assert!(json.contains("\"loop\": -1"));
    }

    #[test]
    fn test_scenario_to_rtapp_json_ping_pong() {
        let (ping_b, pong_b) = workloads::ping_pong(Pid(1), Pid(2), 500_000);
        let scenario = Scenario::builder()
            .cpus(2)
            .task(TaskDef {
                name: "ping".into(),
                pid: Pid(1),
                nice: 0,
                behavior: ping_b,
                start_time_ns: 0,
                mm_id: None,
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
            })
            .task(TaskDef {
                name: "pong".into(),
                pid: Pid(2),
                nice: 0,
                behavior: pong_b,
                start_time_ns: 0,
                mm_id: None,
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
            })
            .duration_ms(1000)
            .build();

        let json = scenario_to_rtapp_json(&scenario).unwrap();
        assert!(json.contains("\"ping\""));
        assert!(json.contains("\"pong\""));
        assert!(json.contains("\"resume\""));
        assert!(json.contains("\"suspend\""));
    }
}
