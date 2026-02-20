use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Result};

use super::{binary_path, LOG_DIR, TARGET_DIR};

fn build_scheduler() -> Result<()> {
    log_info!("Building PANDEMONIUM (release)...");

    let project_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new("cargo")
        .args(["build", "--release"])
        .env("CARGO_TARGET_DIR", TARGET_DIR)
        .current_dir(project_root)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("BUILD FAILED:\n{}", stderr);
    }

    let bin = binary_path();
    let size = std::fs::metadata(&bin)
        .map(|m| m.len() / 1024)
        .unwrap_or(0);
    log_info!("Build complete: {} ({} KB)", bin, size);
    Ok(())
}

fn capture_dmesg_cursor() -> Option<String> {
    let output = Command::new("journalctl")
        .args(["-k", "--no-pager", "-n", "1", "--show-cursor"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.trim().lines().rev() {
        if line.starts_with("-- cursor:") {
            return Some(line.splitn(2, ':').nth(1)?.trim().to_string());
        }
    }
    None
}

fn capture_dmesg_after(cursor: Option<&str>) -> String {
    let mut cmd = Command::new("journalctl");
    cmd.args(["-k", "--no-pager"]);
    if let Some(c) = cursor {
        cmd.args(["--after-cursor", c]);
    }
    let output = match cmd.output() {
        Ok(o) if o.status.success() => o,
        _ => return String::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut relevant = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() || line.starts_with("-- ") {
            continue;
        }
        let low = line.to_lowercase();
        if low.contains("sched_ext") || low.contains("scx") || low.contains("pandemonium") {
            relevant.push(line.to_string());
        }
    }
    relevant.join("\n")
}

fn save_logs(scheduler_output: &str, dmesg: &str, returncode: i32) -> Result<(String, String, String)> {
    std::fs::create_dir_all(LOG_DIR)?;

    let stamp = chrono_stamp();

    let sched_path = format!("{}/run-{}.log", LOG_DIR, stamp);
    std::fs::write(&sched_path, scheduler_output)?;

    let dmesg_path = format!("{}/dmesg-{}.log", LOG_DIR, stamp);
    std::fs::write(
        &dmesg_path,
        if dmesg.is_empty() {
            "(NO RELEVANT KERNEL MESSAGES)\n"
        } else {
            dmesg
        },
    )?;

    let report_path = format!("{}/report-{}.log", LOG_DIR, stamp);
    let report = format!(
        "PANDEMONIUM RUN -- {stamp}\n\
         EXIT CODE: {returncode}\n\n\
         SCHEDULER OUTPUT\n\
         {scheduler_output}\n\n\
         KERNEL LOG (DMESG)\n\
         {dmesg_text}\n",
        dmesg_text = if dmesg.is_empty() {
            "(NO RELEVANT KERNEL MESSAGES)"
        } else {
            dmesg
        },
    );
    std::fs::write(&report_path, &report)?;

    let latest = format!("{}/latest.log", LOG_DIR);
    let _ = std::fs::remove_file(&latest);
    let _ = std::os::unix::fs::symlink(&report_path, &latest);

    Ok((sched_path, dmesg_path, report_path))
}

fn chrono_stamp() -> String {
    let output = Command::new("date")
        .arg("+%Y%m%d-%H%M%S")
        .output()
        .ok();
    match output {
        Some(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

pub fn run_start(observe: bool, sched_args: &[String]) -> Result<()> {
    // BUILD FIRST
    build_scheduler()?;

    let bin = binary_path();
    if !Path::new(&bin).exists() {
        bail!("BINARY NOT FOUND AT {}", bin);
    }

    let mut cmd_args = Vec::new();
    if observe {
        cmd_args.push("--verbose".to_string());
        cmd_args.push("--dump-log".to_string());
    }
    cmd_args.extend(sched_args.iter().cloned());

    let full_cmd = format!("sudo {} {}", bin, cmd_args.join(" "));
    log_info!("Running: {}", full_cmd);

    let cursor = capture_dmesg_cursor();

    let mut child = Command::new("sudo")
        .arg(&bin)
        .args(&cmd_args)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    let mut output_lines = Vec::new();

    for line in reader.lines() {
        match line {
            Ok(l) => {
                println!("{}", l);
                output_lines.push(l);
            }
            Err(_) => break,
        }
    }

    let status = child.wait()?;

    let scheduler_output = output_lines.join("\n");
    let returncode = status.code().unwrap_or(-1);

    log_info!("PANDEMONIUM exited with code {}", returncode);

    // BRIEF PAUSE FOR KERNEL LOG FLUSH
    std::thread::sleep(Duration::from_millis(200));
    let dmesg = capture_dmesg_after(cursor.as_deref());

    // SAVE LOGS
    let (sched_path, dmesg_path, report_path) = save_logs(&scheduler_output, &dmesg, returncode)?;

    // PRINT DMESG
    if dmesg.is_empty() {
        log_info!("Kernel log: no relevant sched_ext messages");
    } else {
        log_info!("Kernel log ({} lines):", dmesg.lines().count());
        for line in dmesg.lines() {
            println!("  {}", line);
        }
    }

    match returncode {
        0 => log_info!("Status: clean exit"),
        130 => log_info!("Status: user interrupted (CTRL+C)"),
        _ => log_warn!("Status: exit code {}", returncode),
    }

    log_info!("Logs saved to {}/", LOG_DIR);
    log_info!("  scheduler: {}", sched_path);
    log_info!("  dmesg:     {}", dmesg_path);
    log_info!("  combined:  {}", report_path);
    log_info!("  latest:    {}/latest.log", LOG_DIR);

    Ok(())
}

pub fn run_dmesg() -> Result<()> {
    let output = Command::new("journalctl")
        .args(["-k", "--no-pager", "-n", "50"])
        .output()?;

    if !output.status.success() {
        bail!("journalctl failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found = false;
    for line in stdout.lines() {
        if line.is_empty() || line.starts_with("-- ") {
            continue;
        }
        let low = line.to_lowercase();
        if low.contains("sched_ext") || low.contains("scx") || low.contains("pandemonium") {
            println!("{}", line);
            found = true;
        }
    }

    if !found {
        log_info!("No recent sched_ext/PANDEMONIUM kernel messages");
    }

    Ok(())
}
