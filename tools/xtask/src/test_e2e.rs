// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct E2eConfig {
    scheduler: HashMap<String, SchedulerConfig>,
}

#[derive(Debug, Deserialize)]
struct SchedulerConfig {
    nix_package: String,
    binary_name: String,
    kernels: Option<Vec<String>>,
    tests: Vec<TestConfig>,
}

#[derive(Debug, Deserialize)]
struct TestConfig {
    name: String,
    description: String,
    scheduler_args: Vec<String>,
    workload: String,
    timeout_sec: u32,
    expected_outcome: String,
    kernels: Option<Vec<String>>,
    metrics: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct JsonTestOutput {
    name: String,
    flags: String,
    kernel: String,
}

pub fn e2e_command(
    list: bool,
    format: &str,
    kernel: Option<String>,
    test_name: Option<String>,
) -> Result<()> {
    let config_path = Path::new("e2e-tests.toml");

    if !config_path.exists() {
        anyhow::bail!("e2e-tests.toml not found. Please create the configuration file.");
    }

    let config_content =
        fs::read_to_string(config_path).context("Failed to read e2e-tests.toml")?;

    let config: E2eConfig =
        toml::from_str(&config_content).context("Failed to parse e2e-tests.toml")?;

    if list {
        return list_tests(&config, format, kernel.as_deref());
    }

    run_tests(&config, kernel.as_deref(), test_name.as_deref())
}

fn list_tests(config: &E2eConfig, format: &str, kernel_filter: Option<&str>) -> Result<()> {
    match format {
        "json" => list_tests_json(config, kernel_filter),
        "human" => list_tests_human(config, kernel_filter),
        _ => anyhow::bail!("Unsupported format: {}. Use 'human' or 'json'", format),
    }
}

fn list_tests_json(config: &E2eConfig, kernel_filter: Option<&str>) -> Result<()> {
    let mut matrix = Vec::new();

    for (scheduler_name, scheduler_config) in &config.scheduler {
        let default_kernels = scheduler_config
            .kernels
            .clone()
            .unwrap_or_else(|| vec!["sched_ext/for-next".to_string()]);

        for test in &scheduler_config.tests {
            let test_kernels = test.kernels.as_ref().unwrap_or(&default_kernels);

            for kernel in test_kernels {
                if let Some(filter) = kernel_filter {
                    if kernel != filter {
                        continue;
                    }
                }

                let flags = test.scheduler_args.join(" ");
                matrix.push(JsonTestOutput {
                    name: format!("{}::{}", scheduler_name, test.name),
                    flags,
                    kernel: kernel.clone(),
                });
            }
        }
    }

    println!("matrix={}", serde_json::to_string(&matrix)?);
    Ok(())
}

fn list_tests_human(config: &E2eConfig, kernel_filter: Option<&str>) -> Result<()> {
    for (scheduler_name, scheduler_config) in &config.scheduler {
        println!("Scheduler: {}", scheduler_name);
        println!("  Nix package: {}", scheduler_config.nix_package);
        println!("  Binary: {}", scheduler_config.binary_name);

        let default_kernels = scheduler_config
            .kernels
            .clone()
            .unwrap_or_else(|| vec!["sched_ext/for-next".to_string()]);

        println!("  Default kernels: {}", default_kernels.join(", "));
        println!("  Tests:");

        for test in &scheduler_config.tests {
            let test_kernels = test.kernels.as_ref().unwrap_or(&default_kernels);

            for kernel in test_kernels {
                if let Some(filter) = kernel_filter {
                    if kernel != filter {
                        continue;
                    }
                }

                println!("    {}::{} (kernel: {})", scheduler_name, test.name, kernel);
                println!("      Description: {}", test.description);
                println!("      Args: {}", test.scheduler_args.join(" "));
                println!("      Workload: {}", test.workload);
                println!("      Timeout: {}s", test.timeout_sec);
                if let Some(metrics) = &test.metrics {
                    println!("      Metrics: {}", metrics.join(", "));
                }
                println!();
            }
        }
        println!();
    }
    Ok(())
}

fn run_tests(config: &E2eConfig, kernel: Option<&str>, test_name: Option<&str>) -> Result<()> {
    let mut tests_run = 0;
    let mut tests_passed = 0;

    for (scheduler_name, scheduler_config) in &config.scheduler {
        // Skip if specific test requested and doesn't match
        if let Some(test_filter) = test_name {
            if !test_filter.starts_with(scheduler_name) {
                continue;
            }
        }

        let default_kernels = scheduler_config
            .kernels
            .clone()
            .unwrap_or_else(|| vec!["sched_ext/for-next".to_string()]);

        for test in &scheduler_config.tests {
            // Skip if specific test requested and doesn't match
            if let Some(test_filter) = test_name {
                let full_test_name = format!("{}::{}", scheduler_name, test.name);
                if test_filter != full_test_name && test_filter != scheduler_name {
                    continue;
                }
            }

            let test_kernels = test.kernels.as_ref().unwrap_or(&default_kernels);

            for test_kernel in test_kernels {
                if let Some(kernel_filter) = kernel {
                    if test_kernel != kernel_filter {
                        continue;
                    }
                }

                tests_run += 1;
                println!(
                    "Running test: {}::{} (kernel: {})",
                    scheduler_name, test.name, test_kernel
                );

                match run_single_test(scheduler_config, test, test_kernel) {
                    Ok(()) => {
                        println!("✓ PASSED: {}::{}", scheduler_name, test.name);
                        tests_passed += 1;
                    }
                    Err(e) => {
                        println!("✗ FAILED: {}::{} - {}", scheduler_name, test.name, e);
                    }
                }
                println!();
            }
        }
    }

    println!("Test Results: {}/{} tests passed", tests_passed, tests_run);

    if tests_passed != tests_run {
        anyhow::bail!("Some tests failed");
    }

    Ok(())
}

fn run_single_test(
    scheduler_config: &SchedulerConfig,
    test: &TestConfig,
    kernel: &str,
) -> Result<()> {
    // Get Nix-built binary path
    let binary_path = get_nix_binary_path(&scheduler_config.nix_package)
        .context("Failed to get Nix binary path")?;

    // Build scheduler command
    let mut scheduler_cmd_parts = vec![binary_path.clone()];
    scheduler_cmd_parts.extend(test.scheduler_args.iter().cloned());
    let scheduler_cmd = scheduler_cmd_parts.join(" ");

    // Build virtme-ng command
    let kernel_path = get_nix_kernel_path(kernel).context("Failed to get Nix kernel path")?;

    println!("  Binary path: {}", binary_path);
    println!("  Kernel path: {}", kernel_path);
    println!("  Scheduler command: {}", scheduler_cmd);
    println!("  Workload: {}", test.workload);

    // Run test in virtme-ng
    // Run workload in background, then scheduler with timeout
    // Note: BusyBox timeout doesn't support --foreground, so we use simple timeout
    let vm_input = format!(
        "{} & timeout {} {}",
        test.workload, test.timeout_sec, scheduler_cmd
    );

    println!("  VM command: {}", vm_input);

    let output = Command::new("vng")
        .args([
            "-m",
            "2G",
            "--cpus",
            "4",
            "--user",
            "root",
            "-v",
            "-r",
            &kernel_path,
            "--rw",
            "--",
            &vm_input,
        ])
        .output()
        .context("Failed to run vng")?;

    // Check exit code
    // BusyBox timeout: returns 0 if command completes, SIGTERM exit code (143) if timed out
    // GNU timeout: returns 124 if timed out, 0 if completes normally
    let exit_code = output.status.code().unwrap_or(-1);

    // Exit codes: 0 = clean exit, 143 = SIGTERM (expected from timeout in BusyBox)
    let is_success = exit_code == 0 || exit_code == 143;

    if !is_success {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "Test failed with exit code {}:\nSTDOUT:\n{}\nSTDERR:\n{}",
            exit_code,
            stdout,
            stderr
        );
    }

    // Check expected outcome
    match test.expected_outcome.as_str() {
        "success" => {
            if !is_success {
                anyhow::bail!("Expected success but got exit code {}", exit_code);
            }
        }
        _ => {
            anyhow::bail!("Unknown expected outcome: {}", test.expected_outcome);
        }
    }

    Ok(())
}

fn get_nix_binary_path(package: &str) -> Result<String> {
    let output = Command::new("nix")
        .args([
            "build",
            "--no-link",
            "--print-out-paths",
            &format!("./.nix#{}", package),
        ])
        .output()
        .context("Failed to run nix build")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Nix build failed: {}", stderr);
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(format!("{}/bin/{}", store_path, package))
}

fn get_nix_kernel_path(kernel: &str) -> Result<String> {
    // Kernel packages are named "kernel_<original_name>" in the flake
    let kernel_package = format!("kernel_{}", kernel);

    let output = Command::new("nix")
        .args([
            "build",
            "--no-link",
            "--print-out-paths",
            &format!("./.nix#{}", kernel_package),
        ])
        .output()
        .context("Failed to run nix build for kernel")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Nix kernel build failed for {}: {}", kernel_package, stderr);
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(format!("{}/bzImage", store_path))
}
