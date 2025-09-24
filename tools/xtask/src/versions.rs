// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Context;
use anyhow::Result;
use regex::Regex;
use serde::Serialize;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::get_cargo_metadata;
use crate::get_rust_paths;

pub fn version_command() -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct Output {
        rust_versions: HashMap<String, String>,
        rust_dep_versions: HashMap<String, String>,
    }

    let mut output = Output {
        rust_versions: HashMap::new(),
        rust_dep_versions: HashMap::new(),
    };

    // Get rust paths and process versions
    let rust_paths = get_rust_paths().context("failed to get rust paths")?;

    for path in &rust_paths {
        if let Some((name, version)) = process_rust_version(path)
            .with_context(|| format!("failed to process rust version for {}", path.display()))?
        {
            output.rust_versions.insert(name, version);
        }
    }

    // Include tree crates as deps
    output.rust_dep_versions.extend(
        output
            .rust_versions
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );

    // Process rust dependencies
    for path in &rust_paths {
        process_rust_deps(path, &mut output.rust_dep_versions)
            .with_context(|| format!("failed to process rust deps for {}", path.display()))?;
    }

    // Remove tree crates from deps for output
    for crate_name in output.rust_versions.keys() {
        output.rust_dep_versions.remove(crate_name);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&output).context("failed to serialize")?
    );

    Ok(())
}

pub fn cargo_path_to_crate(path: &Path) -> String {
    // Get crate name from cargo metadata instead of parsing path
    if let Ok(metadata) = get_cargo_metadata() {
        if let Some(packages) = metadata["packages"].as_array() {
            for package in packages {
                if let (Some(manifest_path), Some(name)) =
                    (package["manifest_path"].as_str(), package["name"].as_str())
                {
                    if PathBuf::from(manifest_path) == path {
                        return name.to_string();
                    }
                }
            }
        }
    }

    // Fallback to path parsing if metadata lookup fails
    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}

fn process_rust_version(path: &Path) -> Result<Option<(String, String)>> {
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();

    let workspace_re = Regex::new(r"^\s*\[\s*workspace\s*\]")?;
    let name_re = Regex::new(r#"^\s*name\s*=\s*"([^"]*)".*$"#)?;
    let version_re = Regex::new(r#"(^\s*version\s*=\s*")([^"]*)(".*$)"#)?;

    let mut name = None;
    let mut version = None;

    for (line_no, line) in lines.iter().enumerate() {
        // Skip if we hit a workspace section
        if workspace_re.is_match(line) {
            log::debug!(
                "[{}:{}] SKIP: workspace section",
                path.display(),
                line_no + 1
            );
            return Ok(None);
        }

        if let Some(captures) = name_re.captures(line) {
            name = Some(captures.get(1).unwrap().as_str().to_string());
            log::debug!(
                "[{}:{}] name: {}",
                path.display(),
                line_no + 1,
                name.as_ref().unwrap()
            );
        }

        if let Some(captures) = version_re.captures(line) {
            version = Some(captures.get(2).unwrap().as_str().to_string());
            log::debug!(
                "[{}:{}] version: {}",
                path.display(),
                line_no + 1,
                version.as_ref().unwrap()
            );
        }

        if name.is_some() && version.is_some() {
            break;
        }
    }

    let crate_name = name.ok_or_else(|| anyhow::anyhow!("Failed to find crate name"))?;
    let current_version = version.ok_or_else(|| anyhow::anyhow!("Failed to find version"))?;

    // Check if name matches path
    if crate_name != cargo_path_to_crate(path) {
        log::warn!(
            "[{}] name \"{}\" does not match the path",
            path.display(),
            crate_name
        );
    }

    Ok(Some((crate_name, current_version)))
}

fn process_rust_deps(path: &Path, rust_deps: &mut HashMap<String, String>) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();

    let sect_re = Regex::new(r"^\s*\[([^\[\]]*)\]\s*$")?;
    let crate_re = Regex::new(r#"^\s*([^=\s]*)\s*=.*$"#)?;
    let version_simple_re = Regex::new(r#"(^[^=].*=\s*")([^"]*)("\s*$)"#)?;
    let version_detailed_re = Regex::new(r#"(^.*version\s*=\s*")([^"]*)(".*$)"#)?;

    let mut in_dep_section = None;
    let mut block_depth = 0;
    let mut current_crate = None;

    for (line_no, line) in lines.iter().enumerate() {
        // Check for section headers
        if let Some(captures) = sect_re.captures(line) {
            if block_depth != 0 {
                return Err(anyhow::anyhow!(
                    "[{}:{}] Unbalanced block_depth {}",
                    path.display(),
                    line_no + 1,
                    block_depth
                ));
            }

            let section = captures.get(1).unwrap().as_str().trim();
            if section.ends_with("dependencies") {
                in_dep_section = Some(section.to_string());
                log::debug!("[{}:{}] [{}]", path.display(), line_no + 1, section);
            } else {
                in_dep_section = None;
            }
            continue;
        }

        if in_dep_section.is_none() {
            continue;
        }

        // Parse comment
        let (body, _comment) = if let Some(comment_pos) = line.find('#') {
            (&line[..comment_pos], &line[comment_pos..])
        } else {
            (&line[..], "")
        };

        if body.trim().is_empty() {
            continue;
        }

        // Track nesting depth
        block_depth += body.matches('{').count() as i32 - body.matches('}').count() as i32;
        block_depth += body.matches('[').count() as i32 - body.matches(']').count() as i32;

        // Determine current crate
        if block_depth == 0 {
            if let Some(captures) = crate_re.captures(body) {
                current_crate = Some(captures.get(1).unwrap().as_str().to_string());
            } else {
                current_crate = None;
            }
        }

        if let Some(ref crate_name) = current_crate {
            // Try to find version
            let version = if let Some(captures) = version_simple_re.captures(body) {
                Some((
                    captures.get(1).unwrap().as_str(),
                    captures.get(2).unwrap().as_str(),
                    captures.get(3).unwrap().as_str(),
                ))
            } else {
                version_detailed_re.captures(body).map(|captures| {
                    (
                        captures.get(1).unwrap().as_str(),
                        captures.get(2).unwrap().as_str(),
                        captures.get(3).unwrap().as_str(),
                    )
                })
            };

            if let Some((_pre, current_version, _post)) = version {
                log::debug!(
                    "[{}:{}] {}: version {}",
                    path.display(),
                    line_no + 1,
                    crate_name,
                    current_version
                );

                // Check for mismatches
                if let Some(existing_version) = rust_deps.get(crate_name) {
                    if existing_version != current_version {
                        log::warn!(
                            "[{}:{}] crate \"{}\" {} mismatches existing {}",
                            path.display(),
                            line_no + 1,
                            crate_name,
                            current_version,
                            existing_version
                        );
                    }
                } else {
                    rust_deps.insert(crate_name.clone(), current_version.to_string());
                }
            }
        }

        if block_depth == 0 {
            current_crate = None;
        }
    }

    if block_depth != 0 {
        return Err(anyhow::anyhow!(
            "[{}] Unbalanced block_depth {}",
            path.display(),
            block_depth
        ));
    }

    Ok(())
}
