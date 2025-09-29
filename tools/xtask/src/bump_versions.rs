// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use crate::get_cargo_metadata;
use crate::get_rust_paths;

pub fn bump_versions_command(packages: Vec<String>, all: bool) -> Result<()> {
    // Determine target crates
    let target_crates = if all {
        get_all_workspace_crates()?
    } else {
        packages
    };

    if target_crates.is_empty() {
        log::info!("No crates to bump.");
        return Ok(());
    }

    log::info!("Analyzing workspace dependencies...");

    // Get cargo metadata
    let metadata = get_cargo_metadata()?;

    // Build map of workspace crates
    let workspace_member_ids: HashSet<String> = metadata
        .workspace_members
        .iter()
        .map(|id| id.to_string())
        .collect();

    let mut workspace_members = HashSet::new();
    let mut crate_paths = HashMap::new();

    for pkg in &metadata.packages {
        if workspace_member_ids.contains(&pkg.id.to_string()) {
            workspace_members.insert(pkg.name.to_string());
            crate_paths.insert(
                pkg.name.to_string(),
                pkg.manifest_path.as_std_path().to_path_buf(),
            );
        }
    }

    // Validate target crates exist
    for crate_name in &target_crates {
        if !workspace_members.contains(crate_name) {
            return Err(anyhow::anyhow!(
                "Crate '{}' not found in workspace",
                crate_name
            ));
        }
    }

    // Find all crates that need to be bumped
    let mut crates_to_bump = HashSet::new();
    let mut version_updates = HashMap::new();

    // Start with target crates
    for target in &target_crates {
        crates_to_bump.insert(target.clone());
    }

    // Find dependencies of target crates (what the target crates depend on)
    for target_crate in &target_crates {
        // Find the target crate's package in metadata
        for pkg in &metadata.packages {
            let pkg_name = pkg.name.as_str();

            if pkg_name == target_crate && workspace_members.contains(pkg_name) {
                // Add all workspace dependencies of this target crate (exclude dev dependencies)
                for dep in &pkg.dependencies {
                    let dep_name = dep.name.as_str();
                    let is_workspace_dep = dep.source.is_none(); // workspace dependency has null source
                                                                 // Only include regular dependencies and build dependencies
                                                                 // Exclude dev dependencies
                    if is_workspace_dep
                        && workspace_members.contains(dep_name)
                        && !matches!(dep.kind, cargo_metadata::DependencyKind::Development)
                    {
                        crates_to_bump.insert(dep_name.to_string());
                    }
                }
                break;
            }
        }
    }

    let sorted_crates: Vec<String> = crates_to_bump.iter().cloned().collect();
    log::info!("Bumping versions for: {}", sorted_crates.join(", "));

    // Show dependencies being bumped
    let target_set: HashSet<String> = target_crates.iter().cloned().collect();
    let deps: Vec<String> = crates_to_bump.difference(&target_set).cloned().collect();
    if !deps.is_empty() {
        log::info!("Found dependencies: {}", deps.join(", "));
    }

    // Bump all versions
    for crate_name in &crates_to_bump {
        if let Some(crate_path) = crate_paths.get(crate_name) {
            let (old_version, new_version) = bump_crate_version(crate_path)?;
            version_updates.insert(crate_name.clone(), new_version.clone());
            log::info!("Bumping {crate_name}: {old_version} → {new_version}");
        }
    }

    // Update dependency references in all affected files
    update_dependent_versions(&version_updates)?;

    log::info!("\nUpdated {} crates successfully.", crates_to_bump.len());
    Ok(())
}

pub fn get_all_workspace_crates() -> Result<Vec<String>> {
    let metadata = get_cargo_metadata()?;
    let mut crates = Vec::new();

    let workspace_member_ids: HashSet<String> = metadata
        .workspace_members
        .iter()
        .map(|id| id.to_string())
        .collect();

    for pkg in &metadata.packages {
        if workspace_member_ids.contains(&pkg.id.to_string()) {
            crates.push(pkg.name.to_string());
        }
    }

    Ok(crates)
}

pub fn bump_crate_version(crate_path: &PathBuf) -> Result<(String, String)> {
    let content = fs::read_to_string(crate_path)?;
    let lines: Vec<&str> = content.lines().collect();

    let version_re = Regex::new(r#"(^\s*version\s*=\s*")([^"]*)(".*$)"#)?;

    for (line_no, line) in lines.iter().enumerate() {
        if let Some(captures) = version_re.captures(line) {
            let current_version = captures.get(2).unwrap().as_str();
            let new_version = increment_patch_version(current_version)?;

            // Update the file
            let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
            new_lines[line_no] = format!(
                "{}{}{}",
                captures.get(1).unwrap().as_str(),
                new_version,
                captures.get(3).unwrap().as_str()
            );

            let new_content = new_lines.join("\n") + "\n";
            fs::write(crate_path, new_content)?;

            return Ok((current_version.to_string(), new_version));
        }
    }

    Err(anyhow::anyhow!(
        "Could not find version in {:?}",
        crate_path
    ))
}

fn increment_patch_version(version: &str) -> Result<String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 3 {
        let major = parts[0];
        let minor = parts[1];
        let patch: u32 = parts[2]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid patch version: {}", parts[2]))?;
        let new_patch = patch + 1;

        // Handle any additional parts (like pre-release identifiers)
        if parts.len() > 3 {
            let extra: Vec<&str> = parts[3..].to_vec();
            Ok(format!(
                "{}.{}.{}.{}",
                major,
                minor,
                new_patch,
                extra.join(".")
            ))
        } else {
            Ok(format!("{major}.{minor}.{new_patch}"))
        }
    } else {
        Err(anyhow::anyhow!("Invalid version format: {}", version))
    }
}

pub fn update_dependent_versions(updates: &HashMap<String, String>) -> Result<()> {
    let rust_paths = get_rust_paths()?;
    let section_re = Regex::new(r"^\s*\[([^\[\]]*)\]\s*$")?;

    for path in rust_paths {
        let content = fs::read_to_string(&path)?;
        let lines: Vec<&str> = content.lines().collect();
        let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        let mut modified = false;

        let mut in_dep_section = false;
        let mut block_depth = 0;

        for (line_no, line) in lines.iter().enumerate() {
            // Check for dependency sections
            if let Some(captures) = section_re.captures(line) {
                if block_depth != 0 {
                    continue;
                }
                let section = captures.get(1).unwrap().as_str().trim();
                // Include all dependency sections
                in_dep_section = section == "dependencies"
                    || section == "build-dependencies"
                    || section == "dev-dependencies";
                continue;
            }

            if !in_dep_section {
                continue;
            }

            // Track nesting depth
            block_depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
            block_depth += line.matches('[').count() as i32 - line.matches(']').count() as i32;

            if block_depth == 0 {
                // Look for workspace dependencies that need version updates
                for (crate_name, new_version) in updates {
                    let pattern = format!(
                        r#"(^\s*{}\s*=.*version\s*=\s*")([^"]*)(".*$)"#,
                        regex::escape(crate_name)
                    );
                    if let Some(captures) = Regex::new(&pattern)?.captures(line) {
                        new_lines[line_no] = format!(
                            "{}{}{}",
                            captures.get(1).unwrap().as_str(),
                            new_version,
                            captures.get(3).unwrap().as_str()
                        );
                        modified = true;
                        break;
                    }
                }
            }
        }

        if modified {
            let new_content = new_lines.join("\n") + "\n";
            fs::write(&path, new_content)?;
        }
    }

    Ok(())
}
