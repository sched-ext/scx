// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Context;
use cargo_metadata::Package;
use serde::Serialize;

use std::collections::BTreeMap;

use crate::get_workspace_packages;

#[derive(Default, Clone, Copy, clap::ValueEnum)]
pub(crate) enum Format {
    #[default]
    Json,
    Starlark,
}

pub fn version_command(format: Format) -> Result<(), anyhow::Error> {
    #[derive(Serialize)]
    struct Output {
        rust_versions: BTreeMap<String, String>,
        rust_dep_versions: BTreeMap<String, String>,
    }

    let mut output = Output {
        rust_versions: BTreeMap::new(),
        rust_dep_versions: BTreeMap::new(),
    };

    // Get workspace packages
    let packages = get_workspace_packages()?;

    // Extract package versions from workspace packages
    for package in &packages {
        output
            .rust_versions
            .insert(package.name.to_string(), package.version.to_string());
    }

    // Include tree crates as deps initially
    output.rust_dep_versions.extend(
        output
            .rust_versions
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );

    // Extract dependencies from all packages
    for package in &packages {
        extract_package_dependencies(package, &mut output.rust_dep_versions);
    }

    // Remove tree crates from deps for output
    for crate_name in output.rust_versions.keys() {
        output.rust_dep_versions.remove(crate_name);
    }

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).context("failed to serialize")?
            );
        }
        Format::Starlark => {
            println!("RUST_VERSIONS = {{");
            for (k, v) in output.rust_versions {
                println!("  \"{k}\": \"{v}\",");
            }
            println!("}}  #  RUST_VERSIONS\n");

            println!("RUST_DEP_VERSIONS = {{");
            for (k, v) in output.rust_dep_versions {
                println!("  \"{k}\": \"{v}\",");
            }
            println!("}}  #  RUST_DEP_VERSIONS");
        }
    };

    Ok(())
}

fn extract_package_dependencies(package: &Package, rust_deps: &mut BTreeMap<String, String>) {
    for dep in &package.dependencies {
        // Skip path dependencies and wildcard versions
        let req_str = dep.req.to_string();
        if dep.path.is_some() || req_str == "*" {
            continue;
        }

        log::debug!(
            "[{}] {}: version {}",
            package.manifest_path,
            dep.name,
            req_str
        );

        // Check for version mismatches
        if let Some(existing_version) = rust_deps.get(&dep.name) {
            if existing_version != &req_str {
                log::warn!(
                    "[{}] crate \"{}\" {} mismatches existing {}",
                    package.manifest_path,
                    dep.name,
                    req_str,
                    existing_version
                );
            }
        } else {
            rust_deps.insert(dep.name.clone(), req_str);
        }
    }
}
