// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{Context, Result};
use cargo_metadata::MetadataCommand;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;

#[derive(Debug, Deserialize)]
struct KernelMetadata {
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    blocklist: Vec<String>,
    #[serde(default = "default_kernel")]
    default: String,
}

fn default_kernel() -> String {
    "sched_ext/for-next".to_string()
}

#[derive(Debug, Serialize)]
struct MatrixEntry {
    name: String,
    flags: String,
    kernel: String,
}

/// Get list of Rust crates with specific kernel requirements
fn get_package_kernel_requirements() -> Result<HashMap<String, KernelMetadata>> {
    let metadata = MetadataCommand::new()
        .exec()
        .context("Failed to run cargo metadata")?;

    let mut kernel_requirements = HashMap::new();

    for pkg in metadata.packages {
        let Some(pkg_metadata) = pkg.metadata.as_object() else {
            continue;
        };
        let Some(scx_metadata) = pkg_metadata.get("scx") else {
            continue;
        };
        let Some(ci_metadata) = scx_metadata.get("ci") else {
            continue;
        };
        let Some(kernel_metadata) = ci_metadata.get("kernel") else {
            continue;
        };

        let kernel_config: KernelMetadata = serde_json::from_value(kernel_metadata.clone())
            .context("Failed to parse kernel metadata")?;
        kernel_requirements.insert(pkg.name.clone(), kernel_config);
    }

    Ok(kernel_requirements)
}

/// Get CI-Test-Kernel trailers from commits between current HEAD and base branch
fn get_kernel_trailers_from_commits() -> Result<HashSet<String>> {
    // In GitHub Actions, GITHUB_BASE_REF contains the target branch name for PRs
    // For push events, it's empty, so we need to determine the base differently
    let base_ref = env::var("GITHUB_BASE_REF").unwrap_or_else(|_| "main".to_string());
    let base_ref = if base_ref.is_empty() {
        "main"
    } else {
        &base_ref
    };

    // Open the git repository
    let repo = gix::discover(".")
        .context("Failed to discover git repository")?;

    // Get the merge base
    let origin_base = format!("origin/{}", base_ref);
    let head_ref = repo
        .find_reference("HEAD")
        .context("Failed to find HEAD reference")?;
    let base_ref_obj = repo
        .find_reference(&origin_base)
        .with_context(|| format!("Failed to find reference {}", origin_base))?;

    let head_id = head_ref
        .id()
        .detach();
    let base_id = base_ref_obj
        .id()
        .detach();

    let merge_base = repo
        .merge_base(head_id, base_id)
        .context("Failed to find merge base")?;

    eprintln!("Merge base with {}: {}", origin_base, merge_base);

    // Get commits between merge_base and HEAD
    let mut kernels = HashSet::new();
    let head_commit = repo
        .find_object(head_id)
        .context("Failed to find HEAD commit")?
        .try_into_commit()
        .map_err(|_| anyhow::anyhow!("HEAD is not a commit"))?;

    let mut commits_to_process = vec![head_commit];
    let mut processed = HashSet::new();
    let mut commit_count = 0;

    while let Some(commit) = commits_to_process.pop() {
        let commit_id = commit.id;

        // Skip if we've reached the merge base or already processed
        if commit_id == merge_base || processed.contains(&commit_id) {
            continue;
        }
        processed.insert(commit_id);
        commit_count += 1;

        // Get the commit message
        let message = commit.message().context("Failed to get commit message")?;
        let message_str = message.to_string();
        let lines: Vec<&str> = message_str.lines().collect();

        let commit_subject = lines.first().unwrap_or(&"Unknown commit");

        // Start from the last line and work backwards, collecting trailers
        for line in lines.iter().rev() {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            if !line.contains(':') {
                break;
            }

            if let Some(stripped) = line.strip_prefix("CI-Test-Kernel:") {
                let kernel = stripped.trim();
                kernels.insert(kernel.to_string());
                eprintln!(
                    "Found CI-Test-Kernel trailer '{}' in commit: {}",
                    kernel, commit_subject
                );
            }
        }

        // Add parents to process
        for parent_id in commit.parent_ids() {
            let parent = repo
                .find_object(parent_id)
                .context("Failed to find parent commit")?
                .try_into_commit()
                .map_err(|_| anyhow::anyhow!("Parent is not a commit"))?;
            commits_to_process.push(parent);
        }
    }

    eprintln!("Found {} commits to search", commit_count);
    eprintln!("Total kernels found from trailers: {:?}", kernels);

    Ok(kernels)
}

/// List integration tests based on kernel requirements and trailers
pub fn list_integration_tests_command(default_kernel: String) -> Result<()> {
    let kernel_reqs = get_package_kernel_requirements()?;
    let trailer_kernels = get_kernel_trailers_from_commits()?;

    let mut kernels_to_test = HashSet::new();
    kernels_to_test.insert(default_kernel.clone());
    kernels_to_test.extend(trailer_kernels);

    let mut matrix = HashSet::new();

    for kernel in &kernels_to_test {
        // List of schedulers to test
        let schedulers = vec![
            "scx_beerland",
            "scx_bpfland",
            "scx_chaos",
            "scx_cosmos",
            "scx_flash",
            "scx_lavd",
            "scx_p2dq",
            "scx_rlfifo",
            "scx_rustland",
            "scx_rusty",
            "scx_tickless",
        ];

        for scheduler in schedulers {
            let reqs = kernel_reqs.get(scheduler);
            let allowlist = reqs.map(|r| &r.allowlist);
            let blocklist = reqs.map(|r| &r.blocklist);
            let this_default = reqs
                .map(|r| r.default.as_str())
                .unwrap_or("sched_ext/for-next");

            if let Some(blocklist) = blocklist {
                if blocklist.contains(kernel) {
                    continue;
                }
            }

            // always allow the default kernel through, crates should specify
            // kernel.default if they want a different one
            if !kernel.is_empty() {
                if let Some(allowlist) = allowlist {
                    if !allowlist.is_empty() && !allowlist.contains(kernel) {
                        continue;
                    }
                }
            }

            // use a blank kernel name for the default, as the common case is to
            // have no trailers and it makes the matrix names harder to read.
            let kernel_name = if kernel == this_default {
                String::new()
            } else {
                kernel.clone()
            };

            matrix.insert((scheduler.to_string(), String::new(), kernel_name));
        }

        // scx_layered with different flags
        let flags_combinations = vec![
            vec!["--disable-topology=false", ""],
            vec!["--disable-topology=false", "--disable-antistall"],
            vec!["--disable-topology=true", ""],
            vec!["--disable-topology=true", "--disable-antistall"],
        ];

        for flags in flags_combinations {
            let flags_str = flags
                .iter()
                .filter(|f| !f.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" ");

            let this_default = "sched_ext/for-next";
            let kernel_name = if kernel == this_default {
                String::new()
            } else {
                kernel.clone()
            };

            matrix.insert(("scx_layered".to_string(), flags_str, kernel_name));
        }
    }

    let mut matrix: Vec<MatrixEntry> = matrix
        .into_iter()
        .map(|(name, flags, kernel)| MatrixEntry {
            name,
            flags,
            kernel,
        })
        .collect();

    // Sort for deterministic output
    matrix.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.flags.cmp(&b.flags))
            .then(a.kernel.cmp(&b.kernel))
    });

    let json = serde_json::to_string(&matrix).context("Failed to serialize matrix")?;
    println!("matrix={}", json);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gix::actor::{Sign, Signature, Time};
    use tempfile::TempDir;

    fn create_test_repo() -> Result<(TempDir, gix::Repository)> {
        let temp_dir = TempDir::new()?;
        let repo = gix::init(temp_dir.path())?;
        Ok((temp_dir, repo))
    }

    fn create_commit(
        repo: &gix::Repository,
        message: &str,
        parents: &[gix::ObjectId],
    ) -> Result<gix::ObjectId> {
        // Create an empty tree
        let empty_tree = {
            let mut tree = gix::objs::Tree::empty();
            let oid = repo.write_object(&tree)?;
            oid.detach()
        };

        let signature = Signature {
            name: "Test User".into(),
            email: "test@example.com".into(),
            time: Time {
                seconds: 1234567890,
                offset: 0,
                sign: Sign::Plus,
            },
        };

        let commit = gix::objs::Commit {
            tree: empty_tree,
            parents: parents.iter().map(|p| p.to_owned()).collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: message.into(),
            extra_headers: vec![],
        };

        let commit_id = repo.write_object(&commit)?;
        Ok(commit_id.detach())
    }

    fn set_head(repo: &gix::Repository, commit_id: gix::ObjectId) -> Result<()> {
        // Update HEAD to point to the new commit
        let mut head = repo.find_reference("HEAD")?;
        head.set_target_id(commit_id);
        Ok(())
    }

    #[test]
    fn test_single_trailer_in_commit() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        // Create a commit with a single CI-Test-Kernel trailer
        let commit1 = create_commit(&repo, "Initial commit", &[])?;
        let commit2 = create_commit(
            &repo,
            "Test commit\n\nCI-Test-Kernel: linux-6.12",
            &[commit1],
        )?;

        set_head(&repo, commit2)?;

        // Create main branch pointing to commit1
        repo.reference(
            "refs/heads/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        // Create origin/main pointing to commit1
        repo.reference(
            "refs/remotes/origin/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        // Change to repo directory for the test
        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        assert_eq!(kernels.len(), 1);
        assert!(kernels.contains("linux-6.12"));

        Ok(())
    }

    #[test]
    fn test_multiple_trailers_in_single_commit() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        let commit1 = create_commit(&repo, "Initial commit", &[])?;
        let commit2 = create_commit(
            &repo,
            "Test commit\n\nCI-Test-Kernel: linux-6.12\nCI-Test-Kernel: linux-6.11",
            &[commit1],
        )?;

        set_head(&repo, commit2)?;

        repo.reference(
            "refs/heads/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        repo.reference(
            "refs/remotes/origin/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        assert_eq!(kernels.len(), 2);
        assert!(kernels.contains("linux-6.12"));
        assert!(kernels.contains("linux-6.11"));

        Ok(())
    }

    #[test]
    fn test_multiple_commits_with_trailers() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        let commit1 = create_commit(&repo, "Initial commit", &[])?;
        let commit2 = create_commit(
            &repo,
            "Second commit\n\nCI-Test-Kernel: linux-6.12",
            &[commit1],
        )?;
        let commit3 = create_commit(
            &repo,
            "Third commit\n\nCI-Test-Kernel: linux-6.11",
            &[commit2],
        )?;

        set_head(&repo, commit3)?;

        repo.reference(
            "refs/heads/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        repo.reference(
            "refs/remotes/origin/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        assert_eq!(kernels.len(), 2);
        assert!(kernels.contains("linux-6.12"));
        assert!(kernels.contains("linux-6.11"));

        Ok(())
    }

    #[test]
    fn test_no_trailers() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        let commit1 = create_commit(&repo, "Initial commit", &[])?;
        let commit2 = create_commit(&repo, "Second commit\n\nNo trailers here", &[commit1])?;

        set_head(&repo, commit2)?;

        repo.reference(
            "refs/heads/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        repo.reference(
            "refs/remotes/origin/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        assert_eq!(kernels.len(), 0);

        Ok(())
    }

    #[test]
    fn test_trailer_with_blank_lines() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        let commit1 = create_commit(&repo, "Initial commit", &[])?;
        // Trailer block should stop at blank lines
        let commit2 = create_commit(
            &repo,
            "Test commit\n\nSome text\n\nCI-Test-Kernel: linux-6.12",
            &[commit1],
        )?;

        set_head(&repo, commit2)?;

        repo.reference(
            "refs/heads/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        repo.reference(
            "refs/remotes/origin/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        assert_eq!(kernels.len(), 1);
        assert!(kernels.contains("linux-6.12"));

        Ok(())
    }

    #[test]
    fn test_mixed_trailers() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        let commit1 = create_commit(&repo, "Initial commit", &[])?;
        let commit2 = create_commit(
            &repo,
            "Test commit\n\nSigned-off-by: Test User <test@example.com>\nCI-Test-Kernel: linux-6.12\nReviewed-by: Reviewer <reviewer@example.com>",
            &[commit1],
        )?;

        set_head(&repo, commit2)?;

        repo.reference(
            "refs/heads/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        repo.reference(
            "refs/remotes/origin/main",
            commit1,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        assert_eq!(kernels.len(), 1);
        assert!(kernels.contains("linux-6.12"));

        Ok(())
    }

    #[test]
    fn test_stack_with_multiple_trailers() -> Result<()> {
        let (_temp_dir, repo) = create_test_repo()?;

        // Create a stack of commits with different trailer configurations
        let base = create_commit(&repo, "Base commit", &[])?;

        // Commit with one trailer
        let commit1 = create_commit(
            &repo,
            "First change\n\nCI-Test-Kernel: linux-6.12",
            &[base],
        )?;

        // Commit with multiple trailers
        let commit2 = create_commit(
            &repo,
            "Second change\n\nCI-Test-Kernel: linux-6.11\nCI-Test-Kernel: linux-6.10",
            &[commit1],
        )?;

        // Commit with no trailers
        let commit3 = create_commit(
            &repo,
            "Third change\n\nNo kernel testing needed",
            &[commit2],
        )?;

        // Commit with trailer and other metadata
        let commit4 = create_commit(
            &repo,
            "Fourth change\n\nSigned-off-by: Dev <dev@example.com>\nCI-Test-Kernel: linux-6.9\nReviewed-by: Reviewer <rev@example.com>",
            &[commit3],
        )?;

        set_head(&repo, commit4)?;

        repo.reference(
            "refs/heads/main",
            base,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create main",
        )?;

        repo.reference(
            "refs/remotes/origin/main",
            base,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "create origin/main",
        )?;

        env::set_current_dir(_temp_dir.path())?;
        env::set_var("GITHUB_BASE_REF", "main");

        let kernels = get_kernel_trailers_from_commits()?;

        // Should find all unique kernels across the stack
        assert_eq!(kernels.len(), 4);
        assert!(kernels.contains("linux-6.12"));
        assert!(kernels.contains("linux-6.11"));
        assert!(kernels.contains("linux-6.10"));
        assert!(kernels.contains("linux-6.9"));

        Ok(())
    }
}
