// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! In-place checkpoint/revert for the optimization loop, using the git index.
//!
//! The optimizer edits the scheduler crate in place on the current branch - it
//! creates no branch and makes no commits. The git index is used as the
//! checkpoint: an accepted round is staged (`git add`), and a rejected round is
//! reverted by restoring the working tree from the index (`git checkout --`),
//! which leaves earlier accepted changes intact and keeps cargo's incremental
//! build cache warm. When the run ends the crate is unstaged, so the winning
//! variant is left as ordinary (uncommitted) working-tree modifications.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("spawn git {args:?}"))?;
    if !out.status.success() {
        bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The crate directory must have no uncommitted changes before we start, so the
/// index checkpoint begins at a known-clean baseline and a revert is safe.
pub fn ensure_clean(repo: &Path, rel_crate: &str) -> Result<()> {
    let status = git(repo, &["status", "--porcelain", "--", rel_crate])?;
    if !status.is_empty() {
        bail!(
            "crate dir '{rel_crate}' has uncommitted changes; commit or stash them first:\n{status}"
        );
    }
    Ok(())
}

pub fn rev_parse(repo: &Path, refname: &str) -> Result<String> {
    git(repo, &["rev-parse", refname])
}

/// Revert the crate working tree to the last checkpoint by restoring it from the
/// index (the last accepted state, or the baseline if nothing is accepted yet).
pub fn discard(repo: &Path, rel_crate: &str) -> Result<()> {
    git(repo, &["checkout", "--", rel_crate])?;
    Ok(())
}

/// Checkpoint the current crate state as accepted by staging it into the index.
pub fn checkpoint(repo: &Path, rel_crate: &str) -> Result<()> {
    git(repo, &["add", "--", rel_crate])?;
    Ok(())
}

/// Unstage the crate (reset the index to HEAD) while keeping working-tree edits,
/// so an accepted result is left as plain uncommitted modifications.
pub fn unstage(repo: &Path, rel_crate: &str) -> Result<()> {
    git(repo, &["reset", "-q", "--", rel_crate])?;
    Ok(())
}

/// Diff of the crate dir between `base_ref` and the working tree.
pub fn diff(repo: &Path, base_ref: &str, rel_crate: &str) -> Result<String> {
    git(repo, &["diff", base_ref, "--", rel_crate])
}

/// Diff of the crate dir between the index checkpoint and the working tree.
pub fn worktree_diff(repo: &Path, rel_crate: &str) -> Result<String> {
    git(repo, &["diff", "--", rel_crate])
}
