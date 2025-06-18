// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use scx_utils::compat::tracefs_mount;

use crate::Search;

pub struct AllKprobeEvents {
    entries: Search,
}

impl AllKprobeEvents {
    pub fn new() -> Result<Self> {
        let kprobe_events = available_kprobe_events()?;
        Ok(Self { entries: Search::new(kprobe_events) })
    }

    pub fn is_valid_kprobe_event(&self, event: &str) -> bool {
        self.entries.binary_search(&event.to_lowercase().to_string()).is_some()
    }

    pub fn are_valid_kprobe_events(&self, events: &[String]) -> bool {
        events.iter().all(|e| self.is_valid_kprobe_event(e))
    }
}

/// Returns the available kprobe events on the system from tracefs.
pub fn available_kprobe_events() -> Result<Vec<String>> {
    let path = tracefs_mount()?;
    let file = File::open(path.join("available_filter_functions"))?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        events.push(line);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_kprobe_event_basic() {
        let kprobe_events = AllKprobeEvents::new().unwrap();
        assert!(kprobe_events.is_valid_kprobe_event("k_fn"));
        assert!(kprobe_events.is_valid_kprobe_event("bpf_scx_is_valid_access"));
        assert!(kprobe_events.is_valid_kprobe_event("__probestub_xfs_readlink"));
        assert!(!kprobe_events.is_valid_kprobe_event(""));
        assert!(!kprobe_events.is_valid_kprobe_event("blahblah"));
    }

    #[test]
    fn test_is_valid_kprobe_event_uppercase() {
        let kprobe_events = AllKprobeEvents::new().unwrap();
        assert!(kprobe_events.is_valid_kprobe_event("k_FN"));
        assert!(kprobe_events.is_valid_kprobe_event("__PROBESTUB_XFS_READLINK"));
        assert!(kprobe_events.is_valid_kprobe_event("bPf_sCx_Is_VaLiD_aCcEsS"));
    }

    #[test]
    fn test_are_valid_kprobe_events_basic() {
        let kprobe_events = AllKprobeEvents::new().unwrap();
        assert!(kprobe_events.are_valid_kprobe_events(&vec![]));
        assert!(kprobe_events.are_valid_kprobe_events(&vec!["k_fn".to_string()]));
        assert!(kprobe_events.are_valid_kprobe_events(&vec![
            "k_fn".to_string(),
            "__probestub_xfs_readlink".to_string(),
            "bpf_scx_is_valid_access".to_string(),
        ]));
        assert!(!kprobe_events.are_valid_kprobe_events(&vec![
            "k_fn".to_string(),
            "__probestub_xfs_readlink".to_string(),
            "bpf_scx_is_valid_access".to_string(),
            "blahblah".to_string(),
        ]));
    }

    #[test]
    fn test_are_valid_kprobe_events_uppercase() {
        let kprobe_events = AllKprobeEvents::new().unwrap();
        assert!(kprobe_events.are_valid_kprobe_events(&vec!["k_FN".to_string()]));
        assert!(kprobe_events.are_valid_kprobe_events(&vec![
            "k_FN".to_string(),
            "__PROBESTUB_XFS_READLINK".to_string(),
            "bPf_sCx_Is_VaLiD_aCcEsS".to_string(),
        ]));
    }
}
