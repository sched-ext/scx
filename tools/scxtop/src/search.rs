// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::cmp::min;

#[allow(dead_code)]
pub fn binary_search(entries: &[String], input: &str) -> Option<usize> {
    entries.binary_search_by(|s| s.as_str().cmp(input)).ok()
}

pub fn substring_search(entries: &[String], input: &str) -> Vec<String> {
    let input = &input.to_lowercase();

    entries
        .iter()
        .filter(|entry| entry.to_lowercase().contains(input))
        .cloned()
        .collect()
}

pub fn sorted_contains(entries: &[String], input: &str) -> bool {
    binary_search(entries, input).is_some()
}

pub fn sorted_contains_all(entries: &[String], inputs: &[String]) -> bool {
    inputs.iter().all(|input| sorted_contains(entries, input))
}

/**
 * We'll want check fuzzily in three ways using the following scoring system:
 * 1: Is it a substring (contains)? 100 points
 * 2: Is it contained in the string but not consecutive (contains_spread)? 100 - (length of input spread out - input length)
 * 3: If we take out one letter, is it now (1) or (2) - (contains_with_typo)? 75 - (length of input spread out - input length)
 *
 * This method will then return a Vec<String> with the highest scoring entries at the lowest indices
 */
pub fn fuzzy_search(entries: &[String], input: &str) -> Vec<String> {
    let input = &input.to_lowercase();

    let mut fuzzy_results: Vec<(&String, u32)> = entries
        .iter()
        .filter_map(|entry| {
            let entry_lower = &entry.to_lowercase();
            entry_lower
                .contains(input)
                .then_some((entry, 100))
                .or_else(|| contains_spread(entry_lower, input).map(|score| (entry, 100 - score)))
        })
        .collect();

    // We only check if our input has a typo if we haven't matched to anything else (for performance reasons)
    if fuzzy_results.is_empty() {
        fuzzy_results = entries
            .iter()
            .filter_map(|entry| {
                contains_with_typo(&entry.to_lowercase(), input).map(|score| (entry, 75 - score))
            })
            .collect()
    }

    fuzzy_results.sort_by(|a, b| b.1.cmp(&a.1));

    fuzzy_results
        .into_iter()
        .map(|(entry, _)| entry.clone())
        .collect()
}

/**
 * Returns Some(n) if all characters of 'pattern' appear in order within 'word',
 * allowing for other characters in between. 'n' is the number of extra characters present.
 * Returns None if the pattern does not appear or does not appear in order.
 *
 * This operates at the byte level, so Unicode scores may be unintuitive but will always be Some
 * if the pattern matches and None if it does not. See test_contains_spread_unicode for details.
 */
pub fn contains_spread(word: &str, pattern: &str) -> Option<u32> {
    if pattern.is_empty() {
        return Some(0);
    }

    let word_bytes = word.as_bytes();
    let word_len = word_bytes.len();
    let pattern_bytes = pattern.as_bytes();
    let pattern_len = pattern_bytes.len();

    if word_len < pattern_len {
        // Pattern cannot be contained in a shorter word
        return None;
    }

    let mut start = 0;
    let mut pat_idx = 0;

    for (i, &byte) in word_bytes.iter().enumerate() {
        if byte == pattern_bytes[pat_idx] {
            if pat_idx == 0 {
                start = i;
            }

            pat_idx += 1;

            if pat_idx == pattern_len {
                let total_len = i - start + 1;
                return Some((total_len - pattern_len) as u32);
            }
        }
    }
    None
}

// Checks for typos by removing each character in pattern, one by one, and calling contains_spread
fn contains_with_typo(word: &str, pattern: &str) -> Option<u32> {
    if pattern.is_empty() {
        return Some(0);
    }

    let mut modified_pattern = String::with_capacity(pattern.len() - 1);
    let mut result = None;

    for i in 0..pattern.len() {
        modified_pattern.push_str(&pattern[..i]);
        modified_pattern.push_str(&pattern[i + 1..]);

        result = match (result, contains_spread(word, &modified_pattern)) {
            (Some(score_a), Some(score_b)) => Some(min(score_a, score_b)),
            (Some(score), None) | (None, Some(score)) => Some(score),
            (_, _) => None,
        };

        modified_pattern.clear();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_events() -> Vec<String> {
        vec![
            "alarmtimer:alarmtimer_suspend",
            "alarmtimer:alarmtimer_fired",
            "amd_cpu:amd_pstate_perf",
            "avc:selinux_audited",
            "btrfs:btrfs_reserve_extent",
            "btrfs:qgroup_num_dirty_extents",
            "btrfs:run_delayed_ref_head",
            "ext4:ext4_fsmap_low_key",
            "ext4:ext4_fc_stats",
            "ext4:ext4_mb_new_inode_pa",
            "syscalls:sys_enter_timerfd_settime",
            "syscalls:sys_enter_settimeofday",
            "syscalls:sys_exit_gettid",
            "syscalls:sys_exit_kcmp",
            "syscalls:sys_exit_pselect6",
            "xfs:xfs_swap_extent_before",
            "xfs:xfs_bmap_free_defer",
            "xhci-hcd:xhci_address_ctrl_ctx",
            "alarmtimer:alarmtimer_cancel",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    #[test]
    fn test_contains_spread_empty() {
        assert_eq!(contains_spread("btrfs:btrfs_reserve_extent", ""), Some(0));
    }

    #[test]
    fn test_contains_spread_basic() {
        let word = "syscalls:sys_exit_pselect6";

        let result_a = contains_spread(word, "exit");
        let result_b = contains_spread(word, "sysexit");

        assert_eq!(result_a, Some(0));
        assert_eq!(result_b, Some(10));
    }

    #[test]
    fn test_contains_spread_complex() {
        let word = "xhci-hcd:xhci_address_ctrl_ctx";

        let result_a = contains_spread(word, "hides");
        let result_b = contains_spread(word, "xxx");

        assert_eq!(result_a, Some(14));
        assert_eq!(result_b, Some(27));
    }

    #[test]
    fn test_contains_spread_cannot_find() {
        let word = "btrfs:btrfs_reserve_extent";

        let result_a = contains_spread(word, "trees");
        let result_b = contains_spread(word, "z");

        assert_eq!(result_a, None);
        assert_eq!(result_b, None);
    }

    #[test]
    fn test_contains_spread_unicode() {
        let word = "こあういえお";
        let input = "あい";

        // Word Bytes: [227, 129, 147, 227, 129, 130, 227, 129, 134, 227, 129, 132, 227, 129, 136, 227, 129, 138]
        // Pattern Bytes: [227, 129, 130, 227, 129, 132]
        // The matching begins at index 0 and ends at index 11, therefore total_len(11) - pattern_len(5) = 6
        assert_eq!(contains_spread(word, input), Some(6));
    }

    #[test]
    fn test_contains_with_typo_empty() {
        assert_eq!(
            contains_with_typo("btrfs:btrfs_reserve_extent", ""),
            Some(0)
        );
    }

    #[test]
    fn test_contains_with_typo_basic() {
        let word = "syscalls:sys_exit_pselect6";

        let result_a = contains_with_typo(word, "exlt");
        let result_b = contains_with_typo(word, "sbsexit");

        assert_eq!(result_a, Some(1));
        assert_eq!(result_b, Some(11));
    }

    #[test]
    fn test_contains_with_typo_complex() {
        let word = "xhci-hcd:xhci_address_ctrl_ctx";

        let result_a = contains_with_typo(word, "hizdes");
        let result_b = contains_with_typo(word, "xxxx");

        assert_eq!(result_a, Some(14));
        assert_eq!(result_b, Some(27));
    }

    #[test]
    fn test_contains_with_typo_cannot_find() {
        let word = "btrfs:btrfs_reserve_extent";

        let result_a = contains_with_typo(word, "btrzz");
        let result_b = contains_with_typo(word, "ww");

        assert_eq!(result_a, None);
        assert_eq!(result_b, None);
    }

    #[test]
    fn test_fuzzy_search_empty() {
        let mut events = test_events();
        events.sort();
        let results = fuzzy_search(&events, "");

        assert_eq!(
            results.len(),
            19,
            "Expected all results, got {}",
            results.len()
        );
    }

    #[test]
    fn test_fuzzy_search_basic() {
        let mut events = test_events();
        events.sort();

        let results = fuzzy_search(&events, "gettid");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "syscalls:sys_exit_gettid".to_string());
    }

    #[test]
    fn test_fuzzy_search_exact_input() {
        let mut events = test_events();
        events.sort();
        let results = fuzzy_search(&events, "alarmtimer_cancel");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }

    #[test]
    fn test_fuzzy_search_exact_input_multiple_results() {
        let mut events = test_events();
        events.sort();
        let results = fuzzy_search(&events, "alarm");

        let expected_matches = [
            "alarmtimer:alarmtimer_suspend",
            "alarmtimer:alarmtimer_fired",
            "alarmtimer:alarmtimer_cancel",
        ];

        for expected in expected_matches.iter() {
            assert!(
                results.contains(&expected.to_string()),
                "Missing expected match: {expected}"
            );
        }

        assert!(results.len() >= expected_matches.len());
    }

    #[test]
    fn test_fuzzy_search_complex_input() {
        let mut events = test_events();
        events.sort();
        let results = fuzzy_search(&events, "alrMcacEL");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }

    #[test]
    fn test_fuzzy_search_long_complex_input() {
        let mut events = test_events();
        events.sort();
        let results = fuzzy_search(&events, "alrMtIImeralarmmer_cacEL");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }

    #[test]
    fn test_fuzzy_search_reuse_search() {
        let mut events = test_events();
        events.sort();

        let results = fuzzy_search(&events, "");
        assert_eq!(
            results.len(),
            19,
            "Expected all results, got {}",
            results.len()
        );

        let results = fuzzy_search(&events, "gettid");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "syscalls:sys_exit_gettid".to_string());

        let results = fuzzy_search(&events, "alarmtimer_cancel");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());

        let results = fuzzy_search(&events, "alarm");
        let expected_matches = [
            "alarmtimer:alarmtimer_suspend",
            "alarmtimer:alarmtimer_fired",
            "alarmtimer:alarmtimer_cancel",
        ];

        for expected in expected_matches.iter() {
            assert!(
                results.contains(&expected.to_string()),
                "Missing expected match: {expected}"
            );
        }

        assert!(
            results.len() >= expected_matches.len(),
            "Expected all results, got {}",
            results.len()
        );

        let results = fuzzy_search(&events, "alrMcacEL");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }

    #[test]
    fn test_binary_search_basic() {
        let mut events = test_events();
        events.sort();

        let result = binary_search(&events, "alarmtimer:alarmtimer_cancel");

        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_binary_search_basic_2() {
        let mut events = test_events();
        events.sort();

        let result = binary_search(&events, "syscalls:sys_enter_settimeofday");

        assert_eq!(result, Some(11));
    }

    #[test]
    fn test_sorted_contains() {
        let mut events = test_events();
        events.sort();

        let result1 = sorted_contains(&events, "ext4:ext4_mb_new_inode_pa");
        assert!(result1);

        let result2 = sorted_contains(&events, "ext4:ext4_mb_new_inode");
        assert!(!result2);
    }

    #[test]
    fn test_sorted_contains_all() {
        let mut events = test_events();
        events.sort();

        let result1 = sorted_contains_all(
            &events,
            &[
                "ext4:ext4_mb_new_inode_pa".to_string(),
                "ext4:ext4_mb_new_inode".to_string(),
            ],
        );
        assert!(!result1);

        let result2 = sorted_contains_all(
            &events,
            &[
                "syscalls:sys_enter_timerfd_settime".to_string(),
                "alarmtimer:alarmtimer_fired".to_string(),
                "ext4:ext4_fc_stats".to_string(),
            ],
        );
        assert!(result2);
    }
}
