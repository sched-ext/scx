use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

#[derive(Debug, Clone)]
pub struct Search {
    entries: Vec<String>,
}

impl Search {
    pub fn new(entries: Vec<String>) -> Self {
        Self { entries }
    }

    pub fn substring_search(&self, input: &str) -> Vec<String> {
        let input = &input.to_lowercase();

        self.entries
            .iter()
            .filter(|entry| entry.to_lowercase().contains(input))
            .cloned()
            .collect()
    }

    pub fn fuzzy_search(&self, input: &str) -> Vec<String> {
        let matcher = SkimMatcherV2::default().ignore_case();

        let mut fuzzy_results: Vec<(&String, i64)> = self
            .entries
            .iter()
            .filter_map(|entry| {
                matcher
                    .fuzzy_match(entry, input)
                    .map(|score| (entry, score))
            })
            .collect();

        fuzzy_results.sort_by(|a, b| b.1.cmp(&a.1));

        fuzzy_results
            .into_iter()
            .map(|(entry, _)| entry.clone())
            .collect()
    }
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
    fn test_fuzzy_search_empty() {
        let events = test_events();
        let search = Search::new(events);
        let results = search.fuzzy_search("");

        assert_eq!(
            results.len(),
            19,
            "Expected all results, got {}",
            results.len()
        );
    }

    #[test]
    fn test_fuzzy_search_basic() {
        let events = test_events();
        let search = Search::new(events);

        let results = search.fuzzy_search("gettid");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "syscalls:sys_exit_gettid".to_string());
    }

    #[test]
    fn test_fuzzy_search_exact_input() {
        let events = test_events();
        let search = Search::new(events);
        let results = search.fuzzy_search("alarmtimer_cancel");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }

    #[test]
    fn test_fuzzy_search_exact_input_multiple_results() {
        let events = test_events();
        let search = Search::new(events);
        let results = search.fuzzy_search("alarm");

        let expected_matches = vec![
            "alarmtimer:alarmtimer_suspend",
            "alarmtimer:alarmtimer_fired",
            "alarmtimer:alarmtimer_cancel",
        ];

        for expected in expected_matches.iter() {
            assert!(
                results.contains(&expected.to_string()),
                "Missing expected match: {}",
                expected
            );
        }

        assert!(results.len() >= expected_matches.len());
    }

    #[test]
    fn test_fuzzy_search_complex_input() {
        let events = test_events();
        let search = Search::new(events);
        let results = search.fuzzy_search("alrMcacEL");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }

    #[test]
    fn test_fuzzy_search_reuse_search() {
        let events = test_events();
        let search = Search::new(events);

        let results = search.fuzzy_search("");
        assert_eq!(
            results.len(),
            19,
            "Expected all results, got {}",
            results.len()
        );

        let results = search.fuzzy_search("gettid");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "syscalls:sys_exit_gettid".to_string());

        let results = search.fuzzy_search("alarmtimer_cancel");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());

        let results = search.fuzzy_search("alarm");
        let expected_matches = vec![
            "alarmtimer:alarmtimer_suspend",
            "alarmtimer:alarmtimer_fired",
            "alarmtimer:alarmtimer_cancel",
        ];

        for expected in expected_matches.iter() {
            assert!(
                results.contains(&expected.to_string()),
                "Missing expected match: {}",
                expected
            );
        }

        assert!(
            results.len() >= expected_matches.len(),
            "Expected all results, got {}",
            results.len()
        );

        let results = search.fuzzy_search("alrMcacEL");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "alarmtimer:alarmtimer_cancel".to_string());
    }
}
