// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use scxtop::{render::MemoryRenderer, AppTheme, KeyMap, MemStatSnapshot};

// Helper function to create test MemStatSnapshot
fn create_test_mem_stats() -> MemStatSnapshot {
    MemStatSnapshot {
        total_kb: 16777216,        // 16GB
        free_kb: 8388608,          // 8GB
        available_kb: 10485760,    // 10GB
        active_kb: 4194304,        // 4GB
        inactive_kb: 3145728,      // 3GB
        active_anon_kb: 2097152,   // 2GB
        inactive_anon_kb: 1048576, // 1GB
        active_file_kb: 2097152,   // 2GB
        inactive_file_kb: 2097152, // 2GB
        unevictable_kb: 0,
        mlocked_kb: 0,
        shmem_kb: 524288,       // 512MB
        buffers_kb: 524288,     // 512MB
        cached_kb: 2097152,     // 2GB
        swap_total_kb: 4194304, // 4GB
        swap_free_kb: 4194304,  // 4GB (no swap used)
        swap_cached_kb: 0,
        dirty_kb: 1024, // 1MB
        writeback_kb: 0,
        anon_pages_kb: 3145728,  // 3GB
        mapped_kb: 1048576,      // 1GB
        slab_kb: 524288,         // 512MB
        sreclaimable_kb: 262144, // 256MB
        sunreclaim_kb: 262144,   // 256MB
        kernel_stack_kb: 16384,  // 16MB
        page_tables_kb: 32768,   // 32MB
        nfs_unstable_kb: 0,
        bounce_kb: 0,
        writeback_tmp_kb: 0,
        commit_limit_kb: 12582912,     // 12GB
        committed_as_kb: 8388608,      // 8GB
        vmalloc_total_kb: 34359738368, // 32TB (typical)
        vmalloc_used_kb: 524288,       // 512MB
        vmalloc_chunk_kb: 0,
        hardware_corrupted_kb: 0,
        anon_huge_pages_kb: 0,
        shmem_huge_pages_kb: 0,
        shmem_pmd_mapped_kb: 0,
        cma_total_kb: 0,
        cma_free_kb: 0,
        huge_pages_total: 0,
        huge_pages_free: 0,
        huge_pages_rsvd: 0,
        huge_pages_surp: 0,
        hugepagesize_kb: 2048,      // 2MB
        direct_map_4k_kb: 1048576,  // 1GB
        direct_map_2m_kb: 15728640, // 15GB
        direct_map_1g_kb: 0,
        swap_pages_in: 0,
        swap_pages_out: 0,
        prev_swap_pages_in: 0,
        prev_swap_pages_out: 0,
        delta_swap_in: 0,
        delta_swap_out: 0,
        pgfault: 1001000,
        pgmajfault: 1010,
        prev_pgfault: 1000000,
        prev_pgmajfault: 1000,
        delta_pgfault: 1000,
        delta_pgmajfault: 10,
    }
}

#[test]
fn test_render_memory_view_basic() {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mem_stats = create_test_mem_stats();
    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let result = MemoryRenderer::render_memory_view(
                frame, &mem_stats, 100,  // sample_rate
                1000, // tick_rate_ms
                &theme,
            );

            assert!(result.is_ok(), "render_memory_view should succeed");
        })
        .unwrap();
}

#[test]
fn test_render_memory_view_with_swap_usage() {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut mem_stats = create_test_mem_stats();

    // Set swap to 50% used
    mem_stats.swap_total_kb = 4194304; // 4GB
    mem_stats.swap_free_kb = 2097152; // 2GB free = 50% used

    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let result = MemoryRenderer::render_memory_view(frame, &mem_stats, 100, 1000, &theme);

            assert!(
                result.is_ok(),
                "render_memory_view with swap usage should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_memory_view_low_memory() {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut mem_stats = create_test_mem_stats();

    // Set low available memory (10% available)
    mem_stats.available_kb = mem_stats.total_kb / 10;

    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let result = MemoryRenderer::render_memory_view(frame, &mem_stats, 100, 1000, &theme);

            assert!(
                result.is_ok(),
                "render_memory_view with low memory should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_memory_summary_basic() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mem_stats = create_test_mem_stats();
    let theme = AppTheme::Default;
    let keymap = KeyMap::default();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result =
                MemoryRenderer::render_memory_summary(frame, area, &mem_stats, &keymap, &theme);

            assert!(result.is_ok(), "render_memory_summary should succeed");
        })
        .unwrap();
}

#[test]
fn test_render_memory_summary_with_different_themes() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mem_stats = create_test_mem_stats();
    let keymap = KeyMap::default();

    for theme in [
        AppTheme::Default,
        AppTheme::MidnightGreen,
        AppTheme::SolarizedDark,
    ] {
        terminal
            .draw(|frame| {
                let area = frame.area();
                let result =
                    MemoryRenderer::render_memory_summary(frame, area, &mem_stats, &keymap, &theme);

                assert!(
                    result.is_ok(),
                    "render_memory_summary with {:?} theme should succeed",
                    theme
                );
            })
            .unwrap();
    }
}

#[test]
fn test_render_memory_view_small_area() {
    // Test rendering in a small terminal
    let mut terminal = Terminal::new(TestBackend::new(40, 20)).unwrap();
    let mem_stats = create_test_mem_stats();
    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let result = MemoryRenderer::render_memory_view(frame, &mem_stats, 100, 1000, &theme);

            assert!(
                result.is_ok(),
                "render_memory_view in small area should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_memory_view_zero_swap() {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut mem_stats = create_test_mem_stats();

    // Set no swap configured
    mem_stats.swap_total_kb = 0;
    mem_stats.swap_free_kb = 0;

    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let result = MemoryRenderer::render_memory_view(frame, &mem_stats, 100, 1000, &theme);

            assert!(
                result.is_ok(),
                "render_memory_view with zero swap should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_memory_view_high_memory_usage() {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut mem_stats = create_test_mem_stats();

    // Set high memory usage (95% used)
    mem_stats.available_kb = mem_stats.total_kb / 20; // Only 5% available

    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let result = MemoryRenderer::render_memory_view(frame, &mem_stats, 100, 1000, &theme);

            assert!(
                result.is_ok(),
                "render_memory_view with high memory usage should succeed"
            );
        })
        .unwrap();
}
