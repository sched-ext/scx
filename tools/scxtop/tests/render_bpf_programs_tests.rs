// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// Basic smoke tests for BPF program rendering
// More comprehensive tests would require constructing complex BpfProgData structures

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use scxtop::render::bpf_programs::{ProgramDetailParams, ProgramsListParams};
use scxtop::{render::BpfProgramRenderer, AppTheme, BpfProgStats, Columns};
use std::collections::VecDeque;

#[test]
fn test_render_programs_list_empty() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let bpf_program_stats = BpfProgStats::default();
    let filtered_programs = vec![];
    let bpf_program_columns = Columns::new(vec![]);
    let mut table_state = ratatui::widgets::TableState::default();
    let bpf_overhead_history = VecDeque::new();
    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let params = ProgramsListParams {
                bpf_program_stats: &bpf_program_stats,
                filtered_programs: &filtered_programs,
                bpf_program_columns: &bpf_program_columns,
                bpf_overhead_history: &bpf_overhead_history,
                filtering: false,
                filter_input: "",
                event_input_buffer: "",
                theme: &theme,
                tick_rate_ms: 1000,
            };
            let result = BpfProgramRenderer::render_programs_list(frame, &mut table_state, &params);

            assert!(
                result.is_ok(),
                "render_programs_list should succeed with empty program list"
            );
        })
        .unwrap();
}

#[test]
fn test_render_programs_list_with_overhead_history() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let bpf_program_stats = BpfProgStats::default();
    let filtered_programs = vec![];
    let bpf_program_columns = Columns::new(vec![]);
    let mut table_state = ratatui::widgets::TableState::default();
    let mut bpf_overhead_history = VecDeque::new();

    // Add some overhead history
    for i in 0..60 {
        bpf_overhead_history.push_back((i as f64) * 0.1);
    }

    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let params = ProgramsListParams {
                bpf_program_stats: &bpf_program_stats,
                filtered_programs: &filtered_programs,
                bpf_program_columns: &bpf_program_columns,
                bpf_overhead_history: &bpf_overhead_history,
                filtering: false,
                filter_input: "",
                event_input_buffer: "",
                theme: &theme,
                tick_rate_ms: 1000,
            };
            let result = BpfProgramRenderer::render_programs_list(frame, &mut table_state, &params);

            assert!(
                result.is_ok(),
                "render_programs_list should succeed with overhead history"
            );
        })
        .unwrap();
}

#[test]
fn test_render_programs_list_different_themes() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let bpf_program_stats = BpfProgStats::default();
    let filtered_programs = vec![];
    let bpf_program_columns = Columns::new(vec![]);
    let bpf_overhead_history = VecDeque::new();

    for theme in [
        AppTheme::Default,
        AppTheme::MidnightGreen,
        AppTheme::SolarizedDark,
    ] {
        let mut table_state = ratatui::widgets::TableState::default();

        terminal
            .draw(|frame| {
                let params = ProgramsListParams {
                    bpf_program_stats: &bpf_program_stats,
                    filtered_programs: &filtered_programs,
                    bpf_program_columns: &bpf_program_columns,
                    bpf_overhead_history: &bpf_overhead_history,
                    filtering: false,
                    filter_input: "",
                    event_input_buffer: "",
                    theme: &theme,
                    tick_rate_ms: 1000,
                };
                let result =
                    BpfProgramRenderer::render_programs_list(frame, &mut table_state, &params);

                assert!(
                    result.is_ok(),
                    "render_programs_list with {:?} theme should succeed",
                    theme
                );
            })
            .unwrap();
    }
}

#[test]
fn test_render_program_detail_no_program() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let bpf_program_stats = BpfProgStats::default();
    let filtered_symbols = vec![];
    let mut symbol_table_state = ratatui::widgets::TableState::default();
    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let params = ProgramDetailParams {
                selected_program_data: None, // no program selected
                bpf_program_stats: &bpf_program_stats,
                filtered_symbols: &filtered_symbols,
                bpf_perf_sampling_active: false,
                active_event_name: "cycles",
                theme: &theme,
                tick_rate_ms: 1000,
            };
            let result =
                BpfProgramRenderer::render_program_detail(frame, &mut symbol_table_state, &params);

            assert!(
                result.is_ok(),
                "render_program_detail should succeed with no program selected"
            );
        })
        .unwrap();
}

#[test]
fn test_render_program_detail_different_themes() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let bpf_program_stats = BpfProgStats::default();
    let filtered_symbols = vec![];

    for theme in [
        AppTheme::Default,
        AppTheme::MidnightGreen,
        AppTheme::SolarizedDark,
    ] {
        let mut symbol_table_state = ratatui::widgets::TableState::default();

        terminal
            .draw(|frame| {
                let params = ProgramDetailParams {
                    selected_program_data: None,
                    bpf_program_stats: &bpf_program_stats,
                    filtered_symbols: &filtered_symbols,
                    bpf_perf_sampling_active: false,
                    active_event_name: "cycles",
                    theme: &theme,
                    tick_rate_ms: 1000,
                };
                let result = BpfProgramRenderer::render_program_detail(
                    frame,
                    &mut symbol_table_state,
                    &params,
                );

                assert!(
                    result.is_ok(),
                    "render_program_detail with {:?} theme should succeed",
                    theme
                );
            })
            .unwrap();
    }
}
