// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use num_format::SystemLocale;
use ratatui::backend::TestBackend;
use ratatui::widgets::TableState;
use ratatui::Terminal;
use scxtop::render::scheduler::{DsqSummaryParams, ProcessLatencyParams, SchedulerViewParams};
use scxtop::{render::SchedulerRenderer, AppTheme, EventData, ProcData, ViewState};
use std::collections::BTreeMap;

// Helper function to create test DSQ data
fn create_test_dsq_data() -> BTreeMap<u64, EventData> {
    let mut dsq_data = BTreeMap::new();

    // Add DSQ 0 with some event data
    let mut dsq0 = EventData::new(60);
    for i in 0..60 {
        dsq0.add_event_data("dsq_lat_us", (i * 10) as u64);
        dsq0.add_event_data("dsq_slice_consumed", (i * 100) as u64);
        dsq0.add_event_data("dsq_vtime", (i * 1000) as u64);
        dsq0.add_event_data("dsq_nr_queued", (i % 10) as u64);
    }
    dsq_data.insert(0, dsq0);

    // Add DSQ 1 with different data
    let mut dsq1 = EventData::new(60);
    for i in 0..60 {
        dsq1.add_event_data("dsq_lat_us", (i * 15) as u64);
        dsq1.add_event_data("dsq_slice_consumed", (i * 150) as u64);
    }
    dsq_data.insert(1, dsq1);

    dsq_data
}

#[test]
fn test_render_scheduler_view_sparkline() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let dsq_data = create_test_dsq_data();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = SchedulerViewParams {
                event: "dsq_lat_us",
                scheduler_name: "scx_rustland",
                dsq_data: &dsq_data,
                sample_rate: 1000,
                localize: false,
                locale: &locale,
                theme: &theme,
                render_title: true,
                render_sample_rate: true,
            };
            let result = SchedulerRenderer::render_scheduler_view(
                frame,
                area,
                &ViewState::Sparkline,
                60,
                &params,
            );

            assert!(
                result.is_ok(),
                "render_scheduler_view sparkline should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_scheduler_view_barchart() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let dsq_data = create_test_dsq_data();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = SchedulerViewParams {
                event: "dsq_lat_us",
                scheduler_name: "scx_rustland",
                dsq_data: &dsq_data,
                sample_rate: 1000,
                localize: false,
                locale: &locale,
                theme: &theme,
                render_title: true,
                render_sample_rate: true,
            };
            let result = SchedulerRenderer::render_scheduler_view(
                frame,
                area,
                &ViewState::BarChart,
                60,
                &params,
            );

            assert!(
                result.is_ok(),
                "render_scheduler_view barchart should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_scheduler_view_no_scheduler() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let dsq_data = BTreeMap::new();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = SchedulerViewParams {
                event: "dsq_lat_us",
                scheduler_name: "", // Empty scheduler name
                dsq_data: &dsq_data,
                sample_rate: 1000,
                localize: false,
                locale: &locale,
                theme: &theme,
                render_title: true,
                render_sample_rate: true,
            };
            let result = SchedulerRenderer::render_scheduler_view(
                frame,
                area,
                &ViewState::Sparkline,
                60,
                &params,
            );

            assert!(
                result.is_ok(),
                "render_scheduler_view with missing scheduler should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_scheduler_view_no_dsqs() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let dsq_data = BTreeMap::new();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = SchedulerViewParams {
                event: "dsq_lat_us",
                scheduler_name: "scx_rustland",
                dsq_data: &dsq_data,
                sample_rate: 1000,
                localize: false,
                locale: &locale,
                theme: &theme,
                render_title: true,
                render_sample_rate: true,
            };
            let result = SchedulerRenderer::render_scheduler_view(
                frame,
                area,
                &ViewState::Sparkline,
                60,
                &params,
            );

            assert!(
                result.is_ok(),
                "render_scheduler_view with no DSQs should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_scheduler_view_with_localization() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let dsq_data = create_test_dsq_data();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = SchedulerViewParams {
                event: "dsq_lat_us",
                scheduler_name: "scx_rustland",
                dsq_data: &dsq_data,
                sample_rate: 1000,
                localize: true, // localize enabled
                locale: &locale,
                theme: &theme,
                render_title: true,
                render_sample_rate: true,
            };
            let result = SchedulerRenderer::render_scheduler_view(
                frame,
                area,
                &ViewState::BarChart,
                60,
                &params,
            );

            assert!(
                result.is_ok(),
                "render_scheduler_view with localization should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_dsq_summary_table() {
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    let dsq_data = create_test_dsq_data();
    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = DsqSummaryParams {
                scheduler_name: "scx_rustland",
                dsq_data: &dsq_data,
                sample_rate: 1000,
                dsq_filter_text: "",
                filtering: false,
                filter_input: "",
                theme: &theme,
            };
            let result = SchedulerRenderer::render_dsq_summary_table(
                frame,
                area,
                &params,
                &mut TableState::default(),
            );

            assert!(result.is_ok(), "render_dsq_summary_table should succeed");
        })
        .unwrap();
}

#[test]
fn test_render_dsq_summary_table_empty() {
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    let dsq_data = BTreeMap::new();
    let theme = AppTheme::Default;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = DsqSummaryParams {
                scheduler_name: "scx_rustland",
                dsq_data: &dsq_data,
                sample_rate: 1000,
                dsq_filter_text: "",
                filtering: false,
                filter_input: "",
                theme: &theme,
            };
            let result = SchedulerRenderer::render_dsq_summary_table(
                frame,
                area,
                &params,
                &mut TableState::default(),
            );

            assert!(
                result.is_ok(),
                "render_dsq_summary_table with empty data should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_dsq_summary_table_different_themes() {
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    let dsq_data = create_test_dsq_data();

    for theme in [
        AppTheme::Default,
        AppTheme::MidnightGreen,
        AppTheme::SolarizedDark,
    ] {
        terminal
            .draw(|frame| {
                let area = frame.area();
                let params = DsqSummaryParams {
                    scheduler_name: "scx_rustland",
                    dsq_data: &dsq_data,
                    sample_rate: 1000,
                    dsq_filter_text: "",
                    filtering: false,
                    filter_input: "",
                    theme: &theme,
                };
                let result = SchedulerRenderer::render_dsq_summary_table(
                    frame,
                    area,
                    &params,
                    &mut TableState::default(),
                );

                assert!(
                    result.is_ok(),
                    "render_dsq_summary_table with {:?} theme should succeed",
                    theme
                );
            })
            .unwrap();
    }
}

#[test]
fn test_render_process_latency_table() {
    let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
    let theme = AppTheme::Default;

    // Use empty proc_data since we can't easily create ProcData without /proc
    let proc_data: BTreeMap<i32, ProcData> = BTreeMap::new();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let params = ProcessLatencyParams {
                proc_data: &proc_data,
                dsq_filter_text: "",
                theme: &theme,
            };
            let result = SchedulerRenderer::render_process_latency_table(
                frame,
                area,
                &params,
                &mut TableState::default(),
            );

            assert!(
                result.is_ok(),
                "render_process_latency_table should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_scheduler_view_different_events() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let dsq_data = create_test_dsq_data();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    for event in [
        "dsq_lat_us",
        "dsq_slice_consumed",
        "dsq_vtime",
        "dsq_nr_queued",
    ] {
        terminal
            .draw(|frame| {
                let area = frame.area();
                let params = SchedulerViewParams {
                    event,
                    scheduler_name: "scx_rustland",
                    dsq_data: &dsq_data,
                    sample_rate: 1000,
                    localize: false,
                    locale: &locale,
                    theme: &theme,
                    render_title: true,
                    render_sample_rate: true,
                };
                let result = SchedulerRenderer::render_scheduler_view(
                    frame,
                    area,
                    &ViewState::Sparkline,
                    60,
                    &params,
                );

                assert!(
                    result.is_ok(),
                    "render_scheduler_view with event {} should succeed",
                    event
                );
            })
            .unwrap();
    }
}
