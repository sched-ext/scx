// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use procfs::process::ProcState;
use ratatui::backend::TestBackend;
use ratatui::layout::Constraint;
use ratatui::Terminal;
use scxtop::{
    render::ProcessRenderer, AppTheme, Column, EventData, FilterItem, FilteredState, ProcData,
    ThreadData,
};
use std::collections::BTreeMap;

// Helper function to create test ProcData
fn create_test_proc_data(tgid: i32, name: &str, cpu_util: f64, num_threads: i64) -> ProcData {
    ProcData {
        tgid,
        process_name: name.to_string(),
        cpu: 0,
        llc: None,
        node: None,
        dsq: None,
        layer_id: None,
        prev_cpu_time: 0,
        current_cpu_time: 0,
        cpu_util_perc: cpu_util,
        state: ProcState::Running,
        cmdline: vec![],
        threads: BTreeMap::new(),
        num_threads,
        data: EventData::new(100),
        max_data_size: 100,
    }
}

// Helper function to create test ThreadData
fn create_test_thread_data(tid: i32, cpu_util: f64) -> ThreadData {
    ThreadData {
        tid,
        tgid: tid,
        thread_name: String::new(),
        cpu: 0,
        llc: None,
        node: None,
        dsq: None,
        layer_id: None,
        prev_cpu_time: 0,
        current_cpu_time: 0,
        cpu_util_perc: cpu_util,
        state: ProcState::Running,
        data: EventData::new(100),
        max_data_size: 100,
        last_waker_pid: None,
        last_waker_comm: None,
    }
}

// Helper function to create test FilteredState
fn create_filtered_state(list: Vec<FilterItem>, selected: usize) -> FilteredState {
    FilteredState {
        list,
        count: 0,
        scroll: 0,
        selected,
    }
}

#[test]
fn test_create_table_header_basic() {
    let theme = AppTheme::Default;
    let col1 = Column {
        header: "PID",
        constraint: Constraint::Length(8),
        value_fn: Box::new(|pid: i32, _data: &ProcData| pid.to_string()),
        visible: true,
    };
    let col2 = Column {
        header: "Name",
        constraint: Constraint::Min(15),
        value_fn: Box::new(|_pid: i32, data: &ProcData| data.process_name.to_string()),
        visible: true,
    };

    let visible_columns = vec![&col1, &col2];
    let (_header, constraints) =
        ProcessRenderer::create_table_header_and_constraints(&visible_columns, &theme);

    // Verify constraints
    assert_eq!(constraints.len(), 2);
    assert_eq!(constraints[0], Constraint::Length(8));
    assert_eq!(constraints[1], Constraint::Min(15));
}

#[test]
fn test_create_table_header_empty() {
    let theme = AppTheme::Default;
    let visible_columns: Vec<&Column<i32, ProcData>> = vec![];
    let (_header, constraints) =
        ProcessRenderer::create_table_header_and_constraints(&visible_columns, &theme);

    assert_eq!(constraints.len(), 0);
}

#[test]
fn test_create_table_header_single_column() {
    let theme = AppTheme::Default;
    let col = Column {
        header: "CPU%",
        constraint: Constraint::Length(6),
        value_fn: Box::new(|_pid: i32, data: &ProcData| format!("{:.1}", data.cpu_util_perc)),
        visible: true,
    };

    let visible_columns = vec![&col];
    let (_header, constraints) =
        ProcessRenderer::create_table_header_and_constraints(&visible_columns, &theme);

    assert_eq!(constraints.len(), 1);
    assert_eq!(constraints[0], Constraint::Length(6));
}

#[test]
fn test_create_table_header_multiple_columns() {
    let theme = AppTheme::Default;
    let columns: Vec<Column<i32, ProcData>> = vec![
        Column {
            header: "PID",
            constraint: Constraint::Length(8),
            value_fn: Box::new(|pid, _| pid.to_string()),
            visible: true,
        },
        Column {
            header: "Name",
            constraint: Constraint::Min(15),
            value_fn: Box::new(|_, data| data.process_name.to_string()),
            visible: true,
        },
        Column {
            header: "CPU%",
            constraint: Constraint::Length(6),
            value_fn: Box::new(|_, data| format!("{:.1}", data.cpu_util_perc)),
            visible: true,
        },
        Column {
            header: "Threads",
            constraint: Constraint::Length(8),
            value_fn: Box::new(|_, data| data.num_threads.to_string()),
            visible: true,
        },
    ];

    let visible_columns: Vec<&Column<i32, ProcData>> = columns.iter().collect();
    let (_header, constraints) =
        ProcessRenderer::create_table_header_and_constraints(&visible_columns, &theme);

    assert_eq!(constraints.len(), 4);
    assert_eq!(constraints[0], Constraint::Length(8));
    assert_eq!(constraints[1], Constraint::Min(15));
    assert_eq!(constraints[2], Constraint::Length(6));
    assert_eq!(constraints[3], Constraint::Length(8));
}

// Tests for actual rendering functions

#[test]
fn test_render_process_table_empty_data() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let proc_data: BTreeMap<i32, ProcData> = BTreeMap::new();

    let columns: Vec<Column<i32, ProcData>> = vec![Column {
        header: "PID",
        constraint: Constraint::Length(8),
        value_fn: Box::new(|pid, _| pid.to_string()),
        visible: true,
    }];
    let visible_columns: Vec<&Column<i32, ProcData>> = columns.iter().collect();

    let filtered_state = create_filtered_state(vec![], 0);

    let theme = AppTheme::Default;
    let mut events_list_size = 0;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = ProcessRenderer::render_process_table(
                frame,
                area,
                &proc_data,
                visible_columns,
                &filtered_state,
                false,
                "",
                0,
                100,
                false,
                &theme,
                events_list_size,
            );

            assert!(result.is_ok());
            let (selected_pid, new_size) = result.unwrap();
            assert_eq!(selected_pid, None);
            events_list_size = new_size;
        })
        .unwrap();

    // Verify events_list_size was calculated
    assert!(events_list_size > 0);
}

#[test]
fn test_render_process_table_with_data() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mut proc_data: BTreeMap<i32, ProcData> = BTreeMap::new();

    // Create sample process data
    let proc1 = create_test_proc_data(1234, "test_process", 25.5, 4);
    proc_data.insert(1234, proc1);

    let proc2 = create_test_proc_data(5678, "another_proc", 10.2, 2);
    proc_data.insert(5678, proc2);

    let columns: Vec<Column<i32, ProcData>> = vec![
        Column {
            header: "PID",
            constraint: Constraint::Length(8),
            value_fn: Box::new(|pid, _| pid.to_string()),
            visible: true,
        },
        Column {
            header: "Name",
            constraint: Constraint::Min(15),
            value_fn: Box::new(|_, data| data.process_name.to_string()),
            visible: true,
        },
    ];
    let visible_columns: Vec<&Column<i32, ProcData>> = columns.iter().collect();

    let filtered_state =
        create_filtered_state(vec![FilterItem::Int(1234), FilterItem::Int(5678)], 0);

    let theme = AppTheme::Default;
    let events_list_size = 0;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = ProcessRenderer::render_process_table(
                frame,
                area,
                &proc_data,
                visible_columns,
                &filtered_state,
                false,
                "",
                100,
                100,
                true,
                &theme,
                events_list_size,
            );

            assert!(result.is_ok());
            let (selected_pid, _) = result.unwrap();
            // First process should be selected (highest CPU usage)
            assert_eq!(selected_pid, Some(1234));
        })
        .unwrap();
}

#[test]
fn test_render_process_table_with_filtering() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mut proc_data: BTreeMap<i32, ProcData> = BTreeMap::new();

    let proc1 = create_test_proc_data(1234, "test_process", 0.0, 1);
    proc_data.insert(1234, proc1);

    let columns: Vec<Column<i32, ProcData>> = vec![Column {
        header: "PID",
        constraint: Constraint::Length(8),
        value_fn: Box::new(|pid, _| pid.to_string()),
        visible: true,
    }];
    let visible_columns: Vec<&Column<i32, ProcData>> = columns.iter().collect();

    let filtered_state = create_filtered_state(vec![FilterItem::Int(1234)], 0);

    let theme = AppTheme::Default;
    let events_list_size = 0;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = ProcessRenderer::render_process_table(
                frame,
                area,
                &proc_data,
                visible_columns,
                &filtered_state,
                true, // filtering active
                "test",
                100,
                100,
                false,
                &theme,
                events_list_size,
            );

            assert!(result.is_ok());
        })
        .unwrap();
}

#[test]
fn test_render_thread_table_basic() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

    let mut proc_data = create_test_proc_data(1234, "test_process", 0.0, 2);

    // Add thread data
    let thread1 = create_test_thread_data(1234, 15.5);
    proc_data.threads.insert(1234, thread1);

    let thread2 = create_test_thread_data(1235, 10.2);
    proc_data.threads.insert(1235, thread2);

    let columns: Vec<Column<i32, ThreadData>> = vec![Column {
        header: "TID",
        constraint: Constraint::Length(8),
        value_fn: Box::new(|tid, _| tid.to_string()),
        visible: true,
    }];
    let visible_columns: Vec<&Column<i32, ThreadData>> = columns.iter().collect();

    let filtered_state =
        create_filtered_state(vec![FilterItem::Int(1234), FilterItem::Int(1235)], 0);

    let theme = AppTheme::Default;
    let events_list_size = 0;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = ProcessRenderer::render_thread_table(
                frame,
                area,
                1234,
                &proc_data,
                visible_columns,
                &filtered_state,
                false,
                "",
                100,
                100,
                false,
                &theme,
                events_list_size,
            );

            assert!(result.is_ok());
            let new_size = result.unwrap();
            assert!(new_size > 0);
        })
        .unwrap();
}

#[test]
fn test_render_thread_table_sorted_by_cpu() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

    let mut proc_data = create_test_proc_data(1234, "test_process", 0.0, 3);

    // Add threads with different CPU usage (unsorted)
    let thread1 = create_test_thread_data(1234, 10.0);
    proc_data.threads.insert(1234, thread1);

    let thread2 = create_test_thread_data(1235, 30.0); // Highest
    proc_data.threads.insert(1235, thread2);

    let thread3 = create_test_thread_data(1236, 20.0);
    proc_data.threads.insert(1236, thread3);

    let columns: Vec<Column<i32, ThreadData>> = vec![
        Column {
            header: "TID",
            constraint: Constraint::Length(8),
            value_fn: Box::new(|tid, _| tid.to_string()),
            visible: true,
        },
        Column {
            header: "CPU%",
            constraint: Constraint::Length(8),
            value_fn: Box::new(|_, data| format!("{:.1}", data.cpu_util_perc)),
            visible: true,
        },
    ];
    let visible_columns: Vec<&Column<i32, ThreadData>> = columns.iter().collect();

    let filtered_state = create_filtered_state(
        vec![
            FilterItem::Int(1234),
            FilterItem::Int(1235),
            FilterItem::Int(1236),
        ],
        0,
    );

    let theme = AppTheme::Default;
    let events_list_size = 0;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = ProcessRenderer::render_thread_table(
                frame,
                area,
                1234,
                &proc_data,
                visible_columns,
                &filtered_state,
                false,
                "",
                100,
                100,
                false,
                &theme,
                events_list_size,
            );

            assert!(result.is_ok());
            // The rendering should sort threads by CPU% (descending)
            // We can't easily verify the order without parsing the rendered output,
            // but we can verify it doesn't panic
        })
        .unwrap();
}

#[test]
fn test_render_process_table_selection() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mut proc_data: BTreeMap<i32, ProcData> = BTreeMap::new();

    let proc1 = create_test_proc_data(100, "proc1", 50.0, 1);
    proc_data.insert(100, proc1);

    let proc2 = create_test_proc_data(200, "proc2", 30.0, 1);
    proc_data.insert(200, proc2);

    let columns: Vec<Column<i32, ProcData>> = vec![Column {
        header: "PID",
        constraint: Constraint::Length(8),
        value_fn: Box::new(|pid, _| pid.to_string()),
        visible: true,
    }];
    let visible_columns: Vec<&Column<i32, ProcData>> = columns.iter().collect();

    // Test selection at index 1 (second process after sorting)
    let filtered_state = create_filtered_state(vec![FilterItem::Int(100), FilterItem::Int(200)], 1);

    let theme = AppTheme::Default;
    let events_list_size = 0;

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = ProcessRenderer::render_process_table(
                frame,
                area,
                &proc_data,
                visible_columns,
                &filtered_state,
                false,
                "",
                100,
                100,
                false,
                &theme,
                events_list_size,
            );

            assert!(result.is_ok());
            let (selected_pid, _) = result.unwrap();
            // After sorting by CPU (descending), second item should be PID 200
            assert_eq!(selected_pid, Some(200));
        })
        .unwrap();
}
