// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::columns::Column;
use crate::{AppTheme, FilteredState, ProcData, ThreadData};
use anyhow::Result;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::prelude::Stylize;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    TableState,
};
use ratatui::Frame;
use std::collections::BTreeMap;

/// Renderer for process and thread tables
pub struct ProcessRenderer;

impl ProcessRenderer {
    /// Creates table header and constraints from visible columns
    pub fn create_table_header_and_constraints<'a, T, D>(
        visible_columns: &'a [&'a Column<T, D>],
        theme: &'a AppTheme,
    ) -> (Row<'a>, Vec<Constraint>) {
        let header = visible_columns
            .iter()
            .map(|col| Cell::from(col.header))
            .collect::<Row>()
            .height(1)
            .style(theme.text_color())
            .bold()
            .underlined();

        let constraints = visible_columns
            .iter()
            .map(|col| col.constraint)
            .collect::<Vec<_>>();

        (header, constraints)
    }

    /// Renders the process table view
    #[allow(clippy::too_many_arguments)]
    pub fn render_process_table(
        frame: &mut Frame,
        area: Rect,
        proc_data: &BTreeMap<i32, ProcData>,
        visible_columns: Vec<&Column<i32, ProcData>>,
        filtered_state: &FilteredState,
        filtering: bool,
        event_input_buffer: &str,
        sample_rate: u32,
        tick_rate_ms: usize,
        render_tick_rate: bool,
        theme: &AppTheme,
        _events_list_size: u16,
    ) -> Result<(Option<i32>, u16)> {
        let [scroll_area, data_area] =
            Layout::horizontal(vec![Constraint::Min(1), Constraint::Percentage(100)]).areas(area);

        // Calculate events list size
        let new_events_list_size = if data_area.height > 0 {
            data_area.height - 1
        } else {
            1
        };

        let (header, constraints) =
            Self::create_table_header_and_constraints(&visible_columns, theme);

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(theme.border_style())
            .title_top(
                Line::from(format!("Processes (total: {})", proc_data.len()))
                    .style(theme.title_style())
                    .centered(),
            )
            .title_top(
                Line::from(vec![
                    Span::styled("f", theme.text_important_color()),
                    Span::styled(
                        if filtering {
                            format!(" {}_", event_input_buffer)
                        } else {
                            "ilter".to_string()
                        },
                        theme.text_color(),
                    ),
                ])
                .left_aligned(),
            )
            .title_top(
                Line::from(format!(
                    "sample rate {}{}",
                    sample_rate,
                    if render_tick_rate {
                        format!(" --- tick rate {}", tick_rate_ms)
                    } else {
                        "".to_string()
                    }
                ))
                .style(theme.text_important_color())
                .right_aligned(),
            );

        let mut filtered_processes: Vec<_> = filtered_state
            .list
            .iter()
            .filter_map(|item| {
                item.as_int()
                    .and_then(|pid| proc_data.get(&pid).map(|data| (pid, data)))
            })
            .collect();
        let selected = filtered_state.selected;

        filtered_processes.sort_unstable_by(|a, b| {
            b.1.cpu_util_perc
                .partial_cmp(&a.1.cpu_util_perc)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.num_threads.cmp(&a.1.num_threads))
        });

        let rows = filtered_processes
            .iter()
            .enumerate()
            .map(|(i, (tgid, data))| {
                visible_columns
                    .iter()
                    .map(|col| Cell::from((col.value_fn)(*tgid, data)))
                    .collect::<Row>()
                    .height(1)
                    .style(if i == selected {
                        theme.text_important_color()
                    } else {
                        theme.text_color()
                    })
            });

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_stateful_widget(
            table,
            data_area,
            &mut TableState::new().with_offset(selected),
        );

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalLeft)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            scroll_area,
            &mut ScrollbarState::new(filtered_processes.len()).position(selected),
        );

        let selected_pid = filtered_processes.get(selected).map(|(tgid, _)| *tgid);
        Ok((selected_pid, new_events_list_size))
    }

    /// Renders the thread table for a selected process
    #[allow(clippy::too_many_arguments)]
    pub fn render_thread_table(
        frame: &mut Frame,
        area: Rect,
        tgid: i32,
        proc_data: &ProcData,
        visible_columns: Vec<&Column<i32, ThreadData>>,
        filtered_state: &FilteredState,
        filtering: bool,
        event_input_buffer: &str,
        sample_rate: u32,
        tick_rate_ms: usize,
        render_tick_rate: bool,
        theme: &AppTheme,
        _events_list_size: u16,
    ) -> Result<u16> {
        let [scroll_area, data_area] =
            Layout::horizontal(vec![Constraint::Min(1), Constraint::Percentage(100)]).areas(area);

        // Calculate events list size
        let new_events_list_size = if data_area.height > 0 {
            data_area.height - 1
        } else {
            1
        };

        let (header, constraints) =
            Self::create_table_header_and_constraints(&visible_columns, theme);

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(theme.border_style())
            .title_top(
                Line::from(format!(
                    "Process: {:.15} [{}] (total threads: {})",
                    proc_data.process_name, tgid, proc_data.num_threads,
                ))
                .style(theme.title_style())
                .centered(),
            )
            .title_top(
                Line::from(vec![
                    Span::styled("f", theme.text_important_color()),
                    Span::styled(
                        if filtering {
                            format!(" {}_", event_input_buffer)
                        } else {
                            "ilter".to_string()
                        },
                        theme.text_color(),
                    ),
                ])
                .left_aligned(),
            )
            .title_top(
                Line::from(if sample_rate > 0 {
                    format!(
                        "sample rate {}{}",
                        sample_rate,
                        if render_tick_rate {
                            format!(" --- tick rate {}", tick_rate_ms)
                        } else {
                            "".to_string()
                        }
                    )
                } else if render_tick_rate {
                    format!("tick rate {}", tick_rate_ms)
                } else {
                    "".to_string()
                })
                .style(theme.text_important_color())
                .right_aligned(),
            );

        let mut filtered_threads: Vec<_> = filtered_state
            .list
            .iter()
            .filter_map(|item| {
                item.as_int()
                    .and_then(|tid| proc_data.threads.get(&tid).map(|data| (tid, data)))
            })
            .collect();
        let selected = filtered_state.selected;

        filtered_threads.sort_unstable_by(|a, b| {
            b.1.cpu_util_perc
                .partial_cmp(&a.1.cpu_util_perc)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let rows = filtered_threads.iter().enumerate().map(|(i, (tid, data))| {
            visible_columns
                .iter()
                .map(|col| Cell::from((col.value_fn)(*tid, data)))
                .collect::<Row>()
                .height(1)
                .style(if i == selected {
                    theme.text_important_color()
                } else {
                    theme.text_color()
                })
        });

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_stateful_widget(
            table,
            data_area,
            &mut TableState::new().with_offset(selected),
        );

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalLeft)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            scroll_area,
            &mut ScrollbarState::new(filtered_threads.len()).position(selected),
        );

        Ok(new_events_list_size)
    }
}
