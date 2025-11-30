// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::columns::{
    get_memory_detail_columns, get_memory_detail_metrics, get_memory_rates_columns,
    get_memory_summary_columns, get_pagefault_summary_columns, get_slab_columns,
    get_swap_summary_columns, Column,
};
use crate::util::format_bytes;
use crate::{Action, AppState, AppTheme, KeyMap, MemStatSnapshot};
use anyhow::Result;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::symbols::line::THICK;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, LineGauge, Row, Table};
use ratatui::{layout::Rect, Frame};

/// Renderer for memory views
pub struct MemoryRenderer;

impl MemoryRenderer {
    /// Renders the full memory view (AppState::Memory)
    pub fn render_memory_view(
        frame: &mut Frame,
        mem_info: &MemStatSnapshot,
        _sample_rate: u32,
        tick_rate_ms: usize,
        theme: &AppTheme,
    ) -> Result<()> {
        let area = frame.area();
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);

        // Get the columns and metrics for the detailed memory view
        let memory_columns = get_memory_detail_columns();
        let memory_metrics = get_memory_detail_metrics();

        // Create header cells from column headers
        let header_cells: Vec<Cell> = memory_columns
            .iter()
            .map(|col| Cell::from(col.header).style(theme.title_style()))
            .collect();

        // Create constraints from column constraints
        let constraints: Vec<Constraint> =
            memory_columns.iter().map(|col| col.constraint).collect();

        // Create rows for memory metrics
        let rows = memory_metrics
            .iter()
            .map(|metric| {
                let cells = memory_columns
                    .iter()
                    .map(|col| {
                        Cell::from((col.value_fn)(metric, mem_info))
                            .style(theme.text_important_color())
                    })
                    .collect::<Vec<Cell>>();
                Row::new(cells)
            })
            .collect::<Vec<Row>>();

        let block = Block::bordered()
            .title_top(
                Line::from("Memory Statistics")
                    .style(theme.title_style())
                    .centered(),
            )
            .title_top(
                Line::from(format!("{}ms", tick_rate_ms))
                    .style(theme.text_important_color())
                    .right_aligned(),
            )
            .border_type(BorderType::Rounded)
            .style(theme.border_style());

        let table = Table::new(rows, constraints)
            .header(Row::new(header_cells).style(theme.title_style()))
            .block(block);

        frame.render_widget(table, left);

        // Create memory usage gauges and additional stats for the right side
        let [right_top, right_middle, right_bottom] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .areas(right);

        // Split the top section into two columns for memory and swap gauges
        let [gauge_left, gauge_right] =
            Layout::horizontal([Constraint::Fill(1); 2]).areas(right_top);

        // Memory usage gauge
        let mem_used_percent =
            100.0 - (mem_info.available_kb as f64 / mem_info.total_kb as f64) * 100.0;
        let mem_used_kb = mem_info.total_kb - mem_info.available_kb;

        // Calculate gradient color based on memory usage percentage
        let mem_gradient_color = theme.gradient_5(
            mem_used_percent,
            20.0, // very low threshold (0-20%)
            40.0, // low threshold (20-40%)
            60.0, // high threshold (40-60%)
            80.0, // very high threshold (60-80%)
            false,
        );

        let mem_gauge = LineGauge::default()
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Memory Usage")
                            .style(theme.title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(theme.border_style()),
            )
            .line_set(THICK)
            .filled_style(mem_gradient_color)
            .ratio(mem_used_percent / 100.0)
            .label(format!(
                "{}/{}",
                format_bytes(mem_used_kb),
                format_bytes(mem_info.total_kb),
            ));

        frame.render_widget(mem_gauge, gauge_left);

        // Swap usage gauge
        let swap_used_percent = if mem_info.swap_total_kb > 0 {
            100.0 - (mem_info.swap_free_kb as f64 / mem_info.swap_total_kb as f64) * 100.0
        } else {
            0.0
        };
        let swap_used_kb = mem_info.swap_total_kb - mem_info.swap_free_kb;

        // Calculate gradient color based on swap usage percentage
        let swap_gradient_color = theme.gradient_5(
            swap_used_percent,
            5.0,  // very low threshold (0-5%) - any swap usage is concerning
            15.0, // low threshold (5-15%)
            35.0, // high threshold (15-35%)
            60.0, // very high threshold (35-60%)
            false,
        );

        let swap_gauge = LineGauge::default()
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Swap Usage")
                            .style(theme.title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(theme.border_style()),
            )
            .line_set(THICK)
            .filled_style(swap_gradient_color)
            .ratio(swap_used_percent / 100.0)
            .label(format!(
                "{}/{}",
                format_bytes(swap_used_kb),
                format_bytes(mem_info.swap_total_kb),
            ));

        frame.render_widget(swap_gauge, gauge_right);

        // Memory rates (pagefaults, swap I/O)
        let memory_rates_columns = get_memory_rates_columns();
        Self::render_memory_table(
            frame,
            right_middle,
            Some("Memory Activity Rates"),
            &memory_rates_columns,
            mem_info,
            true,
            theme,
        )?;

        // Slab information section
        let slab_columns = get_slab_columns();
        Self::render_memory_table(
            frame,
            right_bottom,
            Some("Slab Information"),
            &slab_columns,
            mem_info,
            true,
            theme,
        )?;

        Ok(())
    }

    /// Renders memory summary for default view
    pub fn render_memory_summary(
        frame: &mut Frame,
        area: Rect,
        mem_info: &MemStatSnapshot,
        keymap: &KeyMap,
        theme: &AppTheme,
    ) -> Result<()> {
        let memory_key = keymap.action_keys_string(Action::SetState(AppState::Memory));

        // Check if the memory key is bound
        if memory_key.is_empty() {
            panic!("Memory key is not bound");
        }

        // Create a single block for all memory tables with keybinding in title
        let title = if memory_key == "m" || memory_key == "M" {
            Line::from(vec![
                Span::styled(
                    &memory_key,
                    theme
                        .title_style()
                        .add_modifier(ratatui::style::Modifier::BOLD),
                ),
                Span::styled("emory Statistics", theme.text_color()),
            ])
        } else {
            Line::from(vec![
                Span::styled("Memory Statistics (", theme.text_color()),
                Span::styled(&memory_key, theme.title_style()),
                Span::styled(")", theme.text_color()),
            ])
        };

        let block = Block::bordered()
            .title(title)
            .title_alignment(Alignment::Center)
            .border_type(BorderType::Rounded)
            .style(theme.border_style());

        // Get the inner area of the block
        let inner_area = block.inner(area);

        // Split the inner area into three sections for different memory tables
        // Use proportional heights based on content - memory needs more space than swap and page faults
        let [memory_area, swap_area, pagefault_area] = Layout::vertical([
            Constraint::Length(3), // Memory table (header + 1 row + padding)
            Constraint::Length(3), // Swap table (header + 1 row + padding)
            Constraint::Length(3), // Page faults table (header + 1 row + padding)
        ])
        .margin(0) // Remove margin between tables
        .areas(inner_area);

        // Get the columns for memory, swap, and pagefault stats
        let memory_columns = get_memory_summary_columns();
        let swap_columns = get_swap_summary_columns();
        let pagefault_columns = get_pagefault_summary_columns();

        // Render the block first
        frame.render_widget(block, area);

        // Render memory statistics table (without border)
        Self::render_memory_table(
            frame,
            memory_area,
            None,
            &memory_columns,
            mem_info,
            false,
            theme,
        )?;

        // Render swap statistics table (without border)
        Self::render_memory_table(
            frame,
            swap_area,
            None,
            &swap_columns,
            mem_info,
            false,
            theme,
        )?;

        // Render page fault statistics table (without border)
        Self::render_memory_table(
            frame,
            pagefault_area,
            None,
            &pagefault_columns,
            mem_info,
            false,
            theme,
        )?;

        Ok(())
    }

    /// Renders a memory table with the given columns
    fn render_memory_table(
        frame: &mut Frame,
        area: Rect,
        title: Option<&str>,
        columns: &[Column<(), MemStatSnapshot>],
        mem_stats: &MemStatSnapshot,
        with_border: bool,
        theme: &AppTheme,
    ) -> Result<()> {
        // Create header cells from column headers
        let header_cells: Vec<Cell> = columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| Cell::from(col.header).style(theme.title_style()))
            .collect();

        // Create row data
        let row_cells: Vec<Cell> = columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| {
                let value = (col.value_fn)((), mem_stats);
                Cell::from(value).style(theme.text_color())
            })
            .collect();

        // Get constraints for visible columns
        let constraints: Vec<Constraint> = columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| col.constraint)
            .collect();

        // Create the table with rows and constraints
        let mut table = Table::new(vec![Row::new(row_cells)], constraints)
            .header(Row::new(header_cells))
            .column_spacing(1);

        // Add border and title if requested
        if with_border {
            if let Some(table_title) = title {
                table = table.block(
                    Block::bordered()
                        .title(table_title)
                        .title_alignment(Alignment::Center)
                        .border_type(BorderType::Rounded)
                        .style(theme.border_style()),
                );
            } else {
                table = table.block(
                    Block::bordered()
                        .border_type(BorderType::Rounded)
                        .style(theme.border_style()),
                );
            }
        }

        frame.render_widget(table, area);

        Ok(())
    }
}
