// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::network_stats::{InterfaceStats, NetworkStatSnapshot};
use crate::util::{format_bits, format_bytes, sanitize_nbsp};
use crate::{Action, AppState, AppTheme, KeyMap};
use anyhow::Result;
use num_format::{SystemLocale, ToFormattedString};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::prelude::Stylize;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Block, BorderType, Cell, Chart, Dataset, Paragraph, Row, Table};
use ratatui::Frame;

/// Renderer for network views
pub struct NetworkRenderer;

impl NetworkRenderer {
    /// Renders the full network view (AppState::Network)
    pub fn render_network_view(
        frame: &mut Frame,
        network_stats: &NetworkStatSnapshot,
        tick_rate_ms: usize,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Result<()> {
        let area = frame.area();
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);

        // Create a table for the network interfaces
        let header = Row::new(vec![
            Cell::from("Interface"),
            Cell::from("RX Bits"),
            Cell::from("TX Bits"),
            Cell::from("RX Packets"),
            Cell::from("TX Packets"),
            Cell::from("RX Errors"),
            Cell::from("TX Errors"),
        ])
        .height(1)
        .style(theme.text_color())
        .bold()
        .underlined();

        let constraints = vec![
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
        ];

        let mut interfaces: Vec<(&String, &InterfaceStats)> =
            network_stats.interfaces.iter().collect();
        interfaces.sort_by(|a, b| a.0.cmp(b.0));

        // Get totals for summary row
        let total_delta_recv_bytes = network_stats.get_total_delta_recv_bytes();
        let total_delta_sent_bytes = network_stats.get_total_delta_sent_bytes();
        let total_delta_recv_packets = network_stats.get_total_delta_recv_packets();
        let total_delta_sent_packets = network_stats.get_total_delta_sent_packets();
        let total_delta_recv_errs = network_stats.get_total_delta_recv_errs();
        let total_delta_sent_errs = network_stats.get_total_delta_sent_errs();

        let mut rows: Vec<Row> = interfaces
            .iter()
            .map(|(interface, _)| {
                let delta_recv_bytes = network_stats.get_delta_recv_bytes(interface);
                let delta_sent_bytes = network_stats.get_delta_sent_bytes(interface);
                let delta_recv_packets = network_stats.get_delta_recv_packets(interface);
                let delta_sent_packets = network_stats.get_delta_sent_packets(interface);
                let delta_recv_errs = network_stats.get_delta_recv_errs(interface);
                let delta_sent_errs = network_stats.get_delta_sent_errs(interface);

                Row::new(vec![
                    Cell::from(interface.to_string()),
                    Cell::from(format_bits(delta_recv_bytes) + "/s"),
                    Cell::from(format_bits(delta_sent_bytes) + "/s"),
                    Cell::from(if localize {
                        sanitize_nbsp(delta_recv_packets.to_formatted_string(locale)) + "/s"
                    } else {
                        format!("{delta_recv_packets}/s")
                    }),
                    Cell::from(if localize {
                        sanitize_nbsp(delta_sent_packets.to_formatted_string(locale)) + "/s"
                    } else {
                        format!("{delta_sent_packets}/s")
                    }),
                    Cell::from(if localize {
                        sanitize_nbsp(delta_recv_errs.to_formatted_string(locale)) + "/s"
                    } else {
                        format!("{delta_recv_errs}/s")
                    }),
                    Cell::from(if localize {
                        sanitize_nbsp(delta_sent_errs.to_formatted_string(locale)) + "/s"
                    } else {
                        format!("{delta_sent_errs}/s")
                    }),
                ])
                .height(1)
                .style(theme.text_color())
            })
            .collect();

        // Add summary row at the bottom
        rows.push(
            Row::new(vec![
                Cell::from("TOTAL").style(Style::default().fg(theme.text_important_color()).bold()),
                Cell::from(format_bits(total_delta_recv_bytes) + "/s")
                    .style(Style::default().fg(theme.text_important_color())),
                Cell::from(format_bits(total_delta_sent_bytes) + "/s")
                    .style(Style::default().fg(theme.text_important_color())),
                Cell::from(if localize {
                    sanitize_nbsp(total_delta_recv_packets.to_formatted_string(locale)) + "/s"
                } else {
                    format!("{total_delta_recv_packets}/s")
                })
                .style(Style::default().fg(theme.text_important_color())),
                Cell::from(if localize {
                    sanitize_nbsp(total_delta_sent_packets.to_formatted_string(locale)) + "/s"
                } else {
                    format!("{total_delta_sent_packets}/s")
                })
                .style(Style::default().fg(theme.text_important_color())),
                Cell::from(if localize {
                    sanitize_nbsp(total_delta_recv_errs.to_formatted_string(locale)) + "/s"
                } else {
                    format!("{total_delta_recv_errs}/s")
                })
                .style(Style::default().fg(if total_delta_recv_errs > 0 {
                    Color::Red
                } else {
                    theme.text_important_color()
                })),
                Cell::from(if localize {
                    sanitize_nbsp(total_delta_sent_errs.to_formatted_string(locale)) + "/s"
                } else {
                    format!("{total_delta_sent_errs}/s")
                })
                .style(Style::default().fg(if total_delta_sent_errs > 0 {
                    Color::Red
                } else {
                    theme.text_important_color()
                })),
            ])
            .height(1),
        );

        let block = Block::bordered()
            .title_top(
                Line::from("Network Interfaces")
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

        let table = Table::new(rows, constraints).header(header).block(block);

        // Render the network interfaces table with integrated summary
        frame.render_widget(table, left);

        // Render network traffic charts on the right side
        Self::render_network_charts(frame, right, network_stats, localize, locale, theme)?;

        Ok(())
    }

    /// Renders network summary for default view
    pub fn render_network_summary(
        frame: &mut Frame,
        area: Rect,
        network_stats: &NetworkStatSnapshot,
        keymap: &KeyMap,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Result<()> {
        // Create a table for the network interfaces
        let header = Row::new(vec![
            Cell::from("Interface"),
            Cell::from("RX Bytes"),
            Cell::from("TX Bytes"),
            Cell::from("RX Packets"),
            Cell::from("TX Packets"),
        ])
        .height(1)
        .style(theme.text_color())
        .bold()
        .underlined();

        let constraints = vec![
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ];

        let mut interfaces: Vec<(&String, &InterfaceStats)> =
            network_stats.interfaces.iter().collect();
        interfaces.sort_by(|a, b| b.1.recv_bytes.cmp(&a.1.recv_bytes));

        // Limit to top 5 interfaces by received bytes
        let top_interfaces = interfaces.into_iter().take(5);

        let rows = top_interfaces.map(|(interface, _)| {
            let delta_recv_bytes = network_stats.get_delta_recv_bytes(interface);
            let delta_sent_bytes = network_stats.get_delta_sent_bytes(interface);
            let delta_recv_packets = network_stats.get_delta_recv_packets(interface);
            let delta_sent_packets = network_stats.get_delta_sent_packets(interface);

            Row::new(vec![
                Cell::from(interface.to_string()),
                Cell::from(format_bytes(delta_recv_bytes) + "/s"),
                Cell::from(format_bytes(delta_sent_bytes) + "/s"),
                Cell::from(if localize {
                    sanitize_nbsp(delta_recv_packets.to_formatted_string(locale)) + "/s"
                } else {
                    format!("{delta_recv_packets}/s")
                }),
                Cell::from(if localize {
                    sanitize_nbsp(delta_sent_packets.to_formatted_string(locale)) + "/s"
                } else {
                    format!("{delta_sent_packets}/s")
                }),
            ])
            .height(1)
            .style(theme.text_color())
        });

        let block = Block::bordered()
            .title_top({
                let network_key = keymap.action_keys_string(Action::SetState(AppState::Network));

                if network_key == "N" || network_key == "n" {
                    let key_char = network_key.clone();
                    Line::from(vec![
                        Span::styled(key_char, theme.title_style().add_modifier(Modifier::BOLD)),
                        Span::styled("etwork", theme.text_color()),
                    ])
                    .style(theme.title_style())
                    .centered()
                } else {
                    Line::from(format!("Network (press {network_key} for full view)"))
                        .style(theme.title_style())
                        .centered()
                }
            })
            .border_type(BorderType::Rounded)
            .style(theme.border_style());

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_widget(table, area);

        Ok(())
    }

    /// Renders network traffic charts showing historical data per interface.
    fn render_network_charts(
        frame: &mut Frame,
        area: Rect,
        network_stats: &NetworkStatSnapshot,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Result<()> {
        // Get the top 3 most active interfaces by total bytes
        let mut interface_activity: Vec<(String, u64)> = network_stats
            .interfaces
            .iter()
            .map(|(name, stats)| (name.clone(), stats.recv_bytes + stats.sent_bytes))
            .collect();
        interface_activity.sort_by(|a, b| b.1.cmp(&a.1));
        let top_interfaces: Vec<String> = interface_activity
            .into_iter()
            .take(3)
            .map(|(name, _)| name)
            .collect();

        if top_interfaces.is_empty() {
            let block = Block::bordered()
                .title_top(
                    Line::from("Network Traffic History")
                        .style(theme.title_style())
                        .centered(),
                )
                .border_type(BorderType::Rounded)
                .style(theme.border_style());

            let paragraph = Paragraph::new("No network interfaces detected")
                .block(block)
                .alignment(Alignment::Center);

            frame.render_widget(paragraph, area);
            return Ok(());
        }

        // Create vertical layout for each interface (each interface gets 2 charts: bytes + packets)
        let interface_count = top_interfaces.len();
        let constraints: Vec<Constraint> = (0..interface_count)
            .map(|_| Constraint::Ratio(1, interface_count as u32))
            .collect();

        let interface_areas = Layout::vertical(constraints).split(area);

        // Render charts for each interface
        for (i, interface) in top_interfaces.iter().enumerate() {
            if i < interface_areas.len() {
                Self::render_interface_charts(
                    frame,
                    interface_areas[i],
                    interface,
                    network_stats,
                    localize,
                    locale,
                    theme,
                )?;
            }
        }

        Ok(())
    }

    /// Renders charts for a single interface (bytes and packets stacked vertically).
    fn render_interface_charts(
        frame: &mut Frame,
        area: Rect,
        interface: &str,
        network_stats: &NetworkStatSnapshot,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Result<()> {
        // Split area vertically: bytes chart on top, packets chart on bottom
        let [bytes_area, packets_area] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

        // Render bytes chart for this interface
        Self::render_interface_bytes_chart(frame, bytes_area, interface, network_stats, theme)?;

        // Render packets chart for this interface
        Self::render_interface_packets_chart(
            frame,
            packets_area,
            interface,
            network_stats,
            localize,
            locale,
            theme,
        )?;

        Ok(())
    }

    /// Renders the bytes chart for a single interface.
    fn render_interface_bytes_chart(
        frame: &mut Frame,
        area: Rect,
        interface: &str,
        network_stats: &NetworkStatSnapshot,
        theme: &AppTheme,
    ) -> Result<()> {
        // Split area to make room for summary statistics at the bottom
        let [chart_area, stats_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(area);

        let rx_history = network_stats.get_historical_data(interface, "recv_bytes");
        let tx_history = network_stats.get_historical_data(interface, "sent_bytes");

        // Convert to (x, y) coordinates with RX as negative, TX as positive
        let rx_data: Vec<(f64, f64)> = rx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, -(y as f64)))
            .collect();

        let tx_data: Vec<(f64, f64)> = tx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, y as f64))
            .collect();

        // Collect all values for scaling
        let mut all_values = Vec::new();
        all_values.extend(rx_history.iter().map(|&v| v as f64));
        all_values.extend(tx_history.iter().map(|&v| v as f64));

        let marker = theme.plot_marker();
        let tx_color = theme.positive_value_color();
        let rx_color = theme.negative_value_color();

        // Create datasets
        let datasets = vec![
            Dataset::default()
                .name(format!("{interface} RX"))
                .marker(marker)
                .style(Style::default().fg(rx_color))
                .data(&rx_data),
            Dataset::default()
                .name(format!("{interface} TX"))
                .marker(marker)
                .style(Style::default().fg(tx_color))
                .data(&tx_data),
        ];

        let max_value = all_values.iter().fold(0.0f64, |a, &b| a.max(b)).max(1000.0); // Minimum 1000 bytes/s for reasonable scaling
        let history_len = network_stats.max_history_size as f64;

        let chart = Chart::new(datasets)
            .block(
                Block::bordered()
                    .title_top(
                        Line::from(format!("{interface} - Bits/s"))
                            .style(theme.title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(theme.border_style()),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(theme.text_color())
                    .bounds([0.0, history_len]),
            )
            .y_axis(
                Axis::default()
                    .title("Bits/s")
                    .style(theme.text_color())
                    .bounds([-max_value, max_value])
                    .labels(vec![
                        Span::styled(
                            format!("RX {}", format_bits(max_value as u64)),
                            Style::default().fg(theme.negative_value_color()),
                        ),
                        Span::styled("0", theme.text_color()),
                        Span::styled(
                            format!("TX {}", format_bits(max_value as u64)),
                            Style::default().fg(theme.positive_value_color()),
                        ),
                    ]),
            );

        frame.render_widget(chart, chart_area);

        // Calculate and render summary statistics
        Self::render_bytes_summary_stats(frame, stats_area, &rx_history, &tx_history, theme)?;

        Ok(())
    }

    /// Renders summary statistics for bytes data.
    fn render_bytes_summary_stats(
        frame: &mut Frame,
        area: Rect,
        rx_history: &[u64],
        tx_history: &[u64],
        theme: &AppTheme,
    ) -> Result<()> {
        if rx_history.is_empty() && tx_history.is_empty() {
            return Ok(());
        }

        // Calculate RX statistics
        let (rx_min, rx_max, rx_avg) = if rx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *rx_history.iter().min().unwrap_or(&0);
            let max = *rx_history.iter().max().unwrap_or(&0);
            let avg = rx_history.iter().sum::<u64>() / rx_history.len() as u64;
            (min, max, avg)
        };

        // Calculate TX statistics
        let (tx_min, tx_max, tx_avg) = if tx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *tx_history.iter().min().unwrap_or(&0);
            let max = *tx_history.iter().max().unwrap_or(&0);
            let avg = tx_history.iter().sum::<u64>() / tx_history.len() as u64;
            (min, max, avg)
        };

        let stats_text = vec![Line::from(vec![
            Span::raw("Min: "),
            Span::styled(
                format_bits(rx_min),
                Style::default().fg(theme.negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                format_bits(tx_min),
                Style::default().fg(theme.positive_value_color()),
            ),
            Span::raw(" Max: "),
            Span::styled(
                format_bits(rx_max),
                Style::default().fg(theme.negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                format_bits(tx_max),
                Style::default().fg(theme.positive_value_color()),
            ),
            Span::raw(" Avg: "),
            Span::styled(
                format_bits(rx_avg),
                Style::default().fg(theme.negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                format_bits(tx_avg),
                Style::default().fg(theme.positive_value_color()),
            ),
        ])];

        let stats_paragraph = Paragraph::new(stats_text).style(theme.text_color());

        frame.render_widget(stats_paragraph, area);
        Ok(())
    }

    /// Renders the packets chart for a single interface.
    fn render_interface_packets_chart(
        frame: &mut Frame,
        area: Rect,
        interface: &str,
        network_stats: &NetworkStatSnapshot,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Result<()> {
        // Split area to make room for summary statistics at the bottom
        let [chart_area, stats_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(area);

        let rx_history = network_stats.get_historical_data(interface, "recv_packets");
        let tx_history = network_stats.get_historical_data(interface, "sent_packets");

        // Convert to (x, y) coordinates with RX as negative, TX as positive
        let rx_data: Vec<(f64, f64)> = rx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, -(y as f64)))
            .collect();

        let tx_data: Vec<(f64, f64)> = tx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, y as f64))
            .collect();

        // Collect all values for scaling
        let mut all_values = Vec::new();
        all_values.extend(rx_history.iter().map(|&v| v as f64));
        all_values.extend(tx_history.iter().map(|&v| v as f64));

        let marker = theme.plot_marker();
        let tx_color = theme.positive_value_color();
        let rx_color = theme.negative_value_color();

        // Create datasets
        let datasets = vec![
            Dataset::default()
                .name(format!("{interface} RX"))
                .marker(marker)
                .style(Style::default().fg(rx_color))
                .data(&rx_data),
            Dataset::default()
                .name(format!("{interface} TX"))
                .marker(marker)
                .style(Style::default().fg(tx_color))
                .data(&tx_data),
        ];

        let max_value = all_values.iter().fold(0.0f64, |a, &b| a.max(b)).max(100.0); // Minimum 100 packets/s for reasonable scaling
        let history_len = network_stats.max_history_size as f64;

        let chart = Chart::new(datasets)
            .block(
                Block::bordered()
                    .title_top(
                        Line::from(format!("{interface} - Packets/s"))
                            .style(theme.title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(theme.border_style()),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(theme.text_color())
                    .bounds([0.0, history_len]),
            )
            .y_axis(
                Axis::default()
                    .title("Packets/s")
                    .style(theme.text_color())
                    .bounds([-max_value, max_value])
                    .labels(vec![
                        Span::styled(
                            if localize {
                                format!(
                                    "RX {}",
                                    sanitize_nbsp((max_value as u64).to_formatted_string(locale))
                                )
                            } else {
                                format!("RX {}", max_value as u64)
                            },
                            Style::default().fg(theme.negative_value_color()),
                        ),
                        Span::styled("0", theme.text_color()),
                        Span::styled(
                            if localize {
                                format!(
                                    "TX {}",
                                    sanitize_nbsp((max_value as u64).to_formatted_string(locale))
                                )
                            } else {
                                format!("TX {}", max_value as u64)
                            },
                            Style::default().fg(theme.positive_value_color()),
                        ),
                    ]),
            );

        frame.render_widget(chart, chart_area);

        // Calculate and render summary statistics
        Self::render_packets_summary_stats(
            frame,
            stats_area,
            &rx_history,
            &tx_history,
            localize,
            locale,
            theme,
        )?;

        Ok(())
    }

    /// Renders summary statistics for packets data.
    fn render_packets_summary_stats(
        frame: &mut Frame,
        area: Rect,
        rx_history: &[u64],
        tx_history: &[u64],
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Result<()> {
        if rx_history.is_empty() && tx_history.is_empty() {
            return Ok(());
        }

        // Calculate RX statistics
        let (rx_min, rx_max, rx_avg) = if rx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *rx_history.iter().min().unwrap_or(&0);
            let max = *rx_history.iter().max().unwrap_or(&0);
            let avg = rx_history.iter().sum::<u64>() / rx_history.len() as u64;
            (min, max, avg)
        };

        // Calculate TX statistics
        let (tx_min, tx_max, tx_avg) = if tx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *tx_history.iter().min().unwrap_or(&0);
            let max = *tx_history.iter().max().unwrap_or(&0);
            let avg = tx_history.iter().sum::<u64>() / tx_history.len() as u64;
            (min, max, avg)
        };

        let rx_min_str = if localize {
            sanitize_nbsp(rx_min.to_formatted_string(locale))
        } else {
            rx_min.to_string()
        };
        let rx_max_str = if localize {
            sanitize_nbsp(rx_max.to_formatted_string(locale))
        } else {
            rx_max.to_string()
        };
        let rx_avg_str = if localize {
            sanitize_nbsp(rx_avg.to_formatted_string(locale))
        } else {
            rx_avg.to_string()
        };
        let tx_min_str = if localize {
            sanitize_nbsp(tx_min.to_formatted_string(locale))
        } else {
            tx_min.to_string()
        };
        let tx_max_str = if localize {
            sanitize_nbsp(tx_max.to_formatted_string(locale))
        } else {
            tx_max.to_string()
        };
        let tx_avg_str = if localize {
            sanitize_nbsp(tx_avg.to_formatted_string(locale))
        } else {
            tx_avg.to_string()
        };

        let stats_text = vec![Line::from(vec![
            Span::raw("Min: "),
            Span::styled(
                rx_min_str,
                Style::default().fg(theme.negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                tx_min_str,
                Style::default().fg(theme.positive_value_color()),
            ),
            Span::raw(" Max: "),
            Span::styled(
                rx_max_str,
                Style::default().fg(theme.negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                tx_max_str,
                Style::default().fg(theme.positive_value_color()),
            ),
            Span::raw(" Avg: "),
            Span::styled(
                rx_avg_str,
                Style::default().fg(theme.negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                tx_avg_str,
                Style::default().fg(theme.positive_value_color()),
            ),
        ])];

        let stats_paragraph = Paragraph::new(stats_text).style(theme.text_color());

        frame.render_widget(stats_paragraph, area);
        Ok(())
    }
}
