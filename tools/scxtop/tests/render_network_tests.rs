// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use num_format::SystemLocale;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use scxtop::{
    network_stats::{InterfaceStats, NetworkStatSnapshot},
    render::NetworkRenderer,
    AppTheme, EventData, KeyMap,
};
use std::collections::BTreeMap;

// Helper function to create test NetworkStatSnapshot
fn create_test_network_stats() -> NetworkStatSnapshot {
    let mut interfaces = BTreeMap::new();
    let mut prev_interfaces = BTreeMap::new();

    // Add eth0 with significant traffic
    interfaces.insert(
        "eth0".to_string(),
        InterfaceStats {
            recv_bytes: 1024 * 1024 * 100, // 100 MB
            sent_bytes: 1024 * 1024 * 50,  // 50 MB
            recv_packets: 100000,
            sent_packets: 50000,
            recv_errs: 0,
            sent_errs: 0,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    prev_interfaces.insert(
        "eth0".to_string(),
        InterfaceStats {
            recv_bytes: 1024 * 1024 * 90, // Previous: 90 MB
            sent_bytes: 1024 * 1024 * 45, // Previous: 45 MB
            recv_packets: 90000,
            sent_packets: 45000,
            recv_errs: 0,
            sent_errs: 0,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    // Add lo (loopback) with less traffic
    interfaces.insert(
        "lo".to_string(),
        InterfaceStats {
            recv_bytes: 1024 * 1024 * 10, // 10 MB
            sent_bytes: 1024 * 1024 * 10, // 10 MB
            recv_packets: 10000,
            sent_packets: 10000,
            recv_errs: 0,
            sent_errs: 0,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    prev_interfaces.insert(
        "lo".to_string(),
        InterfaceStats {
            recv_bytes: 1024 * 1024 * 9,
            sent_bytes: 1024 * 1024 * 9,
            recv_packets: 9000,
            sent_packets: 9000,
            recv_errs: 0,
            sent_errs: 0,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    // Add wlan0 with some errors
    interfaces.insert(
        "wlan0".to_string(),
        InterfaceStats {
            recv_bytes: 1024 * 1024 * 20, // 20 MB
            sent_bytes: 1024 * 1024 * 15, // 15 MB
            recv_packets: 20000,
            sent_packets: 15000,
            recv_errs: 5,
            sent_errs: 3,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    prev_interfaces.insert(
        "wlan0".to_string(),
        InterfaceStats {
            recv_bytes: 1024 * 1024 * 18,
            sent_bytes: 1024 * 1024 * 13,
            recv_packets: 18000,
            sent_packets: 13000,
            recv_errs: 3,
            sent_errs: 2,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    let max_history_size = 60;
    let mut historical_data = BTreeMap::new();

    // Add historical data for eth0
    let mut eth0_data = EventData::new(max_history_size);
    for i in 0..max_history_size {
        eth0_data.add_event_data("recv_bytes", 1024 * 1024 * (i as u64 + 10));
        eth0_data.add_event_data("sent_bytes", 1024 * 1024 * (i as u64 + 5));
        eth0_data.add_event_data("recv_packets", 1000 * (i as u64 + 10));
        eth0_data.add_event_data("sent_packets", 500 * (i as u64 + 10));
    }
    historical_data.insert("eth0".to_string(), eth0_data);

    // Add historical data for wlan0
    let mut wlan0_data = EventData::new(max_history_size);
    for i in 0..max_history_size {
        wlan0_data.add_event_data("recv_bytes", 1024 * 512 * (i as u64 + 5));
        wlan0_data.add_event_data("sent_bytes", 1024 * 256 * (i as u64 + 5));
        wlan0_data.add_event_data("recv_packets", 500 * (i as u64 + 5));
        wlan0_data.add_event_data("sent_packets", 250 * (i as u64 + 5));
    }
    historical_data.insert("wlan0".to_string(), wlan0_data);

    NetworkStatSnapshot {
        interfaces,
        prev_interfaces,
        last_update_time: std::time::Instant::now(),
        historical_data,
        max_history_size,
    }
}

#[test]
fn test_render_network_view_basic() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let network_stats = create_test_network_stats();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                1000,  // tick_rate_ms
                false, // localize
                &locale,
                &theme,
            );

            assert!(result.is_ok(), "render_network_view should succeed");
        })
        .unwrap();
}

#[test]
fn test_render_network_view_with_localization() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let network_stats = create_test_network_stats();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                1000,
                true, // localize enabled
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_view with localization should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_view_with_errors() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let mut network_stats = create_test_network_stats();

    // Add interface with high error count
    if let Some(stats) = network_stats.interfaces.get_mut("wlan0") {
        stats.recv_errs = 1000;
        stats.sent_errs = 500;
    }

    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                1000,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_view with errors should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_view_no_interfaces() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let network_stats = NetworkStatSnapshot {
        interfaces: BTreeMap::new(),
        prev_interfaces: BTreeMap::new(),
        last_update_time: std::time::Instant::now(),
        historical_data: BTreeMap::new(),
        max_history_size: 60,
    };
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                1000,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_view with no interfaces should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_summary_basic() {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let network_stats = create_test_network_stats();
    let theme = AppTheme::Default;
    let keymap = KeyMap::default();
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = NetworkRenderer::render_network_summary(
                frame,
                area,
                &network_stats,
                &keymap,
                false,
                &locale,
                &theme,
            );

            assert!(result.is_ok(), "render_network_summary should succeed");
        })
        .unwrap();
}

#[test]
fn test_render_network_summary_with_localization() {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let network_stats = create_test_network_stats();
    let theme = AppTheme::Default;
    let keymap = KeyMap::default();
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = NetworkRenderer::render_network_summary(
                frame,
                area,
                &network_stats,
                &keymap,
                true, // localize enabled
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_summary with localization should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_summary_with_different_themes() {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let network_stats = create_test_network_stats();
    let keymap = KeyMap::default();
    let locale = SystemLocale::default().unwrap();

    for theme in [
        AppTheme::Default,
        AppTheme::MidnightGreen,
        AppTheme::SolarizedDark,
    ] {
        terminal
            .draw(|frame| {
                let area = frame.area();
                let result = NetworkRenderer::render_network_summary(
                    frame,
                    area,
                    &network_stats,
                    &keymap,
                    false,
                    &locale,
                    &theme,
                );

                assert!(
                    result.is_ok(),
                    "render_network_summary with {:?} theme should succeed",
                    theme
                );
            })
            .unwrap();
    }
}

#[test]
fn test_render_network_summary_small_area() {
    // Test rendering in a small terminal
    let mut terminal = Terminal::new(TestBackend::new(50, 15)).unwrap();
    let network_stats = create_test_network_stats();
    let theme = AppTheme::Default;
    let keymap = KeyMap::default();
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = NetworkRenderer::render_network_summary(
                frame,
                area,
                &network_stats,
                &keymap,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_summary in small area should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_view_many_interfaces() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let mut interfaces = BTreeMap::new();
    let mut prev_interfaces = BTreeMap::new();

    // Add 10 interfaces to test rendering with many interfaces
    for i in 0u64..10 {
        let name = format!("eth{}", i);
        interfaces.insert(
            name.clone(),
            InterfaceStats {
                recv_bytes: 1024 * 1024 * (i + 10),
                sent_bytes: 1024 * 1024 * (i + 5),
                recv_packets: 1000 * (i + 10),
                sent_packets: 500 * (i + 10),
                recv_errs: i,
                sent_errs: i,
                recv_drop: 0,
                sent_drop: 0,
            },
        );
        prev_interfaces.insert(
            name,
            InterfaceStats {
                recv_bytes: 1024 * 1024 * (i + 9),
                sent_bytes: 1024 * 1024 * (i + 4),
                recv_packets: 1000 * (i + 9),
                sent_packets: 500 * (i + 9),
                recv_errs: i.saturating_sub(1),
                sent_errs: i.saturating_sub(1),
                recv_drop: 0,
                sent_drop: 0,
            },
        );
    }

    let network_stats = NetworkStatSnapshot {
        interfaces,
        prev_interfaces,
        last_update_time: std::time::Instant::now(),
        historical_data: BTreeMap::new(),
        max_history_size: 60,
    };
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                500,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_view with many interfaces should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_view_high_traffic() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let mut network_stats = create_test_network_stats();

    // Simulate high traffic
    if let Some(stats) = network_stats.interfaces.get_mut("eth0") {
        stats.recv_bytes = 1024 * 1024 * 1024 * 10; // 10 GB
        stats.sent_bytes = 1024 * 1024 * 1024 * 5; // 5 GB
        stats.recv_packets = 10_000_000;
        stats.sent_packets = 5_000_000;
    }

    if let Some(stats) = network_stats.prev_interfaces.get_mut("eth0") {
        stats.recv_bytes = 1024 * 1024 * 1024 * 9;
        stats.sent_bytes = 1024 * 1024 * 1024 * 4;
        stats.recv_packets = 9_000_000;
        stats.sent_packets = 4_000_000;
    }

    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                1000,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_view with high traffic should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_view_zero_traffic() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let mut interfaces = BTreeMap::new();

    // Add interface with no traffic
    interfaces.insert(
        "eth0".to_string(),
        InterfaceStats {
            recv_bytes: 0,
            sent_bytes: 0,
            recv_packets: 0,
            sent_packets: 0,
            recv_errs: 0,
            sent_errs: 0,
            recv_drop: 0,
            sent_drop: 0,
        },
    );

    let network_stats = NetworkStatSnapshot {
        interfaces,
        prev_interfaces: BTreeMap::new(),
        last_update_time: std::time::Instant::now(),
        historical_data: BTreeMap::new(),
        max_history_size: 60,
    };
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let result = NetworkRenderer::render_network_view(
                frame,
                &network_stats,
                1000,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_view with zero traffic should succeed"
            );
        })
        .unwrap();
}

#[test]
fn test_render_network_view_different_tick_rates() {
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    let network_stats = create_test_network_stats();
    let theme = AppTheme::Default;
    let locale = SystemLocale::default().unwrap();

    for tick_rate in [100, 500, 1000, 2000] {
        terminal
            .draw(|frame| {
                let result = NetworkRenderer::render_network_view(
                    frame,
                    &network_stats,
                    tick_rate,
                    false,
                    &locale,
                    &theme,
                );

                assert!(
                    result.is_ok(),
                    "render_network_view with {}ms tick rate should succeed",
                    tick_rate
                );
            })
            .unwrap();
    }
}

#[test]
fn test_render_network_summary_no_interfaces() {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let network_stats = NetworkStatSnapshot {
        interfaces: BTreeMap::new(),
        prev_interfaces: BTreeMap::new(),
        last_update_time: std::time::Instant::now(),
        historical_data: BTreeMap::new(),
        max_history_size: 60,
    };
    let theme = AppTheme::Default;
    let keymap = KeyMap::default();
    let locale = SystemLocale::default().unwrap();

    terminal
        .draw(|frame| {
            let area = frame.area();
            let result = NetworkRenderer::render_network_summary(
                frame,
                area,
                &network_stats,
                &keymap,
                false,
                &locale,
                &theme,
            );

            assert!(
                result.is_ok(),
                "render_network_summary with no interfaces should succeed"
            );
        })
        .unwrap();
}
