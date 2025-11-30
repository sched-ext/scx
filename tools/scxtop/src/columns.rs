// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_prog_data::BpfProgData;
use crate::symbol_data::SymbolSample;
use crate::util::{format_bytes, format_percentage};
use crate::MemStatSnapshot;
use crate::ProcData;
use crate::ThreadData;
use crate::VecStats;
use ratatui::prelude::Constraint;
use std::collections::HashMap;

type ColumnFn<K, D> = Box<dyn Fn(K, &D) -> String>;

pub struct Column<K, D> {
    pub header: &'static str,
    pub constraint: ratatui::prelude::Constraint,
    pub visible: bool,
    pub value_fn: ColumnFn<K, D>,
}

pub struct Columns<K, D> {
    columns: Vec<Column<K, D>>,
    header_to_index: HashMap<&'static str, usize>,
}

impl<K, D> Columns<K, D> {
    pub fn new(columns: Vec<Column<K, D>>) -> Self {
        let header_to_index = columns
            .iter()
            .enumerate()
            .map(|(i, col)| (col.header, i))
            .collect();

        Self {
            columns,
            header_to_index,
        }
    }

    /// Update visibility of a single column by header
    pub fn update_visibility(&mut self, header: &str, visible: bool) -> bool {
        if let Some(&idx) = self.header_to_index.get(header) {
            self.columns[idx].visible = visible;
            true
        } else {
            false
        }
    }

    /// Return a slice of only the visible columns
    pub fn visible_columns(&self) -> impl Iterator<Item = &Column<K, D>> {
        self.columns.iter().filter(|c| c.visible)
    }

    /// Return all columns
    pub fn all_columns(&self) -> &[Column<K, D>] {
        &self.columns
    }
}

/// Macros to generate individual common columns shared between process and thread views
macro_rules! id_column {
    ($header:expr) => {
        Column {
            header: $header,
            constraint: Constraint::Length(8),
            visible: true,
            value_fn: Box::new(|id, _| id.to_string()),
        }
    };
}

macro_rules! name_column {
    ($data_type:ty, $name_field:ident) => {
        Column {
            header: "Name",
            constraint: Constraint::Length(15),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| data.$name_field.clone()),
        }
    };
}

macro_rules! last_dsq_column {
    ($data_type:ty) => {
        Column {
            header: "Last DSQ",
            constraint: Constraint::Length(18),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| {
                data.dsq.map_or(String::new(), |v| format!("0x{v:X}"))
            }),
        }
    };
}

macro_rules! slice_ns_column {
    ($data_type:ty) => {
        Column {
            header: "Slice ns",
            constraint: Constraint::Length(8),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| {
                let stats = VecStats::new(&data.event_data_immut("slice_consumed"), None);
                stats.avg.to_string()
            }),
        }
    };
}

macro_rules! avg_max_lat_column {
    ($data_type:ty) => {
        Column {
            header: "Lat us Avg/Max",
            constraint: Constraint::Length(14),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| {
                let stats = VecStats::new(&data.event_data_immut("lat_us"), None);
                format!("{}/{}", stats.avg, stats.max)
            }),
        }
    };
}

macro_rules! cpu_column {
    ($data_type:ty) => {
        Column {
            header: "CPU",
            constraint: Constraint::Length(3),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| data.cpu.to_string()),
        }
    };
}

macro_rules! llc_column {
    ($data_type:ty) => {
        Column {
            header: "LLC",
            constraint: Constraint::Length(3),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| {
                data.llc.map_or(String::new(), |v| v.to_string())
            }),
        }
    };
}

macro_rules! numa_column {
    ($data_type:ty) => {
        Column {
            header: "NUMA",
            constraint: Constraint::Length(4),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| {
                data.node.map_or(String::new(), |v| v.to_string())
            }),
        }
    };
}

macro_rules! cpu_util_column {
    ($data_type:ty) => {
        Column {
            header: "CPU%",
            constraint: Constraint::Length(4),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| format!("{:.2?}", data.cpu_util_perc)),
        }
    };
}

macro_rules! state_column {
    ($data_type:ty) => {
        Column {
            header: "State",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data: &$data_type| format!("{:?}", data.state)),
        }
    };
}

macro_rules! layer_id_column {
    ($data_type:ty) => {
        Column {
            header: "Layer ID",
            constraint: Constraint::Length(8),
            visible: false,
            value_fn: Box::new(|_, data: &$data_type| {
                data.layer_id
                    .filter(|&v| v >= 0)
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            }),
        }
    };
}

/// Macro for creating a metric column (first column in memory tables)
macro_rules! metric_column {
    ($label:expr) => {
        Column {
            header: "Metric",
            constraint: Constraint::Length(15),
            visible: true,
            value_fn: Box::new(|_, _| $label.to_string()),
        }
    };
}

/// Macro for creating a memory size column
macro_rules! memory_size_column {
    ($header:expr, $field:ident, $visible:expr) => {
        Column {
            header: $header,
            constraint: Constraint::Length(10),
            visible: $visible,
            value_fn: Box::new(|_, data| format_bytes(data.$field)),
        }
    };
}

/// Macro for creating a percentage column
macro_rules! percentage_column {
    ($header:expr, $visible:expr, $calculation:expr) => {
        Column {
            header: $header,
            constraint: Constraint::Length(6),
            visible: $visible,
            value_fn: Box::new(|_, data| format_percentage($calculation(data))),
        }
    };
}

/// Macro for creating a counter column
macro_rules! counter_column {
    ($header:expr, $field:ident, $visible:expr) => {
        Column {
            header: $header,
            constraint: Constraint::Length(10),
            visible: $visible,
            value_fn: Box::new(|_, data| data.$field.to_string()),
        }
    };
}

/// Macro for creating a rate column
macro_rules! rate_column {
    ($header:expr, $field:ident, $visible:expr) => {
        Column {
            header: $header,
            constraint: Constraint::Length(12),
            visible: $visible,
            value_fn: Box::new(|_, data| format!("{}/s", data.$field)),
        }
    };
}

/// Macro for creating a total column
macro_rules! total_column {
    ($header:expr, $visible:expr, $calculation:expr) => {
        Column {
            header: $header,
            constraint: Constraint::Length(10),
            visible: $visible,
            value_fn: Box::new(|_, data| $calculation(data)),
        }
    };
}

pub fn get_process_columns() -> Vec<Column<i32, ProcData>> {
    vec![
        id_column!("TGID"),
        name_column!(ProcData, process_name),
        Column {
            header: "Command Line",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data| data.cmdline.join(" ")),
        },
        layer_id_column!(ProcData),
        last_dsq_column!(ProcData),
        slice_ns_column!(ProcData),
        avg_max_lat_column!(ProcData),
        cpu_column!(ProcData),
        llc_column!(ProcData),
        numa_column!(ProcData),
        Column {
            header: "Threads",
            constraint: Constraint::Length(7),
            visible: true,
            value_fn: Box::new(|_, data| data.num_threads.to_string()),
        },
        cpu_util_column!(ProcData),
    ]
}

/// Returns process columns suitable for non-BPF mode (without BPF-dependent columns)
pub fn get_process_columns_no_bpf() -> Vec<Column<i32, ProcData>> {
    vec![
        id_column!("TGID"),
        name_column!(ProcData, process_name),
        Column {
            header: "Command Line",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data| data.cmdline.join(" ")),
        },
        cpu_column!(ProcData),
        llc_column!(ProcData),
        numa_column!(ProcData),
        Column {
            header: "Threads",
            constraint: Constraint::Length(7),
            visible: true,
            value_fn: Box::new(|_, data| data.num_threads.to_string()),
        },
        cpu_util_column!(ProcData),
    ]
}

pub fn get_thread_columns() -> Vec<Column<i32, ThreadData>> {
    vec![
        id_column!("TID"),
        name_column!(ThreadData, thread_name),
        cpu_column!(ThreadData),
        llc_column!(ThreadData),
        numa_column!(ThreadData),
        state_column!(ThreadData),
        layer_id_column!(ThreadData),
        last_dsq_column!(ThreadData),
        Column {
            header: "Waker PID",
            constraint: Constraint::Length(9),
            visible: true,
            value_fn: Box::new(|_, data: &ThreadData| {
                data.last_waker_pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_default()
            }),
        },
        Column {
            header: "Waker Comm",
            constraint: Constraint::Length(15),
            visible: true,
            value_fn: Box::new(|_, data: &ThreadData| {
                data.last_waker_comm.clone().unwrap_or_default()
            }),
        },
        slice_ns_column!(ThreadData),
        avg_max_lat_column!(ThreadData),
        cpu_util_column!(ThreadData),
    ]
}

/// Returns thread columns suitable for non-BPF mode (without BPF-dependent columns)
pub fn get_thread_columns_no_bpf() -> Vec<Column<i32, ThreadData>> {
    vec![
        id_column!("TID"),
        name_column!(ThreadData, thread_name),
        cpu_column!(ThreadData),
        llc_column!(ThreadData),
        numa_column!(ThreadData),
        cpu_util_column!(ThreadData),
    ]
}

/// Returns columns for memory statistics summary display
pub fn get_memory_summary_columns() -> Vec<Column<(), MemStatSnapshot>> {
    vec![
        metric_column!("Memory"),
        memory_size_column!("Total", total_kb, true),
        memory_size_column!("Free", free_kb, true),
        percentage_column!("Free%", true, |data: &MemStatSnapshot| data.free_ratio()),
        memory_size_column!("Available", available_kb, true),
        memory_size_column!("Cached", cached_kb, true),
        memory_size_column!("Buffers", buffers_kb, true),
        memory_size_column!("Active", active_kb, true),
        memory_size_column!("Inactive", inactive_kb, true),
    ]
}

/// Returns columns for swap statistics summary display
pub fn get_swap_summary_columns() -> Vec<Column<(), MemStatSnapshot>> {
    vec![
        metric_column!("Swap"),
        memory_size_column!("Total", swap_total_kb, true),
        memory_size_column!("Free", swap_free_kb, true),
        percentage_column!("Free%", true, |data: &MemStatSnapshot| data.swap_ratio()),
        memory_size_column!("Cached", swap_cached_kb, true),
        counter_column!("In", delta_swap_in, true),
        counter_column!("Out", delta_swap_out, true),
    ]
}

/// Returns columns for memory rates display
pub fn get_memory_rates_columns() -> Vec<Column<(), MemStatSnapshot>> {
    vec![
        metric_column!("Memory Rates"),
        rate_column!("Page Faults", delta_pgfault, true),
        rate_column!("Major Faults", delta_pgmajfault, true),
        rate_column!("Swap In", delta_swap_in, true),
        rate_column!("Swap Out", delta_swap_out, true),
    ]
}

/// Returns columns for slab information display
pub fn get_slab_columns() -> Vec<Column<(), MemStatSnapshot>> {
    vec![
        metric_column!("Slab Info"),
        memory_size_column!("Total", slab_kb, true),
        percentage_column!("% of RAM", true, |data: &MemStatSnapshot| data.slab_kb
            as f64
            / data.total_kb as f64),
        memory_size_column!("Reclaimable", sreclaimable_kb, true),
        memory_size_column!("Unreclaimable", sunreclaim_kb, true),
        percentage_column!("% of Slab", true, |data: &MemStatSnapshot| {
            if data.slab_kb > 0 {
                data.sunreclaim_kb as f64 / data.slab_kb as f64
            } else {
                0.0
            }
        }),
    ]
}

/// Returns columns for page fault statistics summary display
pub fn get_pagefault_summary_columns() -> Vec<Column<(), MemStatSnapshot>> {
    vec![
        metric_column!("Page Faults"),
        counter_column!("Minor", delta_pgfault, true),
        counter_column!("Major", delta_pgmajfault, true),
        total_column!("Total", true, |data: &MemStatSnapshot| (data.delta_pgfault
            + data.delta_pgmajfault)
            .to_string()),
    ]
}

/// Macro for creating a detail column
macro_rules! detail_column {
    ($header:expr, $constraint:expr, $visible:expr, $value_fn:expr) => {
        Column {
            header: $header,
            constraint: $constraint,
            visible: $visible,
            value_fn: Box::new($value_fn),
        }
    };
}

/// Returns columns for detailed memory view
pub fn get_memory_detail_columns() -> Vec<Column<&'static str, MemStatSnapshot>> {
    vec![
        detail_column!("Metric", Constraint::Percentage(40), true, |name, _| name
            .to_string()),
        detail_column!(
            "Value",
            Constraint::Percentage(30),
            true,
            |name, data| match name {
                "Total Memory" => format_bytes(data.total_kb),
                "Free Memory" => format_bytes(data.free_kb),
                "Available Memory" => format_bytes(data.available_kb),
                "Buffers" => format_bytes(data.buffers_kb),
                "Cached" => format_bytes(data.cached_kb),
                "Active" => format_bytes(data.active_kb),
                "Inactive" => format_bytes(data.inactive_kb),
                "Active (anon)" => format_bytes(data.active_anon_kb),
                "Inactive (anon)" => format_bytes(data.inactive_anon_kb),
                "Active (file)" => format_bytes(data.active_file_kb),
                "Inactive (file)" => format_bytes(data.inactive_file_kb),
                "Unevictable" => format_bytes(data.unevictable_kb),
                "Mlocked" => format_bytes(data.mlocked_kb),
                "Dirty" => format_bytes(data.dirty_kb),
                "Writeback" => format_bytes(data.writeback_kb),
                "Anonymous Pages" => format_bytes(data.anon_pages_kb),
                "Mapped" => format_bytes(data.mapped_kb),
                "Slab" => format_bytes(data.slab_kb),
                "SReclaimable" => format_bytes(data.sreclaimable_kb),
                "SUnreclaim" => format_bytes(data.sunreclaim_kb),
                "Kernel Stack" => format_bytes(data.kernel_stack_kb),
                "Page Tables" => format_bytes(data.page_tables_kb),
                "NFS Unstable" => format_bytes(data.nfs_unstable_kb),
                "Bounce" => format_bytes(data.bounce_kb),
                "Writeback Tmp" => format_bytes(data.writeback_tmp_kb),
                "Commit Limit" => format_bytes(data.commit_limit_kb),
                "Committed AS" => format_bytes(data.committed_as_kb),
                "Swap Total" => format_bytes(data.swap_total_kb),
                "Swap Free" => format_bytes(data.swap_free_kb),
                "Swap Cached" => format_bytes(data.swap_cached_kb),
                "Swap Pages In" => data.delta_swap_in.to_string(),
                "Swap Pages Out" => data.delta_swap_out.to_string(),
                "Page Faults" => data.delta_pgfault.to_string(),
                "Major Page Faults" => data.delta_pgmajfault.to_string(),
                _ => String::from("N/A"),
            }
        ),
        detail_column!(
            "Percentage",
            Constraint::Percentage(30),
            true,
            |name, data| match name {
                "Total Memory" => String::from("100%"),
                "Free Memory" => format_percentage(data.free_ratio()),
                "Available Memory" =>
                    format_percentage(data.available_kb as f64 / data.total_kb as f64),
                "Buffers" => format_percentage(data.buffers_kb as f64 / data.total_kb as f64),
                "Cached" => format_percentage(data.cached_kb as f64 / data.total_kb as f64),
                "Active" => format_percentage(data.active_kb as f64 / data.total_kb as f64),
                "Inactive" => format_percentage(data.inactive_kb as f64 / data.total_kb as f64),
                "Active (anon)" =>
                    format_percentage(data.active_anon_kb as f64 / data.total_kb as f64),
                "Inactive (anon)" =>
                    format_percentage(data.inactive_anon_kb as f64 / data.total_kb as f64),
                "Active (file)" =>
                    format_percentage(data.active_file_kb as f64 / data.total_kb as f64),
                "Inactive (file)" =>
                    format_percentage(data.inactive_file_kb as f64 / data.total_kb as f64),
                "Unevictable" =>
                    format_percentage(data.unevictable_kb as f64 / data.total_kb as f64),
                "Mlocked" => format_percentage(data.mlocked_kb as f64 / data.total_kb as f64),
                "Dirty" => format_percentage(data.dirty_kb as f64 / data.total_kb as f64),
                "Writeback" => format_percentage(data.writeback_kb as f64 / data.total_kb as f64),
                "Anonymous Pages" =>
                    format_percentage(data.anon_pages_kb as f64 / data.total_kb as f64),
                "Mapped" => format_percentage(data.mapped_kb as f64 / data.total_kb as f64),
                "Slab" => format_percentage(data.slab_kb as f64 / data.total_kb as f64),
                "SReclaimable" =>
                    format_percentage(data.sreclaimable_kb as f64 / data.total_kb as f64),
                "SUnreclaim" => format_percentage(data.sunreclaim_kb as f64 / data.total_kb as f64),
                "Kernel Stack" =>
                    format_percentage(data.kernel_stack_kb as f64 / data.total_kb as f64),
                "Page Tables" =>
                    format_percentage(data.page_tables_kb as f64 / data.total_kb as f64),
                "Swap Total" => String::from("100%"),
                "Swap Free" => format_percentage(data.swap_ratio()),
                "Swap Cached" =>
                    format_percentage(data.swap_cached_kb as f64 / data.swap_total_kb as f64),
                _ => String::from(""),
            }
        ),
    ]
}

/// Returns columns for perf top symbol display
pub fn get_perf_top_columns(layered_enabled: bool) -> Vec<Column<String, SymbolSample>> {
    vec![
        Column {
            header: "Symbol",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data| {
                let prefix = if data.is_kernel { "[K] " } else { "[U] " };
                format!("{}{}", prefix, data.symbol_info.symbol_name)
            }),
        },
        Column {
            header: "Module",
            constraint: Constraint::Length(20),
            visible: true,
            value_fn: Box::new(|_, data| data.symbol_info.module_name.clone()),
        },
        Column {
            header: "Layer ID",
            constraint: Constraint::Length(8),
            visible: layered_enabled,
            value_fn: Box::new(|_, data| {
                data.layer_id
                    .filter(|&v| v >= 0)
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            }),
        },
        Column {
            header: "Samples",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| data.count.to_string()),
        },
        Column {
            header: "Percentage",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| format!("{:.2}%", data.percentage)),
        },
    ]
}

/// Returns perf top columns suitable for non-BPF mode (without BPF-dependent features like Layer ID)
pub fn get_perf_top_columns_no_bpf() -> Vec<Column<String, SymbolSample>> {
    vec![
        Column {
            header: "Symbol",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data| {
                let prefix = if data.is_kernel { "[K] " } else { "[U] " };
                format!("{}{}", prefix, data.symbol_info.symbol_name)
            }),
        },
        Column {
            header: "Module",
            constraint: Constraint::Length(20),
            visible: true,
            value_fn: Box::new(|_, data| data.symbol_info.module_name.clone()),
        },
        Column {
            header: "Samples",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| data.count.to_string()),
        },
        Column {
            header: "Percentage",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| format!("{:.2}%", data.percentage)),
        },
    ]
}

/// Returns columns for power monitoring display
pub fn get_power_columns(
    has_temp_data: bool,
    available_cstates: &[String],
) -> Vec<Column<u32, crate::CorePowerData>> {
    // Calculate constraints based on available C-states and temperature data
    let base_columns = if has_temp_data { 5 } else { 4 }; // CPU, Freq, [Temp], Watt, Pkg
    let cstate_columns = available_cstates.len().min(3); // Limit to 3 C-states

    // Use percentage-based constraints for responsive layout
    let base_pct = 70; // 70% for base columns
    let cstate_pct = 30; // 30% for C-state columns

    let mut columns = vec![
        Column {
            header: "CPU",
            constraint: Constraint::Percentage((base_pct / base_columns as u16).max(8)),
            visible: true,
            value_fn: Box::new(|core_id: u32, _: &crate::CorePowerData| core_id.to_string()),
        },
        Column {
            header: "Freq",
            constraint: Constraint::Percentage((base_pct / base_columns as u16).max(10)),
            visible: true,
            value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                if data.frequency_mhz > 1000.0 {
                    format!("{:.1}G", data.frequency_mhz / 1000.0)
                } else {
                    format!("{:.0}M", data.frequency_mhz)
                }
            }),
        },
    ];

    if has_temp_data {
        columns.push(Column {
            header: "Temp",
            constraint: Constraint::Percentage((base_pct / base_columns as u16).max(8)),
            visible: true,
            value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                if data.temperature_celsius > 0.0 {
                    format!("{:.0}°", data.temperature_celsius)
                } else {
                    "-".to_string()
                }
            }),
        });
    }

    columns.extend([
        Column {
            header: "Watt",
            constraint: Constraint::Percentage((base_pct / base_columns as u16).max(10)),
            visible: true,
            value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                if data.power_watts > 0.0 {
                    format!("{:.1}", data.power_watts)
                } else {
                    "-".to_string()
                }
            }),
        },
        Column {
            header: "Pkg",
            constraint: Constraint::Percentage((base_pct / base_columns as u16).max(6)),
            visible: true,
            value_fn: Box::new(|_: u32, data: &crate::CorePowerData| data.package_id.to_string()),
        },
    ]);

    // Add C-state columns with equal percentage distribution
    let cstate_pct_each = if cstate_columns > 0 {
        cstate_pct / cstate_columns as u16
    } else {
        0
    };

    for (idx, cstate) in available_cstates.iter().take(3).enumerate() {
        let cstate_clone = cstate.clone();
        // Create very compact header
        let compact_header = match cstate.as_str() {
            "POLL" => "PL",
            "C1" | "C1_ACPI" => "C1",
            "C1E" => "1E",
            "C3" | "C3_ACPI" => "C3",
            "C6" => "C6",
            "C7" => "C7",
            "C8" => "C8",
            "C9" => "C9",
            "C10" => "10",
            _ => {
                if cstate.len() <= 2 {
                    cstate.as_str()
                } else {
                    match idx {
                        0 => "C0",
                        1 => "C1",
                        2 => "C2",
                        _ => "CX",
                    }
                }
            }
        };

        columns.push(Column {
            header: Box::leak(compact_header.to_string().into_boxed_str()),
            constraint: Constraint::Percentage(cstate_pct_each.max(8)),
            visible: true,
            value_fn: Box::new(move |_core_id: u32, data: &crate::CorePowerData| {
                // Calculate C-state percentage from residency data
                if let Some(cstate_info) = data.c_states.get(&cstate_clone) {
                    // Calculate total residency across all C-states for this core
                    let total_residency: u64 = data.c_states.values().map(|cs| cs.residency).sum();

                    if total_residency > 0 {
                        let percentage =
                            (cstate_info.residency as f64 / total_residency as f64) * 100.0;
                        if percentage >= 99.5 {
                            "99+".to_string()
                        } else if percentage >= 10.0 {
                            format!("{percentage:.0}")
                        } else if percentage >= 1.0 {
                            format!("{percentage:.1}")
                        } else if percentage > 0.0 {
                            "<1".to_string()
                        } else {
                            "0".to_string()
                        }
                    } else {
                        "-".to_string()
                    }
                } else {
                    "-".to_string()
                }
            }),
        });
    }

    columns
}

/// Returns a list of memory metrics to display in the detailed view
pub fn get_memory_detail_metrics() -> Vec<&'static str> {
    vec![
        // Basic Memory Information
        "Total Memory",
        "Free Memory",
        "Available Memory",
        "Buffers",
        "Cached",
        // Memory States
        "Active",
        "Inactive",
        "Active (anon)",
        "Inactive (anon)",
        "Active (file)",
        "Inactive (file)",
        "Unevictable",
        "Mlocked",
        // Memory Types
        "Anonymous Pages",
        "Mapped",
        "Slab",
        "SReclaimable",
        "SUnreclaim",
        "Kernel Stack",
        "Page Tables",
        // I/O Related
        "Dirty",
        "Writeback",
        "NFS Unstable",
        "Bounce",
        "Writeback Tmp",
        // Commit
        "Commit Limit",
        "Committed AS",
        // Swap Information
        "Swap Total",
        "Swap Free",
        "Swap Cached",
        "Swap Pages In",
        "Swap Pages Out",
        // Page Faults
        "Page Faults",
        "Major Page Faults",
    ]
}

/// Returns columns for BPF program statistics display
pub fn get_bpf_program_columns() -> Vec<Column<u32, BpfProgData>> {
    vec![
        Column {
            header: "ID",
            constraint: Constraint::Length(8),
            visible: true,
            value_fn: Box::new(|id, _| id.to_string()),
        },
        Column {
            header: "Type",
            constraint: Constraint::Length(18),
            visible: true,
            value_fn: Box::new(|_, data| data.prog_type.clone()),
        },
        Column {
            header: "Scheduler",
            constraint: Constraint::Length(15),
            visible: true,
            value_fn: Box::new(|_, data| {
                if data.is_sched_ext {
                    data.sched_ext_ops_name
                        .clone()
                        .unwrap_or_else(|| "sched_ext".to_string())
                } else {
                    "-".to_string()
                }
            }),
        },
        Column {
            header: "Name",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data| {
                if data.name.is_empty() {
                    format!("<unnamed-{}>", data.id)
                } else {
                    data.name.clone()
                }
            }),
        },
        Column {
            header: "Runtime",
            constraint: Constraint::Length(12),
            visible: true,
            value_fn: Box::new(|_, data| {
                if data.run_time_ns > 1_000_000_000 {
                    format!("{:.2}s", data.run_time_ns as f64 / 1_000_000_000.0)
                } else if data.run_time_ns > 1_000_000 {
                    format!("{:.2}ms", data.run_time_ns as f64 / 1_000_000.0)
                } else if data.run_time_ns > 1_000 {
                    format!("{:.2}μs", data.run_time_ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", data.run_time_ns)
                }
            }),
        },
        Column {
            header: "Run Count",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| data.run_cnt.to_string()),
        },
        Column {
            header: "Calls/sec",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| {
                let rate = data.calls_per_second();
                if rate >= 1_000_000.0 {
                    format!("{:.1}M", rate / 1_000_000.0)
                } else if rate >= 1_000.0 {
                    format!("{:.1}K", rate / 1_000.0)
                } else {
                    format!("{:.0}", rate)
                }
            }),
        },
        Column {
            header: "Avg Runtime",
            constraint: Constraint::Length(12),
            visible: true,
            value_fn: Box::new(|_, data| {
                let avg_ns = data.avg_runtime_ns();
                if avg_ns > 1_000_000.0 {
                    format!("{:.2}ms", avg_ns / 1_000_000.0)
                } else if avg_ns > 1_000.0 {
                    format!("{:.2}μs", avg_ns / 1_000.0)
                } else {
                    format!("{:.0}ns", avg_ns)
                }
            }),
        },
        Column {
            header: "p50",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| {
                if data.p50_runtime_ns == 0 {
                    "-".to_string()
                } else if data.p50_runtime_ns > 1_000_000 {
                    format!("{:.1}ms", data.p50_runtime_ns as f64 / 1_000_000.0)
                } else if data.p50_runtime_ns > 1_000 {
                    format!("{:.1}μs", data.p50_runtime_ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", data.p50_runtime_ns)
                }
            }),
        },
        Column {
            header: "p99",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, data| {
                if data.p99_runtime_ns == 0 {
                    "-".to_string()
                } else if data.p99_runtime_ns > 1_000_000 {
                    format!("{:.1}ms", data.p99_runtime_ns as f64 / 1_000_000.0)
                } else if data.p99_runtime_ns > 1_000 {
                    format!("{:.1}μs", data.p99_runtime_ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", data.p99_runtime_ns)
                }
            }),
        },
        Column {
            header: "Min Runtime",
            constraint: Constraint::Length(12),
            visible: false,
            value_fn: Box::new(|_, data| {
                if data.min_runtime_ns == 0 {
                    "-".to_string()
                } else if data.min_runtime_ns > 1_000_000 {
                    format!("{:.2}ms", data.min_runtime_ns as f64 / 1_000_000.0)
                } else if data.min_runtime_ns > 1_000 {
                    format!("{:.2}μs", data.min_runtime_ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", data.min_runtime_ns)
                }
            }),
        },
        Column {
            header: "Max Runtime",
            constraint: Constraint::Length(12),
            visible: false,
            value_fn: Box::new(|_, data| {
                if data.max_runtime_ns == 0 {
                    "-".to_string()
                } else if data.max_runtime_ns > 1_000_000 {
                    format!("{:.2}ms", data.max_runtime_ns as f64 / 1_000_000.0)
                } else if data.max_runtime_ns > 1_000 {
                    format!("{:.2}μs", data.max_runtime_ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", data.max_runtime_ns)
                }
            }),
        },
        Column {
            header: "Runtime %",
            constraint: Constraint::Length(10),
            visible: true,
            value_fn: Box::new(|_, _data| {
                // Note: This will be calculated based on total_runtime_ns when rendering
                format!("{:.2}%", 0.0) // Placeholder, will be updated during rendering
            }),
        },
        Column {
            header: "Misses",
            constraint: Constraint::Length(8),
            visible: true,
            value_fn: Box::new(|_, data| data.recursion_misses.to_string()),
        },
        Column {
            header: "Instructions",
            constraint: Constraint::Length(12),
            visible: true,
            value_fn: Box::new(|_, data| data.verified_insns.to_string()),
        },
        Column {
            header: "UID",
            constraint: Constraint::Length(6),
            visible: false,
            value_fn: Box::new(|_, data| data.uid.to_string()),
        },
        Column {
            header: "GPL",
            constraint: Constraint::Length(4),
            visible: false,
            value_fn: Box::new(|_, data| {
                if data.gpl_compatible { "Yes" } else { "No" }.to_string()
            }),
        },
        Column {
            header: "BTF ID",
            constraint: Constraint::Length(8),
            visible: false,
            value_fn: Box::new(|_, data| {
                if data.btf_id == 0 {
                    "-".to_string()
                } else {
                    data.btf_id.to_string()
                }
            }),
        },
        Column {
            header: "Maps",
            constraint: Constraint::Length(6),
            visible: false,
            value_fn: Box::new(|_, data| data.nr_map_ids.to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::prelude::Constraint;

    fn make_column<K, D>(header: &'static str, visible: bool) -> Column<K, D>
    where
        K: 'static,
        D: 'static,
    {
        Column {
            header,
            constraint: Constraint::Length(10),
            visible,
            value_fn: Box::new(|_, _| "value".to_string()),
        }
    }

    #[test]
    fn test_new_columns_builds_header_index() {
        let columns: Vec<Column<i32, i32>> = vec![
            make_column("PID", true),
            make_column("Name", false),
            make_column("CPU%", true),
        ];
        let c = Columns::new(columns);

        assert_eq!(c.header_to_index["PID"], 0);
        assert_eq!(c.header_to_index["Name"], 1);
        assert_eq!(c.header_to_index["CPU%"], 2);
    }

    #[test]
    fn test_visible_columns_filters_properly() {
        let columns: Vec<Column<i32, i32>> = vec![
            make_column("PID", true),
            make_column("Name", false),
            make_column("CPU%", true),
        ];
        let c = Columns::new(columns);
        let visible: Vec<&str> = c.visible_columns().map(|c| c.header).collect();

        assert_eq!(visible, vec!["PID", "CPU%"]);
    }

    #[test]
    fn test_update_visibility_success() {
        let columns: Vec<Column<i32, i32>> =
            vec![make_column("PID", true), make_column("Name", false)];
        let mut c = Columns::new(columns);
        let visible: Vec<&str> = c.visible_columns().map(|c| c.header).collect();
        assert_eq!(visible, vec!["PID"]);

        let updated = c.update_visibility("Name", true);

        assert!(updated);
        let visible: Vec<&str> = c.visible_columns().map(|c| c.header).collect();
        assert_eq!(visible, vec!["PID", "Name"]);
    }

    #[test]
    fn test_update_visibility_fails_gracefully() {
        let columns: Vec<Column<i32, i32>> = vec![make_column("PID", true)];
        let mut c = Columns::new(columns);
        let updated = c.update_visibility("Nonexistent", false);

        assert!(!updated);
        let visible: Vec<&str> = c.visible_columns().map(|c| c.header).collect();
        assert_eq!(visible, vec!["PID"]);
    }

    #[test]
    fn test_all_columns_returns_all() {
        let columns: Vec<Column<i32, i32>> = vec![make_column("A", true), make_column("B", false)];
        let c = Columns::new(columns);
        let headers: Vec<&str> = c.all_columns().iter().map(|c| c.header).collect();

        assert_eq!(headers, vec!["A", "B"]);
    }

    #[test]
    fn test_duplicate_headers_fail_to_map_properly() {
        let columns: Vec<Column<i32, i32>> = vec![make_column("A", true), make_column("A", false)];
        let c = Columns::new(columns);

        // Only the last one will remain in header_to_index
        assert_eq!(c.header_to_index.len(), 1);
        assert_eq!(c.header_to_index["A"], 1);
    }
}
