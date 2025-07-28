// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::ProcData;
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

pub fn get_process_columns() -> Vec<Column<i32, ProcData>> {
    vec![
        Column {
            header: "TGID",
            constraint: Constraint::Length(8),
            visible: true,
            value_fn: Box::new(|tgid, _| tgid.to_string()),
        },
        Column {
            header: "Name",
            constraint: Constraint::Length(15),
            visible: true,
            value_fn: Box::new(|_, data| data.process_name.clone()),
        },
        Column {
            header: "Command Line",
            constraint: Constraint::Fill(1),
            visible: true,
            value_fn: Box::new(|_, data| data.cmdline.join(" ")),
        },
        Column {
            header: "Layer ID",
            constraint: Constraint::Length(8),
            visible: false,
            value_fn: Box::new(|_, data| {
                data.layer_id
                    .filter(|&v| v >= 0)
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            }),
        },
        Column {
            header: "Last DSQ",
            constraint: Constraint::Length(18),
            visible: true,
            value_fn: Box::new(|_, data| data.dsq.map_or(String::new(), |v| format!("0x{v:X}"))),
        },
        Column {
            header: "Slice ns",
            constraint: Constraint::Length(8),
            visible: true,
            value_fn: Box::new(|_, data| {
                let stats = VecStats::new(&data.event_data_immut("slice_consumed"), None);
                stats.avg.to_string()
            }),
        },
        Column {
            header: "Avg/Max Lat us",
            constraint: Constraint::Length(14),
            visible: true,
            value_fn: Box::new(|_, data| {
                let stats = VecStats::new(&data.event_data_immut("lat_us"), None);
                format!("{}/{}", stats.avg, stats.max)
            }),
        },
        Column {
            header: "CPU",
            constraint: Constraint::Length(3),
            visible: true,
            value_fn: Box::new(|_, data| data.cpu.to_string()),
        },
        Column {
            header: "LLC",
            constraint: Constraint::Length(3),
            visible: true,
            value_fn: Box::new(|_, data| data.llc.map_or(String::new(), |v| v.to_string())),
        },
        Column {
            header: "NUMA",
            constraint: Constraint::Length(4),
            visible: true,
            value_fn: Box::new(|_, data| data.node.map_or(String::new(), |v| v.to_string())),
        },
        Column {
            header: "Threads",
            constraint: Constraint::Length(7),
            visible: true,
            value_fn: Box::new(|_, data| data.threads.len().to_string()),
        },
        Column {
            header: "CPU%",
            constraint: Constraint::Length(4),
            visible: true,
            value_fn: Box::new(|_, data| format!("{:?}", data.cpu_util_perc)),
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
            value_fn: Box::new(|_, _| format!("value")),
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
