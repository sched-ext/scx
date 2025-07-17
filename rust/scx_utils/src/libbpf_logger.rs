// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use libbpf_rs::{set_print, PrintLevel};

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{msg}"),
        PrintLevel::Info => log::info!("{msg}"),
        PrintLevel::Warn => log::warn!("{msg}"),
    }
}

pub fn init_libbpf_logging(level: Option<PrintLevel>) {
    set_print(Some((level.unwrap_or(PrintLevel::Debug), print_to_log)));
}
