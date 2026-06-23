// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Minimal ANSI coloring for live terminal progress.

use std::io::IsTerminal;

#[derive(Clone, Copy, Debug)]
pub struct Style {
    enabled: bool,
}

impl Style {
    pub fn stdout(no_color: bool) -> Self {
        Self::new(no_color, std::io::stdout().is_terminal())
    }

    pub fn stderr(no_color: bool) -> Self {
        Self::new(no_color, std::io::stderr().is_terminal())
    }

    fn new(no_color: bool, is_terminal: bool) -> Self {
        let env_disabled = std::env::var_os("NO_COLOR").is_some();
        Self {
            enabled: is_terminal && !no_color && !env_disabled,
        }
    }

    fn paint(&self, code: &str, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: impl AsRef<str>) -> String {
        self.paint("1", text)
    }

    pub fn dim(&self, text: impl AsRef<str>) -> String {
        self.paint("2", text)
    }

    pub fn blue(&self, text: impl AsRef<str>) -> String {
        self.paint("34", text)
    }

    pub fn cyan(&self, text: impl AsRef<str>) -> String {
        self.paint("36", text)
    }

    pub fn green(&self, text: impl AsRef<str>) -> String {
        self.paint("32", text)
    }

    pub fn yellow(&self, text: impl AsRef<str>) -> String {
        self.paint("33", text)
    }

    pub fn red(&self, text: impl AsRef<str>) -> String {
        self.paint("31", text)
    }
}
