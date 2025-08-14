// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use ratatui::style::{Color, Style};
use ratatui::symbols::Marker;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppTheme {
    /// Default theme.
    Default,
    /// Dark theme with green text.
    MidnightGreen,
    /// IAmBlue
    IAmBlue,
    /// Solarized Dark theme
    SolarizedDark,
    /// Greyscale theme
    Greyscale,
    /// Nord theme
    Nord,
    /// Dracula theme
    Dracula,
    /// Monokai theme
    Monokai,
    /// Gruvbox theme
    Gruvbox,
    /// Tokyo Night theme
    TokyoNight,
    /// Catppuccin Mocha theme
    CatppuccinMocha,
    /// One Dark theme
    OneDark,
    /// Ayu Dark theme
    AyuDark,
    /// USA theme with American colors
    USA,
}

impl AppTheme {
    /// Returns the default text color for the theme.
    pub fn text_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Blue,
            AppTheme::SolarizedDark => Color::Rgb(131, 148, 150), // Solarized base0
            AppTheme::Greyscale => Color::Rgb(204, 204, 204),     // Light grey
            AppTheme::Nord => Color::Rgb(216, 222, 233),          // Nord Snow Storm
            AppTheme::Dracula => Color::Rgb(248, 248, 242),       // Dracula foreground
            AppTheme::Monokai => Color::Rgb(248, 248, 242),       // Monokai foreground
            AppTheme::Gruvbox => Color::Rgb(235, 219, 178),       // Gruvbox fg
            AppTheme::TokyoNight => Color::Rgb(169, 177, 214),    // Tokyo Night foreground
            AppTheme::CatppuccinMocha => Color::Rgb(205, 214, 244), // Catppuccin text
            AppTheme::OneDark => Color::Rgb(171, 178, 191),       // One Dark foreground
            AppTheme::AyuDark => Color::Rgb(230, 225, 207),       // Ayu Dark foreground
            AppTheme::USA => Color::White,                        // White text for USA theme
            AppTheme::Default => Color::White,
        }
    }

    /// Returns the title text color for the theme.
    pub fn title_style(&self) -> Style {
        match self {
            AppTheme::MidnightGreen => Style::default().fg(Color::White),
            AppTheme::IAmBlue => Style::default().fg(Color::Blue),
            AppTheme::SolarizedDark => Style::default().fg(Color::Rgb(38, 139, 210)), // Solarized blue
            AppTheme::Greyscale => Style::default().fg(Color::Rgb(255, 255, 255)),    // White
            AppTheme::Nord => Style::default().fg(Color::Rgb(143, 188, 187)),         // Nord Frost
            AppTheme::Dracula => Style::default().fg(Color::Rgb(189, 147, 249)), // Dracula purple
            AppTheme::Monokai => Style::default().fg(Color::Rgb(249, 38, 114)),  // Monokai magenta
            AppTheme::Gruvbox => Style::default().fg(Color::Rgb(250, 189, 47)),  // Gruvbox yellow
            AppTheme::TokyoNight => Style::default().fg(Color::Rgb(187, 154, 247)), // Tokyo Night purple
            AppTheme::CatppuccinMocha => Style::default().fg(Color::Rgb(203, 166, 247)), // Catppuccin mauve
            AppTheme::OneDark => Style::default().fg(Color::Rgb(97, 175, 239)), // One Dark blue
            AppTheme::AyuDark => Style::default().fg(Color::Rgb(255, 204, 102)), // Ayu Dark yellow
            AppTheme::USA => Style::default().fg(Color::Rgb(10, 49, 97)), // Navy blue for USA theme
            AppTheme::Default => Style::default().fg(Color::Green),
        }
    }

    /// Returns the border color for the theme.
    pub fn border_style(&self) -> Style {
        match self {
            AppTheme::MidnightGreen => Style::default().fg(Color::Green),
            AppTheme::IAmBlue => Style::default().fg(Color::Cyan),
            AppTheme::SolarizedDark => Style::default().fg(Color::Rgb(88, 110, 117)), // Solarized base01
            AppTheme::Greyscale => Style::default().fg(Color::Rgb(150, 150, 150)),    // Medium grey
            AppTheme::Nord => Style::default().fg(Color::Rgb(94, 129, 172)),          // Nord Frost
            AppTheme::Dracula => Style::default().fg(Color::Rgb(98, 114, 164)), // Dracula comment
            AppTheme::Monokai => Style::default().fg(Color::Rgb(117, 113, 94)), // Monokai brown
            AppTheme::Gruvbox => Style::default().fg(Color::Rgb(168, 153, 132)), // Gruvbox fg2
            AppTheme::TokyoNight => Style::default().fg(Color::Rgb(86, 95, 137)), // Tokyo Night comment
            AppTheme::CatppuccinMocha => Style::default().fg(Color::Rgb(127, 132, 156)), // Catppuccin overlay0
            AppTheme::OneDark => Style::default().fg(Color::Rgb(92, 99, 112)), // One Dark comment
            AppTheme::AyuDark => Style::default().fg(Color::Rgb(87, 92, 93)),  // Ayu Dark line
            AppTheme::USA => Style::default().fg(Color::Rgb(187, 19, 62)),     // Red for USA theme
            AppTheme::Default => Style::default().fg(Color::White),
        }
    }

    /// Returns the default text enabled color for the theme.
    pub fn text_enabled_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Blue,
            AppTheme::SolarizedDark => Color::Rgb(42, 161, 152), // Solarized cyan
            AppTheme::Greyscale => Color::Rgb(230, 230, 230),    // Light grey
            AppTheme::Nord => Color::Rgb(136, 192, 208),         // Nord Frost cyan
            AppTheme::Dracula => Color::Rgb(80, 250, 123),       // Dracula green
            AppTheme::Monokai => Color::Rgb(166, 226, 46),       // Monokai green
            AppTheme::Gruvbox => Color::Rgb(184, 187, 38),       // Gruvbox green
            AppTheme::TokyoNight => Color::Rgb(158, 206, 106),   // Tokyo Night green
            AppTheme::CatppuccinMocha => Color::Rgb(166, 227, 161), // Catppuccin green
            AppTheme::OneDark => Color::Rgb(152, 195, 121),      // One Dark green
            AppTheme::AyuDark => Color::Rgb(195, 232, 141),      // Ayu Dark green
            AppTheme::USA => Color::Rgb(10, 49, 97),             // Navy blue for USA theme
            AppTheme::Default => Color::Green,
        }
    }

    /// Returns the default text disabled color for the theme.
    pub fn text_disabled_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Red,
            AppTheme::SolarizedDark => Color::Rgb(220, 50, 47), // Solarized red
            AppTheme::Greyscale => Color::Rgb(100, 100, 100),   // Dark grey
            AppTheme::Nord => Color::Rgb(191, 97, 106),         // Nord Aurora red
            AppTheme::Dracula => Color::Rgb(255, 85, 85),       // Dracula red
            AppTheme::Monokai => Color::Rgb(249, 38, 114),      // Monokai magenta
            AppTheme::Gruvbox => Color::Rgb(251, 73, 52),       // Gruvbox red
            AppTheme::TokyoNight => Color::Rgb(247, 118, 142),  // Tokyo Night red
            AppTheme::CatppuccinMocha => Color::Rgb(243, 139, 168), // Catppuccin red
            AppTheme::OneDark => Color::Rgb(224, 108, 117),     // One Dark red
            AppTheme::AyuDark => Color::Rgb(255, 51, 51),       // Ayu Dark red
            AppTheme::USA => Color::Rgb(187, 19, 62),           // Red for USA theme
            AppTheme::Default => Color::Red,
        }
    }

    /// Returns the default text important color for the theme.
    pub fn text_important_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Red,
            AppTheme::IAmBlue => Color::White,
            AppTheme::SolarizedDark => Color::Rgb(181, 137, 0), // Solarized yellow
            AppTheme::Greyscale => Color::Rgb(255, 255, 255),   // White
            AppTheme::Nord => Color::Rgb(235, 203, 139),        // Nord Aurora yellow
            AppTheme::Dracula => Color::Rgb(241, 250, 140),     // Dracula yellow
            AppTheme::Monokai => Color::Rgb(230, 219, 116),     // Monokai yellow
            AppTheme::Gruvbox => Color::Rgb(250, 189, 47),      // Gruvbox yellow
            AppTheme::TokyoNight => Color::Rgb(224, 175, 104),  // Tokyo Night yellow
            AppTheme::CatppuccinMocha => Color::Rgb(249, 226, 175), // Catppuccin yellow
            AppTheme::OneDark => Color::Rgb(229, 192, 123),     // One Dark yellow
            AppTheme::AyuDark => Color::Rgb(255, 204, 102),     // Ayu Dark yellow
            AppTheme::USA => Color::White,                      // White for USA theme
            AppTheme::Default => Color::Red,
        }
    }

    /// Returns the sparkline style for the theme.
    pub fn sparkline_style(&self) -> Style {
        match self {
            AppTheme::MidnightGreen => Style::default().fg(Color::Green),
            AppTheme::IAmBlue => Style::default().fg(Color::Blue),
            AppTheme::SolarizedDark => Style::default().fg(Color::Rgb(133, 153, 0)), // Solarized green
            AppTheme::Greyscale => Style::default().fg(Color::Rgb(180, 180, 180)),   // Light grey
            AppTheme::Nord => Style::default().fg(Color::Rgb(163, 190, 140)), // Nord Aurora green
            AppTheme::Dracula => Style::default().fg(Color::Rgb(139, 233, 253)), // Dracula cyan
            AppTheme::Monokai => Style::default().fg(Color::Rgb(102, 217, 239)), // Monokai blue
            AppTheme::Gruvbox => Style::default().fg(Color::Rgb(104, 157, 106)), // Gruvbox aqua
            AppTheme::TokyoNight => Style::default().fg(Color::Rgb(125, 207, 255)), // Tokyo Night cyan
            AppTheme::CatppuccinMocha => Style::default().fg(Color::Rgb(137, 220, 235)), // Catppuccin sky
            AppTheme::OneDark => Style::default().fg(Color::Rgb(86, 182, 194)), // One Dark cyan
            AppTheme::AyuDark => Style::default().fg(Color::Rgb(95, 175, 239)), // Ayu Dark blue
            AppTheme::USA => Style::default().fg(Color::Rgb(10, 49, 97)), // Navy blue for USA theme
            AppTheme::Default => Style::default().fg(Color::Yellow),
        }
    }

    /// Returns the color for kernel space symbols in perf top view.
    pub fn kernel_symbol_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Rgb(255, 100, 100), // Light red
            AppTheme::IAmBlue => Color::Rgb(255, 140, 0),         // Orange
            AppTheme::SolarizedDark => Color::Rgb(220, 50, 47),   // Solarized red
            AppTheme::Greyscale => Color::Rgb(180, 180, 180),     // Light grey
            AppTheme::Nord => Color::Rgb(191, 97, 106),           // Nord Aurora red
            AppTheme::Dracula => Color::Rgb(255, 85, 85),         // Dracula red
            AppTheme::Monokai => Color::Rgb(249, 38, 114),        // Monokai magenta
            AppTheme::Gruvbox => Color::Rgb(251, 73, 52),         // Gruvbox red
            AppTheme::TokyoNight => Color::Rgb(247, 118, 142),    // Tokyo Night red
            AppTheme::CatppuccinMocha => Color::Rgb(243, 139, 168), // Catppuccin red
            AppTheme::OneDark => Color::Rgb(224, 108, 117),       // One Dark red
            AppTheme::AyuDark => Color::Rgb(255, 160, 122),       // Ayu Dark orange
            AppTheme::USA => Color::Rgb(187, 19, 62),             // Red for USA theme
            AppTheme::Default => Color::Red,
        }
    }

    /// Returns the color for userspace symbols in perf top view.
    pub fn userspace_symbol_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Rgb(100, 255, 100), // Light green
            AppTheme::IAmBlue => Color::Rgb(100, 149, 237),       // Cornflower blue
            AppTheme::SolarizedDark => Color::Rgb(42, 161, 152),  // Solarized cyan
            AppTheme::Greyscale => Color::Rgb(120, 120, 120),     // Medium grey
            AppTheme::Nord => Color::Rgb(136, 192, 208),          // Nord Frost cyan
            AppTheme::Dracula => Color::Rgb(80, 250, 123),        // Dracula green
            AppTheme::Monokai => Color::Rgb(166, 226, 46),        // Monokai green
            AppTheme::Gruvbox => Color::Rgb(104, 157, 106),       // Gruvbox aqua
            AppTheme::TokyoNight => Color::Rgb(158, 206, 106),    // Tokyo Night green
            AppTheme::CatppuccinMocha => Color::Rgb(166, 227, 161), // Catppuccin green
            AppTheme::OneDark => Color::Rgb(152, 195, 121),       // One Dark green
            AppTheme::AyuDark => Color::Rgb(95, 175, 239),        // Ayu Dark blue
            AppTheme::USA => Color::Rgb(10, 49, 97),              // Navy blue for USA theme
            AppTheme::Default => Color::Blue,
        }
    }

    /// Returns the plot marker for charts in the theme.
    pub fn plot_marker(&self) -> Marker {
        match self {
            AppTheme::MidnightGreen => Marker::Braille,
            AppTheme::IAmBlue => Marker::Dot,
            AppTheme::SolarizedDark => Marker::Braille,
            AppTheme::Greyscale => Marker::Block,
            AppTheme::Nord => Marker::Braille,
            AppTheme::Dracula => Marker::Dot,
            AppTheme::Monokai => Marker::Braille,
            AppTheme::Gruvbox => Marker::Block,
            AppTheme::TokyoNight => Marker::Braille,
            AppTheme::CatppuccinMocha => Marker::Dot,
            AppTheme::OneDark => Marker::Braille,
            AppTheme::AyuDark => Marker::Block,
            AppTheme::USA => Marker::Block,
            AppTheme::Default => Marker::Block,
        }
    }

    /// Returns the color for positive values (e.g., TX data) in the theme.
    pub fn positive_value_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Blue,
            AppTheme::SolarizedDark => Color::Rgb(133, 153, 0), // Solarized green
            AppTheme::Greyscale => Color::Rgb(180, 180, 180),   // Light grey
            AppTheme::Nord => Color::Rgb(163, 190, 140),        // Nord Aurora green
            AppTheme::Dracula => Color::Rgb(80, 250, 123),      // Dracula green
            AppTheme::Monokai => Color::Rgb(166, 226, 46),      // Monokai green
            AppTheme::Gruvbox => Color::Rgb(184, 187, 38),      // Gruvbox green
            AppTheme::TokyoNight => Color::Rgb(158, 206, 106),  // Tokyo Night green
            AppTheme::CatppuccinMocha => Color::Rgb(166, 227, 161), // Catppuccin green
            AppTheme::OneDark => Color::Rgb(152, 195, 121),     // One Dark green
            AppTheme::AyuDark => Color::Rgb(195, 232, 141),     // Ayu Dark green
            AppTheme::USA => Color::Rgb(10, 49, 97),            // Navy blue for USA theme
            AppTheme::Default => Color::Green,
        }
    }

    /// Returns the color for negative values (e.g., RX data) in the theme.
    pub fn negative_value_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Yellow,
            AppTheme::IAmBlue => Color::Cyan,
            AppTheme::SolarizedDark => Color::Rgb(42, 161, 152), // Solarized cyan
            AppTheme::Greyscale => Color::Rgb(120, 120, 120),    // Medium grey
            AppTheme::Nord => Color::Rgb(136, 192, 208),         // Nord Frost cyan
            AppTheme::Dracula => Color::Rgb(139, 233, 253),      // Dracula cyan
            AppTheme::Monokai => Color::Rgb(102, 217, 239),      // Monokai blue
            AppTheme::Gruvbox => Color::Rgb(104, 157, 106),      // Gruvbox aqua
            AppTheme::TokyoNight => Color::Rgb(125, 207, 255),   // Tokyo Night cyan
            AppTheme::CatppuccinMocha => Color::Rgb(137, 220, 235), // Catppuccin sky
            AppTheme::OneDark => Color::Rgb(86, 182, 194),       // One Dark cyan
            AppTheme::AyuDark => Color::Rgb(95, 175, 239),       // Ayu Dark blue
            AppTheme::USA => Color::Rgb(187, 19, 62),            // Red for USA theme
            AppTheme::Default => Color::Red,
        }
    }

    /// Returns the low-level color for a 3-level gradient.
    ///
    /// # Arguments
    /// * `reverse` - If true, high values get the "good" color, if false, low values get the "good" color
    pub fn gradient_3_low(&self, reverse: bool) -> Color {
        if reverse {
            // High values are good, so low values get the "bad" color
            self.text_disabled_color()
        } else {
            // Low values are good, so low values get the "good" color
            self.text_enabled_color()
        }
    }

    /// Returns the mid-level color for a 3-level gradient.
    /// Mid-level always uses the important/warning color regardless of reverse direction.
    pub fn gradient_3_mid(&self) -> Color {
        // Mid-level always uses the important/warning color regardless of reverse
        self.text_important_color()
    }

    /// Returns the high-level color for a 3-level gradient.
    ///
    /// # Arguments
    /// * `reverse` - If true, high values get the "good" color, if false, low values get the "good" color
    pub fn gradient_3_high(&self, reverse: bool) -> Color {
        if reverse {
            // High values are good, so high values get the "good" color
            self.text_enabled_color()
        } else {
            // Low values are good, so high values get the "bad" color
            self.text_disabled_color()
        }
    }

    /// Returns a color for a 3-level gradient (LOW, MID, HIGH) based on value and thresholds.
    ///
    /// # Arguments
    /// * `value` - The current value to evaluate
    /// * `low_threshold` - Values <= this are considered LOW
    /// * `high_threshold` - Values >= this are considered HIGH
    /// * `reverse` - If true, high values get the "good" color (green), if false, low values get the "good" color
    pub fn gradient_3(
        &self,
        value: f64,
        low_threshold: f64,
        high_threshold: f64,
        reverse: bool,
    ) -> Color {
        if value <= low_threshold {
            self.gradient_3_low(reverse)
        } else if value >= high_threshold {
            self.gradient_3_high(reverse)
        } else {
            self.gradient_3_mid()
        }
    }

    /// Returns a color for a 5-level gradient (VERY_LOW, LOW, MID, HIGH, VERY_HIGH) based on value and thresholds.
    ///
    /// # Arguments
    /// * `value` - The current value to evaluate
    /// * `very_low_threshold` - Values <= this are considered VERY_LOW
    /// * `low_threshold` - Values <= this (but > very_low) are considered LOW
    /// * `high_threshold` - Values >= this (but < very_high) are considered HIGH
    /// * `very_high_threshold` - Values >= this are considered VERY_HIGH
    /// * `reverse` - If true, high values get the "good" color, if false, low values get the "good" color
    pub fn gradient_5(
        &self,
        value: f64,
        very_low_threshold: f64,
        low_threshold: f64,
        high_threshold: f64,
        very_high_threshold: f64,
        reverse: bool,
    ) -> Color {
        let (very_low_color, low_color, mid_color, high_color, very_high_color) = match self {
            AppTheme::Default => {
                if reverse {
                    (
                        Color::Red,
                        Color::Rgb(255, 165, 0),
                        Color::Yellow,
                        Color::LightGreen,
                        Color::Green,
                    )
                } else {
                    (
                        Color::Green,
                        Color::LightGreen,
                        Color::Yellow,
                        Color::Rgb(255, 165, 0),
                        Color::Red,
                    )
                }
            }
            AppTheme::MidnightGreen => {
                if reverse {
                    (
                        Color::Red,
                        Color::Rgb(255, 140, 0),
                        Color::Yellow,
                        Color::LightGreen,
                        Color::Green,
                    )
                } else {
                    (
                        Color::Green,
                        Color::LightGreen,
                        Color::Yellow,
                        Color::Rgb(255, 140, 0),
                        Color::Red,
                    )
                }
            }
            AppTheme::IAmBlue => {
                if reverse {
                    (
                        Color::Red,
                        Color::Rgb(255, 140, 0),
                        Color::Yellow,
                        Color::Cyan,
                        Color::Blue,
                    )
                } else {
                    (
                        Color::Blue,
                        Color::Cyan,
                        Color::Yellow,
                        Color::Rgb(255, 140, 0),
                        Color::Red,
                    )
                }
            }
            AppTheme::SolarizedDark => {
                if reverse {
                    (
                        Color::Rgb(220, 50, 47),
                        Color::Rgb(203, 75, 22),
                        Color::Rgb(181, 137, 0),
                        Color::Rgb(133, 153, 0),
                        Color::Rgb(42, 161, 152),
                    )
                } else {
                    (
                        Color::Rgb(42, 161, 152),
                        Color::Rgb(133, 153, 0),
                        Color::Rgb(181, 137, 0),
                        Color::Rgb(203, 75, 22),
                        Color::Rgb(220, 50, 47),
                    )
                }
            }
            AppTheme::Greyscale => {
                if reverse {
                    (
                        Color::Rgb(80, 80, 80),
                        Color::Rgb(120, 120, 120),
                        Color::Rgb(160, 160, 160),
                        Color::Rgb(200, 200, 200),
                        Color::Rgb(240, 240, 240),
                    )
                } else {
                    (
                        Color::Rgb(240, 240, 240),
                        Color::Rgb(200, 200, 200),
                        Color::Rgb(160, 160, 160),
                        Color::Rgb(120, 120, 120),
                        Color::Rgb(80, 80, 80),
                    )
                }
            }
            AppTheme::Nord => {
                if reverse {
                    (
                        Color::Rgb(191, 97, 106),
                        Color::Rgb(208, 135, 112),
                        Color::Rgb(235, 203, 139),
                        Color::Rgb(163, 190, 140),
                        Color::Rgb(136, 192, 208),
                    )
                } else {
                    (
                        Color::Rgb(136, 192, 208),
                        Color::Rgb(163, 190, 140),
                        Color::Rgb(235, 203, 139),
                        Color::Rgb(208, 135, 112),
                        Color::Rgb(191, 97, 106),
                    )
                }
            }
            AppTheme::Dracula => {
                if reverse {
                    (
                        Color::Rgb(255, 85, 85),
                        Color::Rgb(255, 184, 108),
                        Color::Rgb(241, 250, 140),
                        Color::Rgb(139, 233, 253),
                        Color::Rgb(80, 250, 123),
                    )
                } else {
                    (
                        Color::Rgb(80, 250, 123),
                        Color::Rgb(139, 233, 253),
                        Color::Rgb(241, 250, 140),
                        Color::Rgb(255, 184, 108),
                        Color::Rgb(255, 85, 85),
                    )
                }
            }
            AppTheme::Monokai => {
                if reverse {
                    (
                        Color::Rgb(249, 38, 114),
                        Color::Rgb(253, 151, 31),
                        Color::Rgb(230, 219, 116),
                        Color::Rgb(102, 217, 239),
                        Color::Rgb(166, 226, 46),
                    )
                } else {
                    (
                        Color::Rgb(166, 226, 46),
                        Color::Rgb(102, 217, 239),
                        Color::Rgb(230, 219, 116),
                        Color::Rgb(253, 151, 31),
                        Color::Rgb(249, 38, 114),
                    )
                }
            }
            AppTheme::Gruvbox => {
                if reverse {
                    (
                        Color::Rgb(251, 73, 52),
                        Color::Rgb(254, 128, 25),
                        Color::Rgb(250, 189, 47),
                        Color::Rgb(184, 187, 38),
                        Color::Rgb(104, 157, 106),
                    )
                } else {
                    (
                        Color::Rgb(104, 157, 106),
                        Color::Rgb(184, 187, 38),
                        Color::Rgb(250, 189, 47),
                        Color::Rgb(254, 128, 25),
                        Color::Rgb(251, 73, 52),
                    )
                }
            }
            AppTheme::TokyoNight => {
                if reverse {
                    (
                        Color::Rgb(247, 118, 142),
                        Color::Rgb(255, 158, 100),
                        Color::Rgb(224, 175, 104),
                        Color::Rgb(125, 207, 255),
                        Color::Rgb(158, 206, 106),
                    )
                } else {
                    (
                        Color::Rgb(158, 206, 106),
                        Color::Rgb(125, 207, 255),
                        Color::Rgb(224, 175, 104),
                        Color::Rgb(255, 158, 100),
                        Color::Rgb(247, 118, 142),
                    )
                }
            }
            AppTheme::CatppuccinMocha => {
                if reverse {
                    (
                        Color::Rgb(243, 139, 168),
                        Color::Rgb(250, 179, 135),
                        Color::Rgb(249, 226, 175),
                        Color::Rgb(137, 220, 235),
                        Color::Rgb(166, 227, 161),
                    )
                } else {
                    (
                        Color::Rgb(166, 227, 161),
                        Color::Rgb(137, 220, 235),
                        Color::Rgb(249, 226, 175),
                        Color::Rgb(250, 179, 135),
                        Color::Rgb(243, 139, 168),
                    )
                }
            }
            AppTheme::OneDark => {
                if reverse {
                    (
                        Color::Rgb(224, 108, 117),
                        Color::Rgb(209, 154, 102),
                        Color::Rgb(229, 192, 123),
                        Color::Rgb(86, 182, 194),
                        Color::Rgb(152, 195, 121),
                    )
                } else {
                    (
                        Color::Rgb(152, 195, 121),
                        Color::Rgb(86, 182, 194),
                        Color::Rgb(229, 192, 123),
                        Color::Rgb(209, 154, 102),
                        Color::Rgb(224, 108, 117),
                    )
                }
            }
            AppTheme::AyuDark => {
                if reverse {
                    (
                        Color::Rgb(255, 51, 51),
                        Color::Rgb(255, 160, 122),
                        Color::Rgb(255, 204, 102),
                        Color::Rgb(95, 175, 239),
                        Color::Rgb(195, 232, 141),
                    )
                } else {
                    (
                        Color::Rgb(195, 232, 141),
                        Color::Rgb(95, 175, 239),
                        Color::Rgb(255, 204, 102),
                        Color::Rgb(255, 160, 122),
                        Color::Rgb(255, 51, 51),
                    )
                }
            }
            AppTheme::USA => {
                if reverse {
                    (
                        Color::Rgb(187, 19, 62),
                        Color::Rgb(255, 100, 100),
                        Color::White,
                        Color::Rgb(100, 149, 237),
                        Color::Rgb(10, 49, 97),
                    )
                } else {
                    (
                        Color::Rgb(10, 49, 97),
                        Color::Rgb(100, 149, 237),
                        Color::White,
                        Color::Rgb(255, 100, 100),
                        Color::Rgb(187, 19, 62),
                    )
                }
            }
        };

        if value <= very_low_threshold {
            very_low_color
        } else if value <= low_threshold {
            low_color
        } else if value < high_threshold {
            mid_color
        } else if value < very_high_threshold {
            high_color
        } else {
            very_high_color
        }
    }

    /// Returns the next theme.
    pub fn next(&self) -> Self {
        match self {
            AppTheme::Default => AppTheme::MidnightGreen,
            AppTheme::MidnightGreen => AppTheme::IAmBlue,
            AppTheme::IAmBlue => AppTheme::SolarizedDark,
            AppTheme::SolarizedDark => AppTheme::Greyscale,
            AppTheme::Greyscale => AppTheme::Nord,
            AppTheme::Nord => AppTheme::Dracula,
            AppTheme::Dracula => AppTheme::Monokai,
            AppTheme::Monokai => AppTheme::Gruvbox,
            AppTheme::Gruvbox => AppTheme::TokyoNight,
            AppTheme::TokyoNight => AppTheme::CatppuccinMocha,
            AppTheme::CatppuccinMocha => AppTheme::OneDark,
            AppTheme::OneDark => AppTheme::AyuDark,
            AppTheme::AyuDark => AppTheme::USA,
            AppTheme::USA => AppTheme::Default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_next() {
        assert_eq!(AppTheme::Default.next(), AppTheme::MidnightGreen);
        assert_eq!(AppTheme::MidnightGreen.next(), AppTheme::IAmBlue);
        assert_eq!(AppTheme::IAmBlue.next(), AppTheme::SolarizedDark);
        assert_eq!(AppTheme::SolarizedDark.next(), AppTheme::Greyscale);
        assert_eq!(AppTheme::Greyscale.next(), AppTheme::Nord);
        assert_eq!(AppTheme::Nord.next(), AppTheme::Dracula);
        assert_eq!(AppTheme::Dracula.next(), AppTheme::Monokai);
        assert_eq!(AppTheme::Monokai.next(), AppTheme::Gruvbox);
        assert_eq!(AppTheme::Gruvbox.next(), AppTheme::TokyoNight);
        assert_eq!(AppTheme::TokyoNight.next(), AppTheme::CatppuccinMocha);
        assert_eq!(AppTheme::CatppuccinMocha.next(), AppTheme::OneDark);
        assert_eq!(AppTheme::OneDark.next(), AppTheme::AyuDark);
        assert_eq!(AppTheme::AyuDark.next(), AppTheme::USA);
        assert_eq!(AppTheme::USA.next(), AppTheme::Default);
    }

    #[test]
    fn test_theme_text_color() {
        assert_eq!(AppTheme::Default.text_color(), Color::White);
        assert_eq!(AppTheme::MidnightGreen.text_color(), Color::Green);
        assert_eq!(AppTheme::IAmBlue.text_color(), Color::Blue);
        assert_eq!(
            AppTheme::SolarizedDark.text_color(),
            Color::Rgb(131, 148, 150)
        ); // Solarized base0
        assert_eq!(AppTheme::Greyscale.text_color(), Color::Rgb(204, 204, 204)); // Light grey
        assert_eq!(AppTheme::Nord.text_color(), Color::Rgb(216, 222, 233)); // Nord Snow Storm
        assert_eq!(AppTheme::Dracula.text_color(), Color::Rgb(248, 248, 242)); // Dracula foreground
        assert_eq!(AppTheme::Monokai.text_color(), Color::Rgb(248, 248, 242)); // Monokai foreground
        assert_eq!(AppTheme::Gruvbox.text_color(), Color::Rgb(235, 219, 178)); // Gruvbox fg
        assert_eq!(AppTheme::TokyoNight.text_color(), Color::Rgb(169, 177, 214)); // Tokyo Night foreground
        assert_eq!(
            AppTheme::CatppuccinMocha.text_color(),
            Color::Rgb(205, 214, 244)
        ); // Catppuccin text
        assert_eq!(AppTheme::OneDark.text_color(), Color::Rgb(171, 178, 191)); // One Dark foreground
        assert_eq!(AppTheme::AyuDark.text_color(), Color::Rgb(230, 225, 207)); // Ayu Dark foreground
    }

    #[test]
    fn test_theme_title_style() {
        assert_eq!(
            AppTheme::Default.title_style(),
            Style::default().fg(Color::Green)
        );
        assert_eq!(
            AppTheme::MidnightGreen.title_style(),
            Style::default().fg(Color::White)
        );
        assert_eq!(
            AppTheme::IAmBlue.title_style(),
            Style::default().fg(Color::Blue)
        );
        assert_eq!(
            AppTheme::SolarizedDark.title_style(),
            Style::default().fg(Color::Rgb(38, 139, 210))
        ); // Solarized blue
        assert_eq!(
            AppTheme::Greyscale.title_style(),
            Style::default().fg(Color::Rgb(255, 255, 255))
        ); // White
        assert_eq!(
            AppTheme::Nord.title_style(),
            Style::default().fg(Color::Rgb(143, 188, 187))
        ); // Nord Frost
        assert_eq!(
            AppTheme::Dracula.title_style(),
            Style::default().fg(Color::Rgb(189, 147, 249))
        ); // Dracula purple
        assert_eq!(
            AppTheme::Monokai.title_style(),
            Style::default().fg(Color::Rgb(249, 38, 114))
        ); // Monokai magenta
        assert_eq!(
            AppTheme::Gruvbox.title_style(),
            Style::default().fg(Color::Rgb(250, 189, 47))
        ); // Gruvbox yellow
        assert_eq!(
            AppTheme::TokyoNight.title_style(),
            Style::default().fg(Color::Rgb(187, 154, 247))
        ); // Tokyo Night purple
        assert_eq!(
            AppTheme::CatppuccinMocha.title_style(),
            Style::default().fg(Color::Rgb(203, 166, 247))
        ); // Catppuccin mauve
        assert_eq!(
            AppTheme::OneDark.title_style(),
            Style::default().fg(Color::Rgb(97, 175, 239))
        ); // One Dark blue
        assert_eq!(
            AppTheme::AyuDark.title_style(),
            Style::default().fg(Color::Rgb(255, 204, 102))
        ); // Ayu Dark yellow
    }

    #[test]
    fn test_theme_border_style() {
        assert_eq!(
            AppTheme::Default.border_style(),
            Style::default().fg(Color::White)
        );
        assert_eq!(
            AppTheme::MidnightGreen.border_style(),
            Style::default().fg(Color::Green)
        );
        assert_eq!(
            AppTheme::IAmBlue.border_style(),
            Style::default().fg(Color::Cyan)
        );
        assert_eq!(
            AppTheme::SolarizedDark.border_style(),
            Style::default().fg(Color::Rgb(88, 110, 117))
        ); // Solarized base01
        assert_eq!(
            AppTheme::Greyscale.border_style(),
            Style::default().fg(Color::Rgb(150, 150, 150))
        ); // Medium grey
        assert_eq!(
            AppTheme::Nord.border_style(),
            Style::default().fg(Color::Rgb(94, 129, 172))
        ); // Nord Frost
        assert_eq!(
            AppTheme::Dracula.border_style(),
            Style::default().fg(Color::Rgb(98, 114, 164))
        ); // Dracula comment
        assert_eq!(
            AppTheme::Monokai.border_style(),
            Style::default().fg(Color::Rgb(117, 113, 94))
        ); // Monokai brown
        assert_eq!(
            AppTheme::Gruvbox.border_style(),
            Style::default().fg(Color::Rgb(168, 153, 132))
        ); // Gruvbox fg2
        assert_eq!(
            AppTheme::TokyoNight.border_style(),
            Style::default().fg(Color::Rgb(86, 95, 137))
        ); // Tokyo Night comment
        assert_eq!(
            AppTheme::CatppuccinMocha.border_style(),
            Style::default().fg(Color::Rgb(127, 132, 156))
        ); // Catppuccin overlay0
        assert_eq!(
            AppTheme::OneDark.border_style(),
            Style::default().fg(Color::Rgb(92, 99, 112))
        ); // One Dark comment
        assert_eq!(
            AppTheme::AyuDark.border_style(),
            Style::default().fg(Color::Rgb(87, 92, 93))
        ); // Ayu Dark line
    }

    #[test]
    fn test_theme_text_enabled_color() {
        assert_eq!(AppTheme::Default.text_enabled_color(), Color::Green);
        assert_eq!(AppTheme::MidnightGreen.text_enabled_color(), Color::Green);
        assert_eq!(AppTheme::IAmBlue.text_enabled_color(), Color::Blue);
        assert_eq!(
            AppTheme::SolarizedDark.text_enabled_color(),
            Color::Rgb(42, 161, 152)
        ); // Solarized cyan
        assert_eq!(
            AppTheme::Greyscale.text_enabled_color(),
            Color::Rgb(230, 230, 230)
        ); // Light grey
        assert_eq!(
            AppTheme::Nord.text_enabled_color(),
            Color::Rgb(136, 192, 208)
        ); // Nord Frost cyan
        assert_eq!(
            AppTheme::Dracula.text_enabled_color(),
            Color::Rgb(80, 250, 123)
        ); // Dracula green
        assert_eq!(
            AppTheme::Monokai.text_enabled_color(),
            Color::Rgb(166, 226, 46)
        ); // Monokai green
        assert_eq!(
            AppTheme::Gruvbox.text_enabled_color(),
            Color::Rgb(184, 187, 38)
        ); // Gruvbox green
        assert_eq!(
            AppTheme::TokyoNight.text_enabled_color(),
            Color::Rgb(158, 206, 106)
        ); // Tokyo Night green
        assert_eq!(
            AppTheme::CatppuccinMocha.text_enabled_color(),
            Color::Rgb(166, 227, 161)
        ); // Catppuccin green
        assert_eq!(
            AppTheme::OneDark.text_enabled_color(),
            Color::Rgb(152, 195, 121)
        ); // One Dark green
        assert_eq!(
            AppTheme::AyuDark.text_enabled_color(),
            Color::Rgb(195, 232, 141)
        ); // Ayu Dark green
    }

    #[test]
    fn test_theme_text_disabled_color() {
        assert_eq!(AppTheme::Default.text_disabled_color(), Color::Red);
        assert_eq!(AppTheme::MidnightGreen.text_disabled_color(), Color::Green);
        assert_eq!(AppTheme::IAmBlue.text_disabled_color(), Color::Red);
        assert_eq!(
            AppTheme::SolarizedDark.text_disabled_color(),
            Color::Rgb(220, 50, 47)
        ); // Solarized red
        assert_eq!(
            AppTheme::Greyscale.text_disabled_color(),
            Color::Rgb(100, 100, 100)
        ); // Dark grey
        assert_eq!(
            AppTheme::Nord.text_disabled_color(),
            Color::Rgb(191, 97, 106)
        ); // Nord Aurora red
        assert_eq!(
            AppTheme::Dracula.text_disabled_color(),
            Color::Rgb(255, 85, 85)
        ); // Dracula red
        assert_eq!(
            AppTheme::Monokai.text_disabled_color(),
            Color::Rgb(249, 38, 114)
        ); // Monokai magenta
        assert_eq!(
            AppTheme::Gruvbox.text_disabled_color(),
            Color::Rgb(251, 73, 52)
        ); // Gruvbox red
        assert_eq!(
            AppTheme::TokyoNight.text_disabled_color(),
            Color::Rgb(247, 118, 142)
        ); // Tokyo Night red
        assert_eq!(
            AppTheme::CatppuccinMocha.text_disabled_color(),
            Color::Rgb(243, 139, 168)
        ); // Catppuccin red
        assert_eq!(
            AppTheme::OneDark.text_disabled_color(),
            Color::Rgb(224, 108, 117)
        ); // One Dark red
        assert_eq!(
            AppTheme::AyuDark.text_disabled_color(),
            Color::Rgb(255, 51, 51)
        ); // Ayu Dark red
    }

    #[test]
    fn test_theme_text_important_color() {
        assert_eq!(AppTheme::Default.text_important_color(), Color::Red);
        assert_eq!(AppTheme::MidnightGreen.text_important_color(), Color::Red);
        assert_eq!(AppTheme::IAmBlue.text_important_color(), Color::White);
        assert_eq!(
            AppTheme::SolarizedDark.text_important_color(),
            Color::Rgb(181, 137, 0)
        ); // Solarized yellow
        assert_eq!(
            AppTheme::Greyscale.text_important_color(),
            Color::Rgb(255, 255, 255)
        ); // White
        assert_eq!(
            AppTheme::Nord.text_important_color(),
            Color::Rgb(235, 203, 139)
        ); // Nord Aurora yellow
        assert_eq!(
            AppTheme::Dracula.text_important_color(),
            Color::Rgb(241, 250, 140)
        ); // Dracula yellow
        assert_eq!(
            AppTheme::Monokai.text_important_color(),
            Color::Rgb(230, 219, 116)
        ); // Monokai yellow
        assert_eq!(
            AppTheme::Gruvbox.text_important_color(),
            Color::Rgb(250, 189, 47)
        ); // Gruvbox yellow
        assert_eq!(
            AppTheme::TokyoNight.text_important_color(),
            Color::Rgb(224, 175, 104)
        ); // Tokyo Night yellow
        assert_eq!(
            AppTheme::CatppuccinMocha.text_important_color(),
            Color::Rgb(249, 226, 175)
        ); // Catppuccin yellow
        assert_eq!(
            AppTheme::OneDark.text_important_color(),
            Color::Rgb(229, 192, 123)
        ); // One Dark yellow
        assert_eq!(
            AppTheme::AyuDark.text_important_color(),
            Color::Rgb(255, 204, 102)
        ); // Ayu Dark yellow
    }

    #[test]
    fn test_theme_sparkline_style() {
        assert_eq!(
            AppTheme::Default.sparkline_style(),
            Style::default().fg(Color::Yellow)
        );
        assert_eq!(
            AppTheme::MidnightGreen.sparkline_style(),
            Style::default().fg(Color::Green)
        );
        assert_eq!(
            AppTheme::IAmBlue.sparkline_style(),
            Style::default().fg(Color::Blue)
        );
        assert_eq!(
            AppTheme::SolarizedDark.sparkline_style(),
            Style::default().fg(Color::Rgb(133, 153, 0))
        ); // Solarized green
        assert_eq!(
            AppTheme::Greyscale.sparkline_style(),
            Style::default().fg(Color::Rgb(180, 180, 180))
        ); // Light grey
        assert_eq!(
            AppTheme::Nord.sparkline_style(),
            Style::default().fg(Color::Rgb(163, 190, 140))
        ); // Nord Aurora green
        assert_eq!(
            AppTheme::Dracula.sparkline_style(),
            Style::default().fg(Color::Rgb(139, 233, 253))
        ); // Dracula cyan
        assert_eq!(
            AppTheme::Monokai.sparkline_style(),
            Style::default().fg(Color::Rgb(102, 217, 239))
        ); // Monokai blue
        assert_eq!(
            AppTheme::Gruvbox.sparkline_style(),
            Style::default().fg(Color::Rgb(104, 157, 106))
        ); // Gruvbox aqua
        assert_eq!(
            AppTheme::TokyoNight.sparkline_style(),
            Style::default().fg(Color::Rgb(125, 207, 255))
        ); // Tokyo Night cyan
        assert_eq!(
            AppTheme::CatppuccinMocha.sparkline_style(),
            Style::default().fg(Color::Rgb(137, 220, 235))
        ); // Catppuccin sky
        assert_eq!(
            AppTheme::OneDark.sparkline_style(),
            Style::default().fg(Color::Rgb(86, 182, 194))
        ); // One Dark cyan
        assert_eq!(
            AppTheme::AyuDark.sparkline_style(),
            Style::default().fg(Color::Rgb(95, 175, 239))
        ); // Ayu Dark blue
    }
}
