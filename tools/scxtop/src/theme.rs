// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use ratatui::style::{Color, Style};
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
