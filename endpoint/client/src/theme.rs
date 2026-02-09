use iced::{Color, Theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTheme {
    Dark,
    Light,
    Dracula,
    Nord,
    SolarizedLight,
    SolarizedDark,
    GruvboxLight,
    GruvboxDark,
    CatppuccinLatte,
    CatppuccinFrappe,
    CatppuccinMacchiato,
    CatppuccinMocha,
    TokyoNight,
    TokyoNightStorm,
    TokyoNightLight,
    KanagawaWave,
    KanagawaDragon,
    KanagawaLotus,
    Moonfly,
    Nightfly,
    Oxocarbon,
    Ferra,
    DefenderExplorer,
}

impl AppTheme {
    pub fn next(&self) -> Self {
        match self {
            AppTheme::Dark => AppTheme::Light,
            AppTheme::Light => AppTheme::Dracula,
            AppTheme::Dracula => AppTheme::Nord,
            AppTheme::Nord => AppTheme::SolarizedLight,
            AppTheme::SolarizedLight => AppTheme::SolarizedDark,
            AppTheme::SolarizedDark => AppTheme::GruvboxLight,
            AppTheme::GruvboxLight => AppTheme::GruvboxDark,
            AppTheme::GruvboxDark => AppTheme::CatppuccinLatte,
            AppTheme::CatppuccinLatte => AppTheme::CatppuccinFrappe,
            AppTheme::CatppuccinFrappe => AppTheme::CatppuccinMacchiato,
            AppTheme::CatppuccinMacchiato => AppTheme::CatppuccinMocha,
            AppTheme::CatppuccinMocha => AppTheme::TokyoNight,
            AppTheme::TokyoNight => AppTheme::TokyoNightStorm,
            AppTheme::TokyoNightStorm => AppTheme::TokyoNightLight,
            AppTheme::TokyoNightLight => AppTheme::KanagawaWave,
            AppTheme::KanagawaWave => AppTheme::KanagawaDragon,
            AppTheme::KanagawaDragon => AppTheme::KanagawaLotus,
            AppTheme::KanagawaLotus => AppTheme::Moonfly,
            AppTheme::Moonfly => AppTheme::Nightfly,
            AppTheme::Nightfly => AppTheme::Oxocarbon,
            AppTheme::Oxocarbon => AppTheme::Ferra,
            AppTheme::Ferra => AppTheme::DefenderExplorer,
            AppTheme::DefenderExplorer => AppTheme::Dark,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            AppTheme::Dark => "Dark",
            AppTheme::Light => "Light",
            AppTheme::Dracula => "Dracula",
            AppTheme::Nord => "Nord",
            AppTheme::SolarizedLight => "Solarized Light",
            AppTheme::SolarizedDark => "Solarized Dark",
            AppTheme::GruvboxLight => "Gruvbox Light",
            AppTheme::GruvboxDark => "Gruvbox Dark",
            AppTheme::CatppuccinLatte => "Catppuccin Latte",
            AppTheme::CatppuccinFrappe => "Catppuccin Frappe",
            AppTheme::CatppuccinMacchiato => "Catppuccin Macchiato",
            AppTheme::CatppuccinMocha => "Catppuccin Mocha",
            AppTheme::TokyoNight => "Tokyo Night",
            AppTheme::TokyoNightStorm => "Tokyo Night Storm",
            AppTheme::TokyoNightLight => "Tokyo Night Light",
            AppTheme::KanagawaWave => "Kanagawa Wave",
            AppTheme::KanagawaDragon => "Kanagawa Dragon",
            AppTheme::KanagawaLotus => "Kanagawa Lotus",
            AppTheme::Moonfly => "Moonfly",
            AppTheme::Nightfly => "Nightfly",
            AppTheme::Oxocarbon => "Oxocarbon",
            AppTheme::Ferra => "Ferra",
            AppTheme::DefenderExplorer => "Defender Explorer",
        }
    }

    pub fn to_iced_theme(&self) -> Theme {
        match self {
            AppTheme::Dark => Theme::Dark,
            AppTheme::Light => Theme::Light,
            AppTheme::Dracula => Theme::Dracula,
            AppTheme::Nord => Theme::Nord,
            AppTheme::SolarizedLight => Theme::SolarizedLight,
            AppTheme::SolarizedDark => Theme::SolarizedDark,
            AppTheme::GruvboxLight => Theme::GruvboxLight,
            AppTheme::GruvboxDark => Theme::GruvboxDark,
            AppTheme::CatppuccinLatte => Theme::CatppuccinLatte,
            AppTheme::CatppuccinFrappe => Theme::CatppuccinFrappe,
            AppTheme::CatppuccinMacchiato => Theme::CatppuccinMacchiato,
            AppTheme::CatppuccinMocha => Theme::CatppuccinMocha,
            AppTheme::TokyoNight => Theme::TokyoNight,
            AppTheme::TokyoNightStorm => Theme::TokyoNightStorm,
            AppTheme::TokyoNightLight => Theme::TokyoNightLight,
            AppTheme::KanagawaWave => Theme::KanagawaWave,
            AppTheme::KanagawaDragon => Theme::KanagawaDragon,
            AppTheme::KanagawaLotus => Theme::KanagawaLotus,
            AppTheme::Moonfly => Theme::Moonfly,
            AppTheme::Nightfly => Theme::Nightfly,
            AppTheme::Oxocarbon => Theme::Oxocarbon,
            AppTheme::Ferra => Theme::Ferra,
            AppTheme::DefenderExplorer => Self::defender_explorer_theme(),
        }
    }

    fn defender_explorer_theme() -> Theme {
        Theme::custom(
            "Defender Explorer".to_string(),
            iced::theme::Palette {
                background: Color::from_rgb(0.04, 0.04, 0.04), // #0a0a0a
                text: Color::from_rgb(0.95, 0.95, 0.95),
                primary: Color::from_rgb(1.0, 0.58, 0.0), // #ff9500 orange
                success: Color::from_rgb(0.2, 0.8, 0.2),
                danger: Color::from_rgb(0.9, 0.2, 0.2),
                warning: Color::from_rgb(0.9, 0.7, 0.0), // Yellow for warnings
            },
        )
    }
}

impl Default for AppTheme {
    fn default() -> Self {
        AppTheme::DefenderExplorer
    }
}
