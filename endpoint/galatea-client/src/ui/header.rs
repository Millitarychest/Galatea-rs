use crate::app::{Message, ViewMode};
use crate::theme::AppTheme;
use iced::widget::{Space, button, column, container, row, text, text_input};
use iced::{Element, Length};

pub fn view(
    connected: bool,
    detection_count: usize,
    file_context_count: usize,
    filter: &'_ str,
    current_theme: AppTheme,
    paused: bool,
    pending_count: usize,
    view_mode: ViewMode,
    loading_file_contexts: bool,
) -> Element<'_, Message> {
    let status_indicator = if connected {
        text("●").style(|_theme| text::Style {
            color: Some(iced::Color::from_rgb(0.0, 0.8, 0.0)),
        })
    } else {
        text("●").style(|_theme| text::Style {
            color: Some(iced::Color::from_rgb(0.8, 0.0, 0.0)),
        })
    };

    let status_text = if connected {
        format!("Connected | {detection_count} detections | {file_context_count} files")
    } else {
        "Disconnected - waiting for agent...".to_string()
    };
    let filter_placeholder = match view_mode {
        ViewMode::Detections => "Filter by process name or PID...",
        ViewMode::FileContexts => "Filter by path, file index, process, or verdict...",
    };

    let header_content = row![
        // Left side: status
        status_indicator,
        text(status_text).size(14),
        // Spacer to push search to center
        Space::new().width(Length::Fill),
        button(
            container(text("Detections").size(12))
                .width(Length::Fixed(100.0))
                .center_x(Length::Fill)
        )
        .on_press(Message::ViewModeChanged(ViewMode::Detections))
        .style(move |theme: &iced::Theme, status| tab_button_style(
            theme,
            status,
            view_mode == ViewMode::Detections
        )),
        button(
            container(text("Files").size(12))
                .width(Length::Fixed(80.0))
                .center_x(Length::Fill)
        )
        .on_press(Message::ViewModeChanged(ViewMode::FileContexts))
        .style(move |theme: &iced::Theme, status| tab_button_style(
            theme,
            status,
            view_mode == ViewMode::FileContexts
        )),
        button(
            container(
                text(if loading_file_contexts {
                    "Refreshing"
                } else {
                    "Refresh"
                })
                .size(12)
            )
            .width(Length::Fixed(100.0))
            .center_x(Length::Fill)
        )
        .on_press(Message::RefreshFileContexts)
        .style(|theme: &iced::Theme, status| {
            button::Style {
                background: Some(iced::Background::Color(
                    theme.extended_palette().secondary.base.color,
                )),
                text_color: theme.palette().text,
                border: iced::Border {
                    radius: 6.0.into(),
                    ..Default::default()
                },
                ..button::primary(theme, status)
            }
        }),
        // Center: search bar with rounded corners
        text_input(filter_placeholder, filter)
            .on_input(Message::FilterChanged)
            .width(Length::Fixed(400.0))
            .padding(8)
            .style(|theme: &iced::Theme, status| {
                text_input::Style {
                    border: iced::Border {
                        color: theme.palette().primary,
                        width: 1.0,
                        radius: 8.0.into(),
                    },
                    ..text_input::default(theme, status)
                }
            }),
        // Small spacer
        Space::new().width(Length::Fixed(10.0)),
        // Pause button
        button(
            container(
                row![
                    text(if paused { "\u{f08d}" } else { "\u{e68f}" })
                        .font(iced::Font {
                            family: iced::font::Family::Name("Font Awesome 6 Free"),
                            weight: iced::font::Weight::Bold,
                            ..Default::default()
                        })
                        .size(12),
                    text(if paused {
                        if pending_count > 0 {
                            format!(" Paused ({})", pending_count)
                        } else {
                            " Paused".to_string()
                        }
                    } else {
                        " Live".to_string()
                    })
                    .size(12),
                ]
                .spacing(0)
            )
            .width(Length::Fixed(140.0))
            .center_x(Length::Fill)
        )
        .on_press(Message::TogglePause)
        .style(move |theme: &iced::Theme, status| {
            let bg_color = if paused {
                theme.palette().primary // Orange when paused
            } else {
                theme.extended_palette().secondary.base.color // Subtle when live
            };
            button::Style {
                background: Some(iced::Background::Color(bg_color)),
                text_color: if paused {
                    iced::Color::BLACK
                } else {
                    theme.palette().text
                },
                border: iced::Border {
                    radius: 6.0.into(),
                    ..Default::default()
                },
                ..button::primary(theme, status)
            }
        }),
        // Spacer to push theme button to right
        Space::new().width(Length::Fill),
        // Right side: theme button with fixed width
        button(
            container(text(format!("Theme: {}", current_theme.name())).size(12))
                .width(Length::Fixed(180.0))
                .center_x(Length::Fill)
        )
        .on_press(Message::ThemeChanged)
        .style(|theme: &iced::Theme, status| {
            button::Style {
                background: Some(iced::Background::Color(theme.palette().primary)),
                text_color: iced::Color::BLACK,
                border: iced::Border {
                    radius: 6.0.into(),
                    ..Default::default()
                },
                ..button::primary(theme, status)
            }
        }),
    ]
    .spacing(10)
    .padding(10)
    .align_y(iced::Alignment::Center);

    // Header with bottom border using column + separator
    column![
        container(header_content)
            .width(Length::Fill)
            .style(move |theme: &iced::Theme| container::Style {
                background: Some(iced::Background::Color(
                    theme.extended_palette().background.strong.color
                )),
                ..Default::default()
            }),
        // Bottom border as a thin colored container
        container(Space::new())
            .width(Length::Fill)
            .height(Length::Fixed(2.0))
            .style(move |theme: &iced::Theme| container::Style {
                background: Some(iced::Background::Color(theme.palette().primary)),
                ..Default::default()
            }),
    ]
    .spacing(0)
    .into()
}

fn tab_button_style(theme: &iced::Theme, status: button::Status, active: bool) -> button::Style {
    let background = if active {
        theme.palette().primary
    } else {
        theme.extended_palette().secondary.base.color
    };

    button::Style {
        background: Some(iced::Background::Color(background)),
        text_color: if active {
            iced::Color::BLACK
        } else {
            theme.palette().text
        },
        border: iced::Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..button::primary(theme, status)
    }
}
