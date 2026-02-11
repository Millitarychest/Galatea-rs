use chrono::Local;
use iced::widget::{Column, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Padding, Theme};
use shared::ipc::{DetectionEvent, Verdict};
use std::collections::{HashSet, VecDeque};

use crate::app::Message;

pub fn view<'a>(
    detections: &'a VecDeque<DetectionEvent>,
    filter: &str,
    selected: Option<usize>,
    expanded: &'a HashSet<String>,
) -> Element<'a, Message> {
    let filtered: Vec<(usize, &DetectionEvent)> = detections
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            if filter.is_empty() {
                true
            } else {
                let filter_lower = filter.to_lowercase();
                d.process_info.name.to_lowercase().contains(&filter_lower)
                    || d.process_info.pid.to_string().contains(&filter_lower)
            }
        })
        .collect();

    if filtered.is_empty() {
        return container(
            text(if detections.is_empty() {
                "No detections yet. Waiting for events from agent..."
            } else {
                "No detections match the filter."
            })
            .size(16),
        )
        .center(Length::Fill)
        .into();
    }

    let mut list = Column::new().spacing(2);

    for (original_idx, detection) in filtered {
        let is_selected = selected == Some(original_idx);
        let is_expanded = expanded.contains(&detection.event_id.to_string());
        list = list.push(detection_row(
            detection,
            original_idx,
            is_selected,
            is_expanded,
        ));
    }

    scrollable(list).height(Length::Fill).into()
}

fn detection_row<'a>(
    detection: &'a DetectionEvent,
    _index: usize,
    selected: bool,
    expanded: bool,
) -> Element<'a, Message> {
    let timestamp = detection.timestamp.with_timezone(&Local).format("%H:%M:%S");
    let verdict_color = match detection.verdict {
        Verdict::Blocked => iced::Color::from_rgb(0.9, 0.2, 0.2),
        Verdict::Allowed => {
            if detection.detection.threat_score > 50 {
                iced::Color::from_rgb(0.9, 0.7, 0.0) // Yellow for suspicious
            } else {
                iced::Color::from_rgb(0.2, 0.8, 0.2) // Green for clean
            }
        }
    };

    let verdict_text = match detection.verdict {
        Verdict::Blocked => "BLOCKED",
        Verdict::Allowed => "ALLOWED",
    };

    let row_content = row![
        text(format!("{}", timestamp))
            .size(12)
            .width(Length::Fixed(80.0)),
        text(&detection.process_info.name)
            .size(12)
            .width(Length::Fixed(200.0)),
        text(format!("PID: {}", detection.process_info.pid))
            .size(12)
            .width(Length::Fixed(100.0)),
        text(format!("Score: {}", detection.detection.threat_score))
            .size(12)
            .width(Length::Fixed(100.0)),
        text(verdict_text)
            .size(12)
            .style(move |_theme: &iced::Theme| text::Style {
                color: Some(verdict_color),
            }),
        text(if expanded { "▼" } else { "▶" })
            .size(12)
            .width(Length::Fixed(30.0)),
    ]
    .spacing(10)
    .padding(8);

    let mut content_column = column![
        button(row_content)
            .on_press(Message::ToggleExpanded(detection.event_id.to_string()))
            .width(Length::Fill)
            .style(move |theme: &iced::Theme, status| {
                let base_color = if selected {
                    // Selected: slightly lighter than background
                    let bg = theme.extended_palette().background.base.color;
                    iced::Color {
                        r: (bg.r + 0.1).min(1.0),
                        g: (bg.g + 0.1).min(1.0),
                        b: (bg.b + 0.1).min(1.0),
                        a: bg.a,
                    }
                } else {
                    // Normal: use theme background
                    theme.extended_palette().background.base.color
                };

                let color = match status {
                    button::Status::Hovered => iced::Color {
                        r: (base_color.r + 0.05).min(1.0),
                        g: (base_color.g + 0.05).min(1.0),
                        b: (base_color.b + 0.05).min(1.0),
                        a: base_color.a,
                    },
                    _ => base_color,
                };

                button::Style {
                    background: Some(iced::Background::Color(color)),
                    text_color: theme.palette().text,
                    border: iced::Border {
                        color: theme.extended_palette().background.strong.color,
                        width: 1.0,
                        radius: 0.0.into(),
                    },
                    ..Default::default()
                }
            })
    ];

    if expanded {
        content_column = content_column.push(expanded_details(detection));
    }

    content_column.into()
}

fn expanded_details<'a>(detection: &'a DetectionEvent) -> Element<'a, Message> {
    let mut details = column![].spacing(6).padding(Padding {
        top: 10.0,
        right: 20.0,
        bottom: 10.0,
        left: 20.0,
    });

    // Process Information
    details =
        details.push(
            text("Process Information")
                .size(14)
                .style(|theme: &Theme| text::Style {
                    color: Some(theme.palette().primary),
                }),
        );

    details = details.push(detail_row("Path", detection.process_info.path.clone()));

    if let Some(ref cmd) = detection.process_info.command_line {
        details = details.push(detail_row("Command Line", cmd.clone()));
    }

    if let Some(parent_pid) = detection.process_info.parent_pid {
        details = details.push(detail_row("Parent PID", parent_pid.to_string()));
    }

    if let Some(creation_time) = detection.process_info.creation_time {
        let time_str = creation_time
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        details = details.push(detail_row("Created", time_str));
    }

    // Hash Information
    if let Some(ref md5) = detection.detection.md5_hash {
        details =
            details.push(
                text("Hash Information")
                    .size(14)
                    .style(|theme: &Theme| text::Style {
                        color: Some(theme.palette().primary),
                    }),
            );
        details = details.push(detail_row("MD5", md5.clone()));
    }

    // Signature Match
    if let Some(ref sig) = detection.detection.signature_match {
        details = details.push(
            text("Signature Match")
                .size(14)
                .style(|_theme: &iced::Theme| text::Style {
                    color: Some(iced::Color::from_rgb(0.9, 0.5, 0.5)),
                }),
        );
        details = details.push(detail_row("Hash", sig.hash.clone()));
        details = details.push(detail_row("Score", sig.verdict_score.to_string()));
        details = details.push(detail_row("Metadata", sig.metadata.clone()));
    }

    // Authenticode
    if let Some(ref auth) = detection.detection.authenticode {
        details = details.push(
            text("Authenticode Information")
                .size(14)
                .style(|theme: &Theme| text::Style {
                    color: Some(theme.palette().primary),
                }),
        );
        details = details.push(detail_row(
            "Signed",
            if auth.is_signed { "Yes" } else { "No" }.to_string(),
        ));
        details = details.push(detail_row(
            "Trusted",
            if auth.is_trusted { "Yes" } else { "No" }.to_string(),
        ));
        details = details.push(detail_row(
            "Revoked",
            if auth.is_revoked { "Yes" } else { "No" }.to_string(),
        ));
        if let Some(ref signer) = auth.signer {
            details = details.push(detail_row("Signer", signer.clone()));
        }
        details = details.push(detail_row(
            "Score Modifier",
            auth.score_modifier.to_string(),
        ));
    }

    // Heuristics
    if let Some(ref heur) = detection.detection.heuristics {
        details = details.push(
            text("Heuristic Analysis")
                .size(14)
                .style(|_theme: &iced::Theme| text::Style {
                    color: Some(iced::Color::from_rgb(0.9, 0.7, 0.5)),
                }),
        );
        details = details.push(detail_row(
            "Packed",
            if heur.is_packed { "Yes" } else { "No" }.to_string(),
        ));
        if let Some(ref packer) = heur.packer_name {
            details = details.push(detail_row("Packer", packer.clone()));
        }
        details = details.push(detail_row(
            "RWX Sections",
            if heur.has_rwx_sections { "Yes" } else { "No" }.to_string(),
        ));
        details = details.push(detail_row(
            "High Entropy",
            if heur.high_entropy { "Yes" } else { "No" }.to_string(),
        ));
        if let Some(ref imphash) = heur.imphash {
            details = details.push(detail_row("ImpHash", imphash.clone()));
        }
        details = details.push(detail_row(
            "Score Modifier",
            heur.score_modifier.to_string(),
        ));
    }

    // ML Prediction
    if let Some(ref ml) = detection.detection.ml_prediction {
        details = details.push(
            text("ML Prediction")
                .size(14)
                .style(|_theme: &Theme| text::Style {
                    color: Some(iced::Color::from_rgb(0.7, 0.5, 0.9)),
                }),
        );
        details = details.push(detail_row(
            "Malicious Probability",
            format!("{:.2}%", ml.malicious_probability * 100.0),
        ));
        details = details.push(detail_row("Score Modifier", ml.score_modifier.to_string()));
    }

    container(details)
        .style(|theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(
                theme.extended_palette().background.weak.color,
            )),
            border: iced::Border {
                color: theme.extended_palette().background.strong.color,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

fn detail_row<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(
        row![
            text(format!("{}: ", label))
                .size(11)
                .width(Length::Fixed(150.0))
                .style(|_theme: &iced::Theme| text::Style {
                    color: Some(iced::Color::from_rgb(0.6, 0.6, 0.6)),
                }),
            text_input("", &value)
                .size(11)
                .padding(0)
                .style(|_theme: &iced::Theme, _status| text_input::Style {
                    background: iced::Background::Color(iced::Color::TRANSPARENT),
                    border: iced::Border::default(),
                    icon: iced::Color::TRANSPARENT,
                    placeholder: iced::Color::TRANSPARENT,
                    value: iced::Color::from_rgb(0.95, 0.95, 0.95),
                    selection: iced::Color::from_rgba(0.3, 0.5, 0.8, 0.5),
                })
        ]
        .spacing(8)
        .padding(Padding {
            top: 4.0,
            right: 8.0,
            bottom: 4.0,
            left: 8.0,
        }),
    )
    .style(|theme: &iced::Theme| container::Style {
        background: Some(iced::Background::Color(
            theme.extended_palette().background.base.color,
        )),
        border: iced::Border {
            color: theme.extended_palette().background.strong.color,
            width: 0.5,
            radius: 2.0.into(),
        },
        ..Default::default()
    })
    .padding(Padding {
        top: 2.0,
        right: 0.0,
        bottom: 2.0,
        left: 0.0,
    })
    .into()
}
