use chrono::Local;
use iced::widget::{Column, button, container, row, scrollable, text};
use iced::{Element, Length};
use shared::ipc::{DetectionEvent, Verdict};
use std::collections::VecDeque;

use crate::app::Message;

pub fn view<'a>(
    detections: &'a VecDeque<DetectionEvent>,
    filter: &str,
    selected: Option<usize>,
) -> Element<'a, Message> {
    let filtered: Vec<(usize, &DetectionEvent)> = detections
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            if filter.is_empty() {
                true
            } else {
                d.process_info
                    .name
                    .to_lowercase()
                    .contains(&filter.to_lowercase())
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
        list = list.push(detection_row(detection, original_idx, is_selected));
    }

    scrollable(list).height(Length::Fill).into()
}

fn detection_row<'a>(
    detection: &'a DetectionEvent,
    index: usize,
    selected: bool,
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
            .style(move |_theme| text::Style {
                color: Some(verdict_color),
            }),
    ]
    .spacing(10)
    .padding(8);

    let btn = button(row_content)
        .on_press(Message::DetectionSelected(index))
        .width(Length::Fill)
        .style(move |_theme: &iced::Theme, status| {
            let base_color = if selected {
                iced::Color::from_rgb(0.2, 0.3, 0.4)
            } else {
                iced::Color::from_rgb(0.15, 0.15, 0.15)
            };

            let color = match status {
                button::Status::Hovered => iced::Color {
                    r: base_color.r + 0.05,
                    g: base_color.g + 0.05,
                    b: base_color.b + 0.05,
                    a: base_color.a,
                },
                _ => base_color,
            };

            button::Style {
                background: Some(iced::Background::Color(color)),
                border: iced::Border {
                    color: iced::Color::from_rgb(0.3, 0.3, 0.3),
                    width: 1.0,
                    radius: 0.0.into(),
                },
                text_color: iced::Color::WHITE,
                ..Default::default()
            }
        });

    btn.into()
}
