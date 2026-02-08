use crate::app::Message;
use iced::widget::{container, row, text, text_input};
use iced::{Element, Length};

pub fn view(connected: bool, detection_count: usize, filter: &str) -> Element<Message> {
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
        format!("Connected | {} detections", detection_count)
    } else {
        "Disconnected - waiting for agent...".to_string()
    };

    let header_content = row![
        status_indicator,
        text(status_text).size(14),
        text_input("Filter by process name...", filter)
            .on_input(Message::FilterChanged)
            .width(Length::Fixed(300.0)),
    ]
    .spacing(10)
    .padding(10);

    container(header_content)
        .width(Length::Fill)
        .style(|_theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgb(
                0.1, 0.1, 0.1,
            ))),
            border: iced::Border {
                color: iced::Color::from_rgb(0.3, 0.3, 0.3),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}
