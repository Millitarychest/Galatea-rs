use chrono::Local;
use galatea_shared::ipc::{
    FileContextKeySnapshot, FileContextSnapshot, FileFlagSnapshot, FileScanSummarySnapshot,
    FileVerdictSnapshot,
};
use iced::widget::{Column, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Padding, Theme};
use std::collections::HashSet;

use crate::app::Message;

pub fn view<'a>(
    file_contexts: &'a [FileContextSnapshot],
    filter: &str,
    loading: bool,
    status: Option<&'a str>,
    expanded: &'a HashSet<String>,
) -> Element<'a, Message> {
    if loading && file_contexts.is_empty() {
        return container(text("Refreshing file context cache...").size(16))
            .center(Length::Fill)
            .into();
    }

    let filtered: Vec<&FileContextSnapshot> = file_contexts
        .iter()
        .filter(|context| file_context_matches(context, filter))
        .collect();

    if filtered.is_empty() {
        let empty_text = if file_contexts.is_empty() {
            status.unwrap_or("No file contexts cached yet.")
        } else {
            "No file contexts match the filter."
        };

        return container(text(empty_text).size(16))
            .center(Length::Fill)
            .into();
    }

    let mut list = Column::new().spacing(2);
    list = list.push(header_row(status));

    for context in filtered {
        let expanded_key = expanded_key(context);
        list = list.push(file_context_row(
            context,
            expanded.contains(&expanded_key),
            expanded_key,
        ));
    }

    scrollable(list).height(Length::Fill).into()
}

fn header_row<'a>(status: Option<&'a str>) -> Element<'a, Message> {
    container(
        row![
            text("Last write").size(11).width(Length::Fixed(130.0)),
            text("Path").size(11).width(Length::FillPortion(4)),
            text("File index").size(11).width(Length::Fixed(130.0)),
            text("Verdict").size(11).width(Length::Fixed(110.0)),
            text("Flags").size(11).width(Length::Fixed(180.0)),
            text(status.unwrap_or(""))
                .size(11)
                .width(Length::Fixed(136.0)),
            text("").size(11).width(Length::Fixed(24.0)),
        ]
        .spacing(10)
        .padding(8),
    )
    .style(|theme: &iced::Theme| container::Style {
        background: Some(iced::Background::Color(
            theme.extended_palette().background.strong.color,
        )),
        ..Default::default()
    })
    .into()
}

fn file_context_row<'a>(
    context: &'a FileContextSnapshot,
    expanded: bool,
    expanded_key: String,
) -> Element<'a, Message> {
    let verdict = context
        .last_scan_summary
        .as_ref()
        .map(|summary| verdict_label(summary.verdict))
        .unwrap_or("Unscanned");
    let verdict_color = context
        .last_scan_summary
        .as_ref()
        .map(|summary| verdict_color(summary.verdict))
        .unwrap_or_else(|| iced::Color::from_rgb(0.5, 0.6, 0.7));

    let row_content = row![
        text(format_optional_time(context.last_write_time.as_ref()))
            .size(12)
            .width(Length::Fixed(130.0)),
        text(display_path(context))
            .size(12)
            .width(Length::FillPortion(4)),
        text(format_optional_u64(context.file_index))
            .size(12)
            .width(Length::Fixed(130.0)),
        text(verdict)
            .size(12)
            .width(Length::Fixed(110.0))
            .style(move |_theme: &Theme| text::Style {
                color: Some(verdict_color),
            }),
        text(format_flags(&context.matching_flags))
            .size(12)
            .width(Length::Fixed(180.0)),
        text("").size(12).width(Length::Fixed(136.0)),
        text(if expanded { "▼" } else { "▶" })
            .size(12)
            .width(Length::Fixed(24.0)),
    ]
    .spacing(10)
    .padding(8);

    let mut content = column![
        button(row_content)
            .on_press(Message::ToggleExpanded(expanded_key.clone()))
            .padding(0)
            .width(Length::Fill)
            .style(|theme: &iced::Theme, status| {
                let base_color = theme.extended_palette().background.base.color;
                let color = match status {
                    button::Status::Hovered => iced::Color {
                        r: (base_color.r + 0.05).min(1.0),
                        g: (base_color.g + 0.05).min(1.0),
                        b: (base_color.b + 0.05).min(1.0),
                        a: base_color.a,
                    },
                    button::Status::Active | button::Status::Pressed | button::Status::Disabled => {
                        base_color
                    }
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
        content = content.push(expanded_details(context));
    }

    content.into()
}

fn expanded_details<'a>(context: &'a FileContextSnapshot) -> Element<'a, Message> {
    let mut details = column![
        text("File Context")
            .size(14)
            .style(|theme: &Theme| text::Style {
                color: Some(theme.palette().primary),
            }),
        detail_row("Cache Key", format_key(&context.key)),
        detail_row("Path", display_path(context)),
        detail_row("File Index", format_optional_u64(context.file_index)),
        detail_row("Flags", format_flags(&context.matching_flags)),
    ]
    .spacing(6)
    .padding(Padding {
        top: 10.0,
        right: 20.0,
        bottom: 10.0,
        left: 20.0,
    });

    if let Some(process) = &context.last_write_process {
        details = details.push(detail_row("Last Writer", process.clone()));
    }
    details = details.push(detail_row(
        "Last Write",
        format_optional_time(context.last_write_time.as_ref()),
    ));
    details = details.push(detail_row(
        "Last Rename",
        format_optional_time(context.last_rename_time.as_ref()),
    ));
    if let Some(original_name) = &context.original_name {
        details = details.push(detail_row("Original Name", original_name.clone()));
    }
    if let Some(summary) = &context.last_scan_summary {
        details = details.push(scan_summary_details(summary));
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

fn scan_summary_details<'a>(summary: &'a FileScanSummarySnapshot) -> Element<'a, Message> {
    column![
        text("Latest Static Scan")
            .size(14)
            .style(|theme: &Theme| text::Style {
                color: Some(theme.palette().primary),
            }),
        detail_row("Verdict", verdict_label(summary.verdict).to_string()),
        detail_row("Threat Score", summary.threat_score.to_string()),
        detail_row("File Size", summary.file_size.to_string()),
        detail_row("Modified", format_time(&summary.mod_time)),
        detail_row("Scan File Index", format_optional_u64(summary.file_index)),
    ]
    .spacing(6)
    .into()
}

fn detail_row<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(
        row![
            text(format!("{label}: "))
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

fn file_context_matches(context: &FileContextSnapshot, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }

    let filter_lower = filter.to_lowercase();
    let path = display_path(context).to_lowercase();
    let key = format_key(&context.key).to_lowercase();
    let writer = context
        .last_write_process
        .as_deref()
        .unwrap_or("")
        .to_lowercase();
    let verdict = context
        .last_scan_summary
        .as_ref()
        .map(|summary| verdict_label(summary.verdict).to_lowercase())
        .unwrap_or_default();
    let flags = format_flags(&context.matching_flags).to_lowercase();

    path.contains(&filter_lower)
        || key.contains(&filter_lower)
        || writer.contains(&filter_lower)
        || verdict.contains(&filter_lower)
        || flags.contains(&filter_lower)
}

fn display_path(context: &FileContextSnapshot) -> String {
    context
        .normalized_file_path
        .clone()
        .unwrap_or_else(|| format_key(&context.key))
}

fn format_flags(flags: &[FileFlagSnapshot]) -> String {
    if flags.is_empty() {
        return "-".to_string();
    }

    flags
        .iter()
        .map(|flag| flag_label(*flag))
        .collect::<Vec<_>>()
        .join(", ")
}

fn flag_label(flag: FileFlagSnapshot) -> &'static str {
    match flag {
        FileFlagSnapshot::FileWriteSuccess => "FileWriteSuccess",
        FileFlagSnapshot::WhiteListed => "WhiteListed",
        FileFlagSnapshot::BlackListed => "BlackListed",
        FileFlagSnapshot::StaticScanMalicious => "StaticScanMalicious",
        FileFlagSnapshot::StaticScanSuspicious => "StaticScanSuspicious",
        FileFlagSnapshot::StaticScanBeneign => "StaticScanBeneign",
        FileFlagSnapshot::InAutoStartLocation => "InAutoStartLocation",
        FileFlagSnapshot::InTempLocation => "InTempLocation",
        FileFlagSnapshot::RenamedToExecutable => "RenamedToExecutable",
        FileFlagSnapshot::FileCreateSuccess => "FileCreated",
    }
}

fn format_key(key: &FileContextKeySnapshot) -> String {
    match key {
        FileContextKeySnapshot::FileIndex(file_index) => format!("file-index:{file_index:#x}"),
        FileContextKeySnapshot::Path(path) => path.clone(),
    }
}

fn expanded_key(context: &FileContextSnapshot) -> String {
    format!("file-context:{}", format_key(&context.key))
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| format!("{value:#x}"))
        .unwrap_or_else(|| "-".to_string())
}

fn format_optional_time(time: Option<&chrono::DateTime<chrono::Utc>>) -> String {
    time.map(format_time).unwrap_or_else(|| "-".to_string())
}

fn format_time(time: &chrono::DateTime<chrono::Utc>) -> String {
    time.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn verdict_label(verdict: FileVerdictSnapshot) -> &'static str {
    match verdict {
        FileVerdictSnapshot::Benign => "Benign",
        FileVerdictSnapshot::Suspicious => "Suspicious",
        FileVerdictSnapshot::Malicious => "Malicious",
    }
}

fn verdict_color(verdict: FileVerdictSnapshot) -> iced::Color {
    match verdict {
        FileVerdictSnapshot::Benign => iced::Color::from_rgb(0.2, 0.8, 0.2),
        FileVerdictSnapshot::Suspicious => iced::Color::from_rgb(0.9, 0.7, 0.0),
        FileVerdictSnapshot::Malicious => iced::Color::from_rgb(0.9, 0.2, 0.2),
    }
}
