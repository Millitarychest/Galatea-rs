use iced::widget::{column, container};
use iced::{Element, Task, Theme};
use shared::ipc::{DetectionEvent, IpcMessage};
use std::collections::{HashSet, VecDeque};

use crate::ipc_client::{IpcClient, IpcClientMessage};
use crate::theme::AppTheme;
use crate::ui;

const MAX_DETECTIONS: usize = 1000;

pub struct GalateaGui {
    ipc_client: IpcClient,
    connected: bool,
    detections: VecDeque<DetectionEvent>,
    pending_detections: VecDeque<DetectionEvent>,
    selected_detection: Option<usize>,
    expanded_events: HashSet<String>,
    filter_text: String,
    current_theme: AppTheme,
    paused: bool,
}

#[derive(Debug, Clone)]
pub enum Message {
    IpcEvent(IpcClientMessage),
    FilterChanged(String),
    DetectionSelected(usize),
    ToggleExpanded(String),
    ThemeChanged,
    TogglePause,
    Tick,
}

impl Default for GalateaGui {
    fn default() -> Self {
        GalateaGui {
            ipc_client: IpcClient::start(),
            connected: false,
            detections: VecDeque::new(),
            pending_detections: VecDeque::new(),
            selected_detection: None,
            expanded_events: HashSet::new(),
            filter_text: String::new(),
            current_theme: AppTheme::default(),
            paused: false,
        }
    }
}

impl GalateaGui {
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::IpcEvent(event) => {
                match event {
                    IpcClientMessage::Connected => {
                        self.connected = true;
                    }
                    IpcClientMessage::Disconnected => {
                        self.connected = false;
                    }
                    IpcClientMessage::Message(IpcMessage::Detection(detection)) => {
                        // If paused, add to pending; otherwise add to visible detections
                        if self.paused {
                            self.pending_detections.push_front(detection);
                            // Keep pending list from growing too large
                            if self.pending_detections.len() > MAX_DETECTIONS {
                                self.pending_detections.pop_back();
                            }
                        } else {
                            self.detections.push_front(detection);
                            // Keep only last MAX_DETECTIONS
                            if self.detections.len() > MAX_DETECTIONS {
                                self.detections.pop_back();
                            }
                        }
                    }
                    IpcClientMessage::Message(_) => {
                        // Other message types (StatusUpdate, ConfigUpdate) - ignore for now
                    }
                }
            }
            Message::FilterChanged(text) => {
                self.filter_text = text;
            }
            Message::DetectionSelected(index) => {
                self.selected_detection = Some(index);
            }
            Message::ToggleExpanded(event_id) => {
                if self.expanded_events.contains(&event_id) {
                    self.expanded_events.remove(&event_id);
                } else {
                    self.expanded_events.insert(event_id);
                    // Auto-pause when expanding an event
                    if !self.paused {
                        self.paused = true;
                    }
                }
            }
            Message::ThemeChanged => {
                self.current_theme = self.current_theme.next();
            }
            Message::TogglePause => {
                self.paused = !self.paused;
                // When unpausing, move all pending detections to visible list
                if !self.paused {
                    while let Some(detection) = self.pending_detections.pop_back() {
                        self.detections.push_front(detection);
                    }
                    // Trim to MAX_DETECTIONS
                    while self.detections.len() > MAX_DETECTIONS {
                        self.detections.pop_back();
                    }
                }
            }
            Message::Tick => {
                // Poll IPC client for new messages
                while let Some(event) = self.ipc_client.try_recv() {
                    return self.update(Message::IpcEvent(event));
                }
            }
        }

        Task::none()
    }

    pub fn view(&'_ self) -> Element<'_, Message> {
        let content = column![
            ui::header::view(
                self.connected,
                self.detections.len(),
                &self.filter_text,
                self.current_theme,
                self.paused,
                self.pending_detections.len()
            ),
            ui::detection_list::view(
                &self.detections,
                &self.filter_text,
                self.selected_detection,
                &self.expanded_events
            ),
        ]
        .spacing(0);

        container(content)
            .width(iced::Length::Fill)
            .height(iced::Length::Fill)
            .into()
    }

    pub fn subscription(&self) -> iced::Subscription<Message> {
        // Poll for IPC messages every 100ms
        use iced::futures::stream;
        use std::time::Duration;

        iced::Subscription::run(|| {
            stream::unfold((), |_| async {
                async_std::task::sleep(Duration::from_millis(100)).await;
                Some((Message::Tick, ()))
            })
        })
    }

    pub fn theme(&self) -> Theme {
        self.current_theme.to_iced_theme()
    }
}
