use iced::widget::{column, container};
use iced::{Element, Task, Theme};
use shared::ipc::{DetectionEvent, IpcMessage};
use std::collections::VecDeque;

use crate::ipc_client::{IpcClient, IpcClientMessage};
use crate::ui;

const MAX_DETECTIONS: usize = 1000;

pub struct GalateaGui {
    ipc_client: IpcClient,
    connected: bool,
    detections: VecDeque<DetectionEvent>,
    selected_detection: Option<usize>,
    filter_text: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    IpcEvent(IpcClientMessage),
    FilterChanged(String),
    DetectionSelected(usize),
    Tick,
}

impl Default for GalateaGui {
    fn default() -> Self {
        GalateaGui {
            ipc_client: IpcClient::start(),
            connected: false,
            detections: VecDeque::new(),
            selected_detection: None,
            filter_text: String::new(),
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
                        self.detections.push_front(detection);

                        // Keep only last MAX_DETECTIONS
                        if self.detections.len() > MAX_DETECTIONS {
                            self.detections.pop_back();
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
            Message::Tick => {
                // Poll IPC client for new messages
                while let Some(event) = self.ipc_client.try_recv() {
                    return self.update(Message::IpcEvent(event));
                }
            }
        }

        Task::none()
    }

    pub fn view(&self) -> Element<Message> {
        let content = column![
            ui::header::view(self.connected, self.detections.len(), &self.filter_text),
            ui::detection_list::view(&self.detections, &self.filter_text, self.selected_detection),
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
        Theme::Dark
    }
}
