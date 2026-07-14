use galatea_shared::ipc::{DetectionEvent, FileContextSnapshot, IpcMessage};
use iced::futures::stream;
use iced::widget::{column, container};
use iced::{Element, Task, Theme};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use crate::ipc_client::{IpcClient, IpcClientMessage};
use crate::theme::AppTheme;
use crate::ui;

const MAX_DETECTIONS: usize = 1000;
const FILE_CONTEXT_SNAPSHOT_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Detections,
    FileContexts,
}

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
    view_mode: ViewMode,
    file_contexts: Vec<FileContextSnapshot>,
    file_context_status: Option<String>,
    loading_file_contexts: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Message {
    IpcEvent(IpcClientMessage),
    FilterChanged(String),
    DetectionSelected(usize),
    ToggleExpanded(String),
    ThemeChanged,
    TogglePause,
    ViewModeChanged(ViewMode),
    RefreshFileContexts,
    FileContextsLoaded(Result<Vec<FileContextSnapshot>, String>),
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
            view_mode: ViewMode::Detections,
            file_contexts: Vec::new(),
            file_context_status: None,
            loading_file_contexts: false,
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
                    if matches!(self.view_mode, ViewMode::Detections) && !self.paused {
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
            Message::ViewModeChanged(view_mode) => {
                self.view_mode = view_mode;
                self.filter_text.clear();
                if matches!(view_mode, ViewMode::FileContexts) && self.file_contexts.is_empty() {
                    return self.refresh_file_contexts();
                }
            }
            Message::RefreshFileContexts => {
                return self.refresh_file_contexts();
            }
            Message::FileContextsLoaded(result) => {
                self.loading_file_contexts = false;
                match result {
                    Ok(entries) => {
                        let count = entries.len();
                        self.file_contexts = entries;
                        self.file_context_status = Some(format!("{count} cached files"));
                    }
                    Err(e) => {
                        self.file_context_status = Some(e);
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
        let body = match self.view_mode {
            ViewMode::Detections => ui::detection_list::view(
                &self.detections,
                &self.filter_text,
                self.selected_detection,
                &self.expanded_events,
            ),
            ViewMode::FileContexts => ui::file_context_list::view(
                &self.file_contexts,
                &self.filter_text,
                self.loading_file_contexts,
                self.file_context_status.as_deref(),
                &self.expanded_events,
            ),
        };

        let content = column![
            ui::header::view(
                self.connected,
                self.detections.len(),
                self.file_contexts.len(),
                &self.filter_text,
                self.current_theme,
                self.paused,
                self.pending_detections.len(),
                self.view_mode,
                self.loading_file_contexts,
            ),
            body,
        ]
        .spacing(0);

        container(content)
            .width(iced::Length::Fill)
            .height(iced::Length::Fill)
            .into()
    }

    pub fn subscription(&self) -> iced::Subscription<Message> {
        // Poll for IPC messages every 100ms

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

    fn refresh_file_contexts(&mut self) -> Task<Message> {
        if self.loading_file_contexts {
            return Task::none();
        }

        self.loading_file_contexts = true;
        self.file_context_status = Some("Refreshing file context cache...".to_string());

        Task::perform(
            async {
                async_std::task::spawn_blocking(|| {
                    IpcClient::request_file_context_snapshot(FILE_CONTEXT_SNAPSHOT_LIMIT)
                })
                .await
            },
            Message::FileContextsLoaded,
        )
    }
}
