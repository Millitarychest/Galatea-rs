#![windows_subsystem = "windows"]
mod app;
mod ipc_client;
mod theme;
mod ui;

use app::GalateaGui;

// Embed FontAwesome Solid font
const FONT_AWESOME_SOLID: &[u8] = include_bytes!("../assets/fonts/fa-solid-900.ttf");

fn main() -> iced::Result {
    iced::application(
        || (GalateaGui::default(), iced::Task::none()),
        GalateaGui::update,
        GalateaGui::view,
    )
    .subscription(GalateaGui::subscription)
    .theme(GalateaGui::theme)
    .font(FONT_AWESOME_SOLID)
    .window_size((1200.0, 800.0))
    .run()
}
