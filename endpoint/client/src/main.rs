mod app;
mod ipc_client;
mod ui;

use app::GalateaGui;

fn main() -> iced::Result {
    iced::application(
        || (GalateaGui::default(), iced::Task::none()),
        GalateaGui::update,
        GalateaGui::view,
    )
    .subscription(GalateaGui::subscription)
    .theme(GalateaGui::theme)
    .window_size((1200.0, 800.0))
    .run()
}
