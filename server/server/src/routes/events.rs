use axum::response::Html;

use super::layout;

/// GET /events — All events across fleet
pub async fn serve_events() -> Html<String> {
    let content = include_str!("../../web/events.html");
    layout::page("Event Feed", "events", content)
}
