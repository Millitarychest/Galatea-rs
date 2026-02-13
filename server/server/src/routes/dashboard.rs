use axum::response::Html;

use super::layout;

/// GET / — Fleet overview dashboard
pub async fn serve_dashboard() -> Html<String> {
    let content = include_str!("../../web/dashboard.html");
    layout::page("Fleet Overview", "fleet", content)
}
