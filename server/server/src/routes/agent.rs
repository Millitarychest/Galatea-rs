use axum::extract::Path;
use axum::response::Html;

use super::layout;

/// GET /agents/{id} — Agent detail page
pub async fn serve_agent(Path(id): Path<String>) -> Html<String> {
    let content = include_str!("../../web/agent.html").replace("{id}", &id);
    layout::page("Agent Detail", "", &content)
}
