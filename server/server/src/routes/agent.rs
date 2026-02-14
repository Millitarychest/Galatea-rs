use axum::extract::Path;
use axum::response::Html;

use crate::db::agent_db::{get_agent_by_id, AgentInfo};
use crate::state::AppContext;
use crate::utils::fmt::format_timestamp;
use super::layout;



/// GET /agents/{id} — Agent detail page
pub async fn serve_agent(Path(id): Path<String>) -> Html<String> {
    let context = AppContext::global();
    let agent = get_agent_by_id(&context.db_pool, &id).unwrap_or(None);

    let content = if let Some(agent) = agent {
        render_agent_content(&agent)
    } else {
        render_agent_not_found(&id)
    };

    layout::page("Agent Detail", "", &content)
}

fn render_agent_content(agent: &AgentInfo) -> String {
    let short_id = if agent.agent_id.len() > 8 {
        &agent.agent_id[..8]
    } else {
        &agent.agent_id
    };

    include_str!("../../web/agent.html")
        .replace("{short_id}", short_id)
        .replace("{id}", &agent.agent_id)
        .replace("{hostname}", &agent.hostname)
        .replace("{status_class}", agent.status.as_str())
        .replace("{status}", agent.status.as_str())
        .replace("{os_version}", &agent.os_version)
        .replace("{agent_version}", &agent.agent_version)
        .replace("{ip_address}", &agent.ip_address)
        .replace("{registered_at}", &format_timestamp(&agent.registered_at))
        .replace("{last_heartbeat}", &agent.last_heartbeat_at.as_deref().map(format_timestamp).unwrap_or_else(|| "Never".to_string()))
}

fn render_agent_not_found(id: &str) -> String {
    format!(
        r#"<div class="breadcrumb">
            <a href="/">Fleet</a>
            <span class="separator">›</span>
            <span>Agent Not Found</span>
        </div>

        <div class="page-header">
            <h2>Agent Not Found</h2>
            <p>No agent found with ID: <span class="mono">{}</span></p>
        </div>

        <div class="empty-state">
            <div class="icon">❓</div>
            <p>The agent you're looking for doesn't exist or hasn't been registered yet.</p>
        </div>"#,
        id
    )
}
