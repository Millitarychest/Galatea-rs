use axum::response::Html;

use crate::db::{get_all_agents, AgentInfo, AgentStatus};
use crate::state::AppContext;
use crate::utils::fmt::format_timestamp;
use super::layout;

/// GET / — Fleet overview dashboard
pub async fn serve_dashboard() -> Html<String> {
    let context = AppContext::global();
    let agents = match get_all_agents(&context.db_pool) {
        Ok(agents) => agents,
        Err(_) => vec![],
    };

    let content = render_dashboard_content(&agents);
    layout::page("Fleet Overview", "fleet", &content)
}

fn render_dashboard_content(agents: &[AgentInfo]) -> String {
    let total = agents.len();
    let online = agents.iter().filter(|a| a.status == AgentStatus::Online).count();
    let offline = agents.iter().filter(|a| a.status == AgentStatus::Offline).count();
    let stale = agents.iter().filter(|a| a.status == AgentStatus::Stale).count();

    let table_rows = if agents.is_empty() {
        r#"<tr>
            <td colspan="7">
                <div class="empty-state">
                    <div class="icon">📡</div>
                    <p>No agents registered yet. Deploy an agent to get started.</p>
                </div>
            </td>
        </tr>"#.to_string()
    } else {
        agents.iter()
            .map(|agent| {
                let last_heartbeat = agent.last_heartbeat_at.as_deref().map(format_timestamp).unwrap_or_else(|| "Never".to_string());
                let short_id = if agent.agent_id.len() > 8 { 
                    &agent.agent_id[..8] 
                } else { 
                    &agent.agent_id 
                };
                format!(
                    r#"<tr>
                        <td>
                            <span class="status">
                                <span class="status-dot {}"></span>
                                {}
                            </span>
                        </td>
                        <td><a href="/agents/{}" class="table-link">{}</a></td>
                        <td><code class="mono">{}</code></td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>"#,
                    agent.status.class(),
                    agent.status.as_str(),
                    agent.agent_id, agent.hostname,
                    short_id,
                    agent.os_version,
                    agent.agent_version,
                    agent.ip_address,
                    last_heartbeat
                )
            })
            .collect::<String>()
    };

    include_str!("../../web/dashboard.html")
        .replace("{total_agents}", &total.to_string())
        .replace("{online_count}", &online.to_string())
        .replace("{stale_count}", &stale.to_string())
        .replace("{offline_count}", &offline.to_string())
        .replace("{agent_rows}", &table_rows)
}
