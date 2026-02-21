use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::Html;
use babel_api_definition::{TelemetryEvent, TelemetryVerdict};

use crate::db::agent_db::{get_agent_by_id, AgentInfo};
use crate::db::telemetry_db;
use crate::state::AppContext;
use crate::utils::fmt::format_timestamp;
use super::layout;

/// GET /agents/{id} - Agent detail page
pub async fn serve_agent(Path(id): Path<String>) -> (StatusCode, Html<String>) {
    let context = match AppContext::ensure_global() {
        Ok(context) => context,
        Err(e) => {
            mimic_core::mimic_log!("Failed to acquire AppContext for agent page: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Html("Service unavailable".to_string()),
            );
        }
    };

    let agent = get_agent_by_id(&context.db_pool, &id).unwrap_or(None);

    let content = if let Some(agent) = agent {
        render_agent_content(&agent, context)
    } else {
        render_agent_not_found(&id)
    };

    (
        StatusCode::OK,
        layout::page(
            "Agent Detail",
            "",
            &context.config.agent_registration_secret,
            &content,
        ),
    )
}

fn render_agent_content(agent: &AgentInfo, context: &AppContext) -> String {
    let events = telemetry_db::get_recent_events_for_agent(&context.db_pool, &agent.agent_id, 100)
        .unwrap_or_default();
    let short_id = if agent.agent_id.len() > 8 {
        &agent.agent_id[..8]
    } else {
        &agent.agent_id
    };
    let timeline_rows = render_timeline_rows(&events);

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
        .replace(
            "{last_heartbeat}",
            &agent
                .last_heartbeat_at
                .as_deref()
                .map(format_timestamp)
                .unwrap_or_else(|| "Never".to_string()),
        )
        .replace("{timeline_rows}", &timeline_rows)
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

fn render_timeline_rows(events: &[telemetry_db::TelemetryListItem]) -> String {
    if events.is_empty() {
        return r#"<tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="icon">📋</div>
                        <p>No events for this agent yet.</p>
                    </div>
                </td>
            </tr>"#
        .to_string();
    }

    events
        .iter()
        .map(render_timeline_row)
        .collect::<String>()
}

fn render_timeline_row(event: &telemetry_db::TelemetryListItem) -> String {
    let parsed = serde_json::from_str::<TelemetryEvent>(&event.payload_json).ok();
    let (process_name, process_id, threat_score, verdict_text, verdict_class) = match parsed {
        Some(TelemetryEvent::Process(process)) => {
            let name = process
                .image_path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(process.image_path.as_str())
                .to_string();
            let score = process
                .threat_score
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());

            match process.verdict {
                TelemetryVerdict::Allowed => {
                    (name, process.process_id.to_string(), score, "allowed", "allowed")
                }
                TelemetryVerdict::Blocked => {
                    (name, process.process_id.to_string(), score, "blocked", "blocked")
                }
            }
        }
        None => {
            let fallback_process = if event.event_type.is_empty() {
                "unknown".to_string()
            } else {
                event.event_type.clone()
            };
            (
                fallback_process,
                "-".to_string(),
                "-".to_string(),
                "unknown",
                "allowed",
            )
        }
    };

    format!(
        r#"<tr data-event-id="{event_id}">
            <td>{timestamp}</td>
            <td><code class="mono">{process_name}</code></td>
            <td><code class="mono">{pid}</code></td>
            <td><span class="threat-score">{threat_score}</span></td>
            <td><span class="badge {verdict_class}">{verdict_text}</span></td>
        </tr>"#,
        event_id = escape_html(&event.event_id),
        timestamp = escape_html(&format_timestamp(&event.occurred_at)),
        process_name = escape_html(&process_name),
        pid = escape_html(&process_id),
        threat_score = escape_html(&threat_score),
        verdict_class = escape_html(verdict_class),
        verdict_text = escape_html(verdict_text),
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
