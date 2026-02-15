use axum::{http::StatusCode, response::Html};
use api_definition::{TelemetryEvent, TelemetryVerdict};

use super::layout;
use crate::db::telemetry_db::{self, TelemetryListItem};
use crate::state::AppContext;
use crate::utils::fmt::format_timestamp;

/// GET /events - All events across fleet
pub async fn serve_events() -> (StatusCode, Html<String>) {
    let context = match AppContext::ensure_global() {
        Ok(context) => context,
        Err(e) => {
            mimic_core::mimic_log!("Failed to acquire AppContext for events: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Html("Service unavailable".to_string()),
            );
        }
    };

    let events = telemetry_db::get_recent_events(&context.db_pool, 200).unwrap_or_default();
    let content = render_events_content(&events);
    (
        StatusCode::OK,
        layout::page(
            "Event Feed",
            "events",
            &context.config.agent_registration_secret,
            &content,
        ),
    )
}

fn render_events_content(events: &[TelemetryListItem]) -> String {
    let mut allowed_count = 0usize;
    let mut blocked_count = 0usize;

    let rows = if events.is_empty() {
        r#"<tr>
                <td colspan="6">
                    <div class="empty-state">
                        <div class="icon">[!]</div>
                        <p>No events recorded yet. Events will appear here once agents report telemetry.</p>
                    </div>
                </td>
            </tr>"#
        .to_string()
    } else {
        events
            .iter()
            .map(|event| render_event_row(event, &mut allowed_count, &mut blocked_count))
            .collect::<String>()
    };

    include_str!("../../web/events.html")
        .replace("{total_events}", &events.len().to_string())
        .replace("{blocked_count}", &blocked_count.to_string())
        .replace("{allowed_count}", &allowed_count.to_string())
        .replace("{event_rows}", &rows)
}

fn render_event_row(
    event: &TelemetryListItem,
    allowed_count: &mut usize,
    blocked_count: &mut usize,
) -> String {
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
                    *allowed_count += 1;
                    (name, process.process_id.to_string(), score, "allowed", "allowed")
                }
                TelemetryVerdict::Blocked => {
                    *blocked_count += 1;
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

    let hostname = event
        .agent_hostname
        .as_deref()
        .filter(|h| !h.is_empty())
        .unwrap_or("unknown");
    let short_id = if event.agent_id.len() > 8 {
        &event.agent_id[..8]
    } else {
        &event.agent_id
    };

    format!(
        r#"<tr data-event-id="{event_id}">
            <td>{timestamp}</td>
            <td><a href="/agents/{agent_id}" class="table-link">{hostname}</a> <code class="mono">{short_id}</code></td>
            <td><code class="mono">{process_name}</code></td>
            <td><code class="mono">{pid}</code></td>
            <td><span class="threat-score">{threat_score}</span></td>
            <td><span class="badge {verdict_class}">{verdict_text}</span></td>
        </tr>"#,
        event_id = escape_html(&event.event_id),
        timestamp = escape_html(&format_timestamp(&event.occurred_at)),
        agent_id = escape_html(&event.agent_id),
        hostname = escape_html(hostname),
        short_id = escape_html(short_id),
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
