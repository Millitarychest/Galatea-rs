use axum::{Json, extract::Path, http::StatusCode};
use serde_json::{Value, json};

use crate::{config::AGENT_PSK, db, state::AppContext};
use api_definition::{AgentAuthentication, AgentRegistration};

fn validate_psk(auth: &AgentAuthentication) -> bool {
    auth.psk == AGENT_PSK
}

/// POST /api/v1/agents/register
pub async fn handle_register(Json(registration): Json<AgentRegistration>) -> (StatusCode, Json<serde_json::Value>) {
    if !validate_psk(&registration.auth) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid PSK" })),
        );
    }

    if let Err(e) = db::register_agent(&AppContext::global().db_pool, &registration) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to register agent: {}", e) })),
        );
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "agent_id": registration.uuid.to_string()
        })),
    )
}

/// POST /api/v1/agents/{id}/heartbeat
pub async fn handle_heartbeat(
    Path(_id): Path<String>,
    Json(_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // TODO: Update last_heartbeat_at in database
    // TODO: Query pending commands for this agent

    (
        StatusCode::OK,
        Json(json!({
            "server_time": chrono::Utc::now().to_rfc3339(),
            "pending_commands": []
        })),
    )
}

/// POST /api/v1/agents/{id}/telemetry
pub async fn handle_telemetry(
    Path(_id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let event_count = body
        .get("events")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // TODO: Store events in database

    (
        StatusCode::OK,
        Json(json!({
            "accepted": event_count,
            "rejected": 0
        })),
    )
}

/// POST /api/v1/agents/{id}/commands/{cmd_id}/ack
pub async fn handle_command_ack(
    Path((_id, _cmd_id)): Path<(String, String)>,
    Json(_body): Json<Value>,
) -> StatusCode {
    // TODO: Update command status in database

    StatusCode::OK
}
