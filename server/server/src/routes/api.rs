use axum::{Json, extract::Path, http::StatusCode};
use serde_json::{Value, json};

use crate::{config::AGENT_PSK, db, state::AppContext};
use api_definition::{AgentAuthentication, AgentCommandAck, AgentHeartbeat, AgentRegistration};

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

    if let Err(e) = db::agent_db::register_agent(&AppContext::global().db_pool, &registration) {
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
    Path(id): Path<String>,
    Json(body): Json<AgentHeartbeat>,
) -> (StatusCode, Json<Value>) {
    if !validate_psk(&body.auth) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid PSK" })),
        );
    }
    
    let agent_id = body.uuid.to_string();
    if id != agent_id{
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid Json-Body" })),
        );
    }

    if let Err(e) = db::agent_db::update_heartbeat(&AppContext::global().db_pool, &agent_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to update heartbeat: {}", e) })),
        );
    }

    let commands = match db::commands_db::get_pending_commands(&AppContext::global().db_pool, &agent_id) {
        Ok(cmds) => cmds,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to get pending commands: {}", e) })),
            );
        }
    };

    for cmd in &commands {
        let _ = db::commands_db::mark_command_delivered(&AppContext::global().db_pool, &cmd.command_id);
    }

    (
        StatusCode::OK,
        Json(json!({
            "server_time": chrono::Utc::now().to_rfc3339(),
            "pending_commands": commands.iter().map(|c| json!({
                "command_id": c.command_id,
                "command_type": c.command_type,
                "payload": c.payload_json.as_ref().map(|s| serde_json::from_str::<Value>(s).ok()).flatten()
            })).collect::<Vec<_>>()
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
    Path((id, cmd_id)): Path<(String, String)>,
    Json(body): Json<AgentCommandAck>,
) -> (StatusCode, Json<Value>) {
    if !validate_psk(&body.auth) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid PSK" })),
        );
    }
    let agent_id = body.uuid.to_string();
    let body_cmd_id = body.command_id.to_string();
    if id != agent_id || cmd_id != body_cmd_id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid Json-Body" })),
        );
    }

    if let Err(e) = db::commands_db::complete_command(&AppContext::global().db_pool, &cmd_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to register agent: {}", e) })),
        );
    }

    (StatusCode::OK, Json(json!("")))
}
