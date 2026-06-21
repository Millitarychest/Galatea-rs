use axum::{Json, extract::Path, http::StatusCode};
use serde_json::{Value, json};

use crate::{config::AGENT_PSK, db, state::AppContext};
use babel_api_definition::{
    AgentAuthentication, AgentCommandAck, AgentHeartbeat, AgentRegistration, AgentTelemetry,
};

fn validate_psk(auth: &AgentAuthentication) -> bool {
    auth.psk == AGENT_PSK
}

fn service_unavailable(message: String) -> (StatusCode, Json<Value>) {
    mimic_core::mimic_log!("AppContext unavailable: {}", message);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "Service unavailable", "details": message })),
    )
}

fn context_or_503() -> Result<&'static AppContext, (StatusCode, Json<Value>)> {
    AppContext::ensure_global().map_err(service_unavailable)
}

/// POST /api/v1/agents/register
pub async fn handle_register(
    Json(registration): Json<AgentRegistration>,
) -> (StatusCode, Json<serde_json::Value>) {
    let context = match context_or_503() {
        Ok(context) => context,
        Err(response) => return response,
    };

    if !validate_psk(&registration.auth.expose_secret()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid PSK" })),
        );
    }

    if let Err(e) = db::agent_db::register_agent(&context.db_pool, &registration) {
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
    let context = match context_or_503() {
        Ok(context) => context,
        Err(response) => return response,
    };

    if !validate_psk(&body.auth.expose_secret()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid PSK" })),
        );
    }

    let agent_id = body.uuid.to_string();
    if id != agent_id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid Json-Body" })),
        );
    }

    if let Err(e) = db::agent_db::update_heartbeat(&context.db_pool, &agent_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to update heartbeat: {}", e) })),
        );
    }

    let commands = match db::commands_db::get_pending_commands(&context.db_pool, &agent_id) {
        Ok(cmds) => cmds,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to get pending commands: {}", e) })),
            );
        }
    };

    for cmd in &commands {
        let _ = db::commands_db::mark_command_delivered(&context.db_pool, &cmd.command_id);
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
    Path(id): Path<String>,
    Json(body): Json<AgentTelemetry>,
) -> (StatusCode, Json<Value>) {
    let context = match context_or_503() {
        Ok(context) => context,
        Err(response) => return response,
    };

    if !validate_psk(&body.auth.expose_secret()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid PSK" })),
        );
    }

    let agent_id = body.uuid.to_string();
    if id != agent_id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid Json-Body" })),
        );
    }

    let accepted = match db::telemetry_db::insert_events(&context.db_pool, &agent_id, &body.events)
    {
        Ok(inserted) => inserted,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to store telemetry events: {}", e) })),
            );
        }
    };
    let rejected = body.events.len().saturating_sub(accepted);

    (
        StatusCode::OK,
        Json(json!({
            "accepted": accepted,
            "rejected": rejected
        })),
    )
}

/// POST /api/v1/agents/{id}/commands/{cmd_id}/ack
pub async fn handle_command_ack(
    Path((id, cmd_id)): Path<(String, String)>,
    Json(body): Json<AgentCommandAck>,
) -> (StatusCode, Json<Value>) {
    let context = match context_or_503() {
        Ok(context) => context,
        Err(response) => return response,
    };

    if !validate_psk(&body.auth.expose_secret()) {
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

    if let Err(e) = db::commands_db::complete_command(&context.db_pool, &cmd_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to register agent: {}", e) })),
        );
    }

    (StatusCode::OK, Json(json!("")))
}
