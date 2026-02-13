use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

////////////Agent Api Body/////////////

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentRegistration {
    pub uuid: Uuid,
    pub host_info: AgentHostInfo,
    pub auth: AgentAuthentication,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentHeartbeat {
    pub uuid: Uuid,
    pub auth: AgentAuthentication,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentTelemetry {
    pub uuid: Uuid,
    pub auth: AgentAuthentication,
    pub events: Vec<TelemetryEvent>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentCommandAck {
    pub uuid: Uuid,
    pub auth: AgentAuthentication,
    pub command_id: Uuid,
    pub success: bool,
    pub message: Option<String>,
}

////////////Info Components/////////////

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentAuthentication {
    pub psk: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentHostInfo {
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
    pub ip_address: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TelemetryEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
}

