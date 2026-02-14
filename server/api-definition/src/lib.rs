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
    #[serde(default = "default_telemetry_schema_version")]
    pub schema_version: u16,
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
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum TelemetryEvent {
    Process(ProcessTelemetryEvent),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryVerdict {
    Allowed,
    Blocked,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProcessTelemetryEvent {
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub process_id: u64,
    pub parent_process_id: Option<u64>,
    pub image_path: String,
    pub command_line: Option<String>,
    pub md5_hash: Option<String>,
    pub threat_score: Option<i32>,
    pub verdict: TelemetryVerdict,
}

impl TelemetryEvent {
    pub fn event_id(&self) -> Uuid {
        match self {
            Self::Process(event) => event.event_id,
        }
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        match self {
            Self::Process(event) => event.occurred_at,
        }
    }

    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Process(_) => "process",
        }
    }
}

fn default_telemetry_schema_version() -> u16 {
    1
}
