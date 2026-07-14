#![deny(missing_docs)]

//! API interface definitions for endpoint to server communication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secrets::{Secret, expose_secret};

/// Module provides a "Secret" wrapper type used to redact PII or sensitive info in logging
pub mod secrets;

////////////Agent Api Body/////////////

/// Agent registration payload sent when an agent enrolls with the server.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentRegistration {
    /// Stable agent identifier.
    pub uuid: Uuid,
    /// Host metadata reported by the agent.
    pub host_info: AgentHostInfo,
    /// Authentication material used to authorize the request.
    #[serde(serialize_with = "expose_secret")]
    pub auth: Secret<AgentAuthentication>,
}

/// Agent heartbeat payload used for liveness and command polling.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentHeartbeat {
    /// Stable agent identifier.
    pub uuid: Uuid,
    /// Authentication material used to authorize the request.
    #[serde(serialize_with = "expose_secret")]
    pub auth: Secret<AgentAuthentication>,
}

/// Telemetry upload payload containing one or more events.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentTelemetry {
    /// Stable agent identifier.
    pub uuid: Uuid,
    /// Authentication material used to authorize the request.
    #[serde(serialize_with = "expose_secret")]
    pub auth: Secret<AgentAuthentication>,
    /// Telemetry schema version used by the sender.
    #[serde(default = "default_telemetry_schema_version")]
    pub schema_version: u16,
    /// Events included in this upload batch.
    pub events: Vec<TelemetryEvent>,
}

/// Command acknowledgement payload sent by agents after command execution.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentCommandAck {
    /// Stable agent identifier.
    pub uuid: Uuid,
    /// Authentication material used to authorize the request.
    #[serde(serialize_with = "expose_secret")]
    pub auth: Secret<AgentAuthentication>,
    /// Identifier of the acknowledged command.
    pub command_id: Uuid,
    /// Whether command handling succeeded.
    pub success: bool,
    /// Optional human-readable message describing execution outcome.
    pub message: Option<String>,
}

////////////Info Components/////////////

/// Authentication values supplied by an agent.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentAuthentication {
    /// Pre-shared key configured for enrollment and API access.
    pub psk: String,
}

/// Host metadata reported by an agent.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentHostInfo {
    /// Host name of the endpoint.
    pub hostname: String,
    /// OS version string reported by the endpoint.
    pub os_version: String,
    /// Agent version running on the endpoint.
    pub agent_version: String,
    /// Optional IP address if available at collection time.
    pub ip_address: Option<String>,
}

/// Supported telemetry event envelope variants.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum TelemetryEvent {
    /// Process execution telemetry event.
    Process(ProcessTelemetryEvent),
}

/// Final action taken by the agent for a telemetry item.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryVerdict {
    /// The process or action was allowed.
    Allowed,
    /// The process or action was blocked.
    Blocked,
}

/// Detailed telemetry data for process-related events.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProcessTelemetryEvent {
    /// Unique event identifier.
    pub event_id: Uuid,
    /// Event timestamp in UTC.
    pub occurred_at: DateTime<Utc>,
    /// Process identifier.
    pub process_id: u64,
    /// Parent process identifier if known.
    pub parent_process_id: Option<u64>,
    /// Full executable image path.
    pub image_path: String,
    /// Full command line when available.
    pub command_line: Option<String>,
    /// MD5 hash of the executable when available.
    pub md5_hash: Option<String>,
    /// Optional computed threat score.
    pub threat_score: Option<i32>,
    /// Final allow/block verdict for this process.
    pub verdict: TelemetryVerdict,
}

impl TelemetryEvent {
    /// Returns the unique identifier of this event.
    pub fn event_id(&self) -> Uuid {
        match self {
            Self::Process(event) => event.event_id,
        }
    }

    /// Returns the UTC timestamp when this event occurred.
    pub fn occurred_at(&self) -> DateTime<Utc> {
        match self {
            Self::Process(event) => event.occurred_at,
        }
    }

    /// Returns the normalized event type name.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Process(_) => "process",
        }
    }
}

/// Default schema version used when one is not specified by the sender.
fn default_telemetry_schema_version() -> u16 {
    1
}
