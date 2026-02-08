#![no_std]

#[cfg(any(feature = "client_ipc", feature = "agent_ipc"))]
extern crate alloc;

// Agent and driver

pub const IOCTL_GET_EVENT: u32 = 0x80002000;
pub const IOCTL_SEND_VERDICT: u32 = 0x80002004;
pub const IOCTL_REGISTER_AGENT: u32 = 0x80002008;

#[repr(C)]
pub struct GalateaEvent {
    pub process_id: u64,
    pub request_id: u64,
    pub frozen: bool,
    pub image_path: [u16; 260],
}

#[repr(C)]
pub struct GalateaVerdict {
    pub process_id: u64,
    pub request_id: u64,
    pub allow: bool,
}

// Agent and Client
#[cfg(any(feature = "client_ipc", feature = "agent_ipc"))]
pub mod ipc {
    use alloc::string::String;

    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    #[cfg(feature = "agent_ipc")]
    use uuid::Uuid;

    pub const PIPE_NAME: &str = "\\\\.\\pipe\\galatea_client_events";
    pub const PIPE_BUFFER_SIZE: u32 = 65536; // 64KB buffer
    pub const PIPE_TIMEOUT_MS: u32 = 5000;


    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DetectionEvent {
        /// Unique event identifier
        #[cfg(feature = "agent_ipc")]
        pub event_id: Uuid,
        #[cfg(not(feature = "agent_ipc"))]
        pub event_id: String,

        /// Timestamp when event was created
        pub timestamp: DateTime<Utc>,

        /// Process information
        pub process_info: ProcessInfo,

        /// Detection details
        pub detection: DetectionDetails,

        /// Final verdict
        pub verdict: Verdict,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProcessInfo {
        pub pid: u64,
        pub name: String,
        pub path: String,
        pub parent_pid: Option<u64>,
        pub command_line: Option<String>,
        pub creation_time: Option<DateTime<Utc>>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DetectionDetails {
        /// Overall threat score (0-100+)
        pub threat_score: i32,

        /// Hash information
        pub md5_hash: Option<String>,

        /// Signature-based detections
        pub signature_match: Option<SignatureMatch>,

        /// Authenticode signature info
        pub authenticode: Option<AuthenticodeInfo>,

        /// Heuristic analysis results
        pub heuristics: Option<HeuristicResults>,

        /// ML prediction
        pub ml_prediction: Option<MlPrediction>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignatureMatch {
        pub hash: String,
        pub verdict_score: i32,
        pub metadata: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthenticodeInfo {
        pub is_signed: bool,
        pub is_trusted: bool,
        pub is_revoked: bool,
        pub signer: Option<String>,
        pub score_modifier: i32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HeuristicResults {
        pub is_packed: bool,
        pub packer_name: Option<String>,
        pub has_rwx_sections: bool,
        pub high_entropy: bool,
        pub imphash: Option<String>,
        pub score_modifier: i32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MlPrediction {
        pub malicious_probability: f32,
        pub score_modifier: i32,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub enum Verdict {
        Allowed,
        Blocked,
    }

    /// IPC message types
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum IpcMessage {
        /// Detection event from agent
        Detection(DetectionEvent),

        /// Agent status update
        StatusUpdate { message: String },

        /// Configuration change notification
        ConfigUpdate { message: String },
    }
}
