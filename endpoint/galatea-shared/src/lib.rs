#![no_std]
#![deny(missing_docs)]

//! Defines IPC / IOCTL Interface for on endpoint communication

#[cfg(any(feature = "client_ipc", feature = "agent_ipc"))]
extern crate alloc;

// Agent and driver

/// Agent IOCTL request for current process creation events
pub const IOCTL_GET_EVENT: u32 = 0x80002000;
/// Agent IOCTL response for sending process creation verdict
pub const IOCTL_SEND_VERDICT: u32 = 0x80002004;
/// Agent IOCTL to register the agent with the driver
pub const IOCTL_REGISTER_AGENT: u32 = 0x80002008;

/// Struct used to send a process creation event via IOCTL
#[repr(C)]
pub struct GalateaEvent {
    /// Process ID
    pub process_id: u64,
    /// Request ID used for tracking of verdicts in kernel mode
    pub request_id: u64,
    /// Was the process frozen by the kernel
    pub frozen: bool,
    /// Image Path of the process
    pub image_path: [u16; 260],
}

/// Struct used to send a process creation verdict via IOCTL
#[repr(C)]
pub struct GalateaVerdict {
    /// Process ID
    pub process_id: u64,
    /// Request ID used for tracking of verdicts in kernel mode
    pub request_id: u64,
    /// Should the kernel allow the process creation
    pub allow: bool,
}

// Agent and Client
/// Module containing usermode IPC definitions
#[cfg(any(feature = "client_ipc", feature = "agent_ipc"))]
pub mod ipc {
    use alloc::string::String;

    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    #[cfg(feature = "agent_ipc")]
    use uuid::Uuid;

    /// Named Pipe Identifier used for agent - client IPC
    pub const PIPE_NAME: &str = "\\\\.\\pipe\\galatea_client_events";
    /// Named Pipe Configuration item "Buffer size" used for agent - client IPC
    pub const PIPE_BUFFER_SIZE: u32 = 65536; // 64KB buffer
    /// Named Pipe Configuration item "timeout" used for agent - client IPC
    pub const PIPE_TIMEOUT_MS: u32 = 5000;


    /// Struct used in agent IPC broadcast, containing all relavent detection information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DetectionEvent {
        /// Unique event identifier
        #[cfg(feature = "agent_ipc")]
        pub event_id: Uuid,
        /// Unique event identifier
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

    /// Struct used in agent IPC broadcast, containing information about the inspected broadcast
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProcessInfo {
        ///Process ID
        pub pid: u64,
        ///Process Name
        pub name: String,
        ///Image Path
        pub path: String,
        ///Parent Process (when available)
        pub parent_pid: Option<u64>,
        ///Command Line (when available)
        pub command_line: Option<String>,
        ///Timestamp
        pub creation_time: Option<DateTime<Utc>>,
    }

    /// Struct used in agent IPC broadcast, containing information about the verdicts of the different engine steps
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

    /// Struct used in agent IPC broadcast, containing the known bad check result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignatureMatch {
        /// Matched IOC
        pub hash: String,
        /// Change in Threat score
        pub verdict_score: i32,
        /// Description of the IOC
        pub metadata: String,
    }

    /// Struct used in agent IPC broadcast, containing the authenticode check result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthenticodeInfo {
        /// was the image signed?
        pub is_signed: bool,
        /// was the signer trusted?
        pub is_trusted: bool,
        /// was the cert revoked?
        pub is_revoked: bool,
        /// Name of the signer
        pub signer: Option<String>,
        /// Change in Threat score
        pub score_modifier: i32,
    }

    /// Struct used in agent IPC broadcast, containing the heuristics check result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HeuristicResults {
        /// Was a packer found
        pub is_packed: bool,
        /// Information about the fond packer
        pub packer_name: Option<String>,
        /// Section with RWX permission found
        pub has_rwx_sections: bool,
        /// is the entropy unusual 
        pub high_entropy: bool,
        /// Imphash of the binary
        pub imphash: Option<String>,
        /// Change in Threat score
        pub score_modifier: i32,
    }

    /// Struct used in agent IPC broadcast, containing the ml classifier result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MlPrediction {
        /// Certainty that the binary is malicious
        pub malicious_probability: f32,
        /// Change in Threat score
        pub score_modifier: i32,
    }

    /// Enum used in agent IPC broadcast, representing the final engine verdict
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub enum Verdict {
        /// Process creation allowed
        Allowed,
        /// Process creation blocked
        Blocked,
    }

    /// IPC message types
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum IpcMessage {
        /// Detection event from agent
        Detection(DetectionEvent),

        /// Agent status update
        StatusUpdate { 
            /// Message - to be defined
            message: String 
        },

        /// Configuration change notification
        ConfigUpdate { 
            /// Message - to be defined
            message: String 
        },
    }
}
