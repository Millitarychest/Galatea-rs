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

// Agent and Filter
/// Module containing communication-port structures used by the filesystem filter.
pub mod filter_port {
    /// Maximum payload bytes carried by one filter communication-port message.
    pub const FILTER_PORT_PAYLOAD_SIZE: usize = 2048;

    /// Message kind sent over the filter communication port.
    #[repr(u32)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GalateaFilterMessageKind {
        /// Raw proof-of-concept payload.
        Raw = 0,
        /// Filesystem telemetry payload.
        FileTelemetry = 1,
    }

    impl Default for GalateaFilterMessageKind {
        fn default() -> Self {
            Self::Raw
        }
    }

    /// Message payload sent from the filesystem filter to the agent.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct GalateaFilterMessage {
        /// Message kind discriminator.
        pub kind: GalateaFilterMessageKind,
        /// Number of valid bytes in [`payload`](Self::payload).
        pub payload_len: u32,
        /// Fixed-size payload buffer.
        pub payload: [u8; FILTER_PORT_PAYLOAD_SIZE],
    }

    impl Default for GalateaFilterMessage {
        fn default() -> Self {
            Self {
                kind: GalateaFilterMessageKind::Raw,
                payload_len: 0,
                payload: [0; FILTER_PORT_PAYLOAD_SIZE],
            }
        }
    }

    /// Struct used to send File System Events via IOCTL
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct GalateaFSEvent {
        /// Process ID as Fallback
        pub process_id: u64,
        /// Process Start ID, this should be a quasi uuid
        pub process_start_key: u64,
        /// Request ID used for tracking of verdicts in kernel mode
        pub request_id: u64,
        /// Type of the File System Event
        pub event_type: FSEventType,
        /// Targeted File Path
        pub file_path: [u16; 260],
        /// NTFS file index
        pub file_index: u64,
    }

    /// Enum used to represent the different actions that might be taken on a File
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub enum FSEventType {
        /// A file handle was opened
        FileOpen,
        /// A file was created
        FileCreate,
        /// A file was written to
        FileWrite,
        /// A file was renamed or its metadata was changed
        FileModify(FSModOperation),
        /// A file was marked for deletion
        FileDelete,
    }

    /// Metadata-changing filesystem operations.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub enum FSModOperation {
        /// A file rename was requested.
        Rename(RenameMeta),
    }

    /// Metadata captured from a file rename request.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct RenameMeta {
        /// Rename flags supplied by the caller.
        pub flags: u32,
        /// Requested new file path or name.
        pub new_file_path: [u16; 260],
    }
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
    /// Named Pipe Identifier used for agent - client request/response IPC
    pub const COMMAND_PIPE_NAME: &str = "\\\\.\\pipe\\galatea_client_commands";
    /// Named Pipe Configuration item "Buffer size" used for agent - client IPC
    pub const PIPE_BUFFER_SIZE: u32 = 65536; // 64KB buffer
    /// Named Pipe Configuration item "timeout" used for agent - client IPC
    pub const PIPE_TIMEOUT_MS: u32 = 5000;

    /// Stable cache key rendered for client display.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum FileContextKeySnapshot {
        /// NTFS file index key.
        FileIndex(u64),
        /// Canonicalized path fallback key.
        Path(String),
    }

    /// File reputation verdict stored with the latest scan summary.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub enum FileVerdictSnapshot {
        /// No suspicious static analysis signal.
        Benign,
        /// Static analysis found suspicious traits.
        Suspicious,
        /// Static analysis crossed the blocking threshold.
        Malicious,
    }

    /// Serializable static scan summary for a file context entry.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FileScanSummarySnapshot {
        /// Simplified file reputation verdict.
        pub verdict: FileVerdictSnapshot,
        /// Static analysis threat score.
        pub threat_score: i32,
        /// File size observed at scan time.
        pub file_size: u64,
        /// File modification time observed at scan time.
        pub mod_time: DateTime<Utc>,
        /// NTFS file index observed at scan time.
        pub file_index: Option<u64>,
    }

    /// Serializable file context flag for GUI display.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub enum FileFlagSnapshot {
        /// A file write completed successfully.
        FileWriteSuccess,
        /// File is explicitly allowlisted.
        WhiteListed,
        /// File is explicitly blocklisted.
        BlackListed,
        /// Static analysis classified the file as malicious.
        StaticScanMalicious,
        /// Static analysis classified the file as suspicious.
        StaticScanSuspicious,
        /// Static analysis classified the file as benign.
        StaticScanBeneign,
        /// File is in a file-based autostart location.
        InAutoStartLocation,
        /// File is in a temporary file location.
        InTempLocation,
        /// File was renamed to an executable extension.
        RenamedToExecutable,
    }

    /// Serializable snapshot of one file context cache entry.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FileContextSnapshot {
        /// Cache key used for lookup.
        pub key: FileContextKeySnapshot,
        /// Current normalized file path when known.
        pub normalized_file_path: Option<String>,
        /// NTFS file index when known.
        pub file_index: Option<u64>,
        /// Process image responsible for the latest write when known.
        pub last_write_process: Option<String>,
        /// Timestamp of the latest observed write.
        pub last_write_time: Option<DateTime<Utc>>,
        /// Timestamp of the latest observed rename.
        pub last_rename_time: Option<DateTime<Utc>>,
        /// Original file name before rename when known.
        pub original_name: Option<String>,
        /// Matching file context flags.
        pub matching_flags: alloc::vec::Vec<FileFlagSnapshot>,
        /// Latest static scan summary when known.
        pub last_scan_summary: Option<FileScanSummarySnapshot>,
    }

    /// Request messages sent by the GUI to the agent command pipe.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum IpcRequest {
        /// Request a bounded file context cache snapshot.
        GetFileContextSnapshot {
            /// Maximum number of entries to return.
            limit: usize,
        },
    }

    /// Response messages sent by the agent command pipe to the GUI.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum IpcResponse {
        /// Bounded file context cache snapshot.
        FileContextSnapshot {
            /// Snapshot entries.
            entries: alloc::vec::Vec<FileContextSnapshot>,
        },
        /// Command failed.
        Error {
            /// Human-readable error message.
            message: String,
        },
    }

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
        /// Allowlisted system process — no scan performed
        SystemAllowed,
    }

    /// IPC message types
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum IpcMessage {
        /// Detection event from agent
        Detection(DetectionEvent),

        /// Agent status update
        StatusUpdate {
            /// Message - to be defined
            message: String,
        },

        /// Configuration change notification
        ConfigUpdate {
            /// Message - to be defined
            message: String,
        },
    }
}
