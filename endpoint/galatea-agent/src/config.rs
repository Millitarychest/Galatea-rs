// Temporary file to hold config globals
// should eventually be moved to external file with easier mod

// SERVER INFO
pub const SERVER_URI: &str = "http://localhost:80";
pub const AGENT_PSK: &str = "galatea_secret";

// NAMES
pub const DRIVER_SERVICE_NAME: &str = "Galatea";
pub const DRIVER_FILE_NAME: &str = "driver/galatea_kernel_sensor.sys";
pub const DB_FILE_NAME: &str = "galatea_dataset.db";
pub const HOOK_FILE_NAME: &str = "galatea_userland_hooks.dll";

// ACTION THRESHOLDS
pub const STAT_BLOCK_THRESHOLD: i32 = 80;
pub const STAT_SUSPICIOUS_THRESHOLD: i32 = 50;
/// Maximum seconds to wait for an in-flight scan before falling through.
/// Must be shorter than the kernel freeze APC timeout (5 s).
pub const SCAN_WAIT_TIMEOUT_SECS: u64 = 4;

// UI OPTIONS
/// When true, allowlisted system processes are reported to the UI (no verdict / no scan).
pub const SHOW_SYSTEM_PROCESSES: bool = true;

// DETECTION THRESHOLDS
pub const HEUR_ENTROPY_THRESHOLD: f64 = 7.2;

pub const ML_CERTAINTY_MAL: f64 = 0.90;

// SCORING WEIGHTS
pub const HEUR_KNOWN_PACKER_SCORE: i32 = 30; // Always added with HEUR_ENTROPY_SCORE
pub const HEUR_ENTROPY_SCORE: i32 = 25;
pub const HEUR_RWX_SEC_SCORE: i32 = 40;
pub const HEUR_HIDDEN_IMP_SCORE: i32 = 20;

pub const CODE_SIGN_FORGIVENESS: i32 = -40;
pub const CODE_SIGN_UNTRUSTED: i32 = 5;
pub const CODE_SIGN_REVOKED: i32 = 100;

pub const ML_MALICIOUS: i32 = 40;

// Log Targets
pub const LOG_FILE: &str = "galatea.log";

// ETW
pub const ETW_HOOK_PROVIDER_UUID: &str = "722c7445-b4c2-538b-b843-e87b14e249d1";
pub const ETW_HOOK_PROVIDER_NAME: &str = "mimicry.galatea_hooks";