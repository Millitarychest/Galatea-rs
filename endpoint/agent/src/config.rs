// Temporary file to hold config globals
// should eventually be moved to external file with easier mod


// NAMES
pub const DRIVER_SERVICE_NAME: &str = "Galatea";
pub const DRIVER_FILE_NAME: &str = "driver.sys";
pub const DB_FILE_NAME: &str = "galatea_dataset.db";

// DETECTION THRESHOLDS
pub const STAT_BLOCK_THRESHOLD: i32 = 80;
pub const STAT_SUSPICIOUS_THRESHOLD: i32 = 50;

pub const HEUR_ENTROPY_THRESHOLD: f64 = 7.2;


// SCORING WEIGHTS
pub const HEUR_KNOWN_PACKER_SCORE: i32 = 40; // Always added with HEUR_ENTROPY_SCORE
pub const HEUR_ENTROPY_SCORE: i32 = 30;
pub const HEUR_RWX_SEC_SCORE: i32 = 40;
pub const HEUR_HIDDEN_IMP_SCORE: i32 = 20;