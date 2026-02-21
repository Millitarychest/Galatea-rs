use std::time::Duration;

// Web Server
pub const SERVER_PORT: u16 = 80;
pub const SERVER_INTERFACE: [u8; 4] = [0, 0, 0, 0];

// Agent Authentication
pub const AGENT_PSK: &str = "galatea_secret";

// Heartbeat Settings
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
pub const AGENT_OFFLINE_TIMEOUT: Duration = Duration::from_secs(30 * 3);
