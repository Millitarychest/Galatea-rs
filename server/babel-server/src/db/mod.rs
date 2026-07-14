use std::path::Path;

use mimic_core::error;
use mimic_core::mimic_log;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::state::AppConfig;

pub mod agent_db;
pub mod commands_db;
pub mod telemetry_db;

const SQL_INIT_STATMENTS: [&str; 5] = [
    "CREATE TABLE IF NOT EXISTS agents (
        agent_id    TEXT PRIMARY KEY,
        hostname    TEXT NOT NULL,
        os_version  TEXT,
        agent_version TEXT,
        ip_address  TEXT,
        last_heartbeat_at TEXT,
        registered_at TEXT NOT NULL,
        status      TEXT DEFAULT 'offline'
    )",
    "CREATE TABLE IF NOT EXISTS commands (
        command_id   TEXT PRIMARY KEY,
        agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
        command_type TEXT NOT NULL,
        payload_json TEXT,
        status       TEXT DEFAULT 'pending',
        created_at   TEXT NOT NULL,
        delivered_at TEXT,
        acked_at     TEXT
    )",
    "CREATE TABLE IF NOT EXISTS telemetry_events (
        event_id     TEXT PRIMARY KEY,
        agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
        event_type   TEXT NOT NULL,
        occurred_at  TEXT NOT NULL,
        ingested_at  TEXT NOT NULL,
        payload_json TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_telemetry_agent_time
        ON telemetry_events (agent_id, occurred_at)",
    "CREATE TABLE IF NOT EXISTS server_config (
        id                      INTEGER PRIMARY KEY CHECK (id = 1),
        registration_secret     TEXT NOT NULL
    )",
];

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_db_pool(db_path: &str) -> error::Result<DbPool> {
    mimic_log!("Initializing Database at: {}", db_path);

    let manager = SqliteConnectionManager::file(Path::new(db_path));
    let pool = Pool::builder().max_size(16).build(manager)?;

    let conn = pool
        .get()
        .map_err(|e| format!("Failed to get DB conn: {}", e))?;

    for statement in SQL_INIT_STATMENTS {
        conn.execute(statement, [])
            .map_err(|e| format!("Schema init failed: {}", e))?;
    }

    Ok(pool)
}

pub fn fetch_persisted_config(pool: &DbPool) -> Option<AppConfig> {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(_) => return None,
    };

    let mut stmt =
        match conn.prepare("SELECT registration_secret FROM server_config WHERE id = 1 LIMIT 1") {
            Ok(s) => s,
            Err(_) => return None,
        };

    let config: Option<AppConfig> = match stmt.query_one([], |row| {
        Ok(AppConfig {
            agent_registration_secret: row.get(0)?,
        })
    }) {
        Ok(r) => Some(r),
        Err(_) => None,
    };

    config
}

pub fn persist_config(pool: &DbPool, config: &AppConfig) -> error::Result<()> {
    let conn = pool
        .get()
        .map_err(|e| format!("Failed to get DB conn: {}", e))?;

    conn.execute(
        "INSERT INTO server_config (id, registration_secret) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET registration_secret = excluded.registration_secret",
        [&config.agent_registration_secret],
    )
    .map_err(|e| format!("Failed to persist config: {}", e))?;

    Ok(())
}
