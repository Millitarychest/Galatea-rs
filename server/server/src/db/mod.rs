use std::path::Path;

use mimic_core::error;
use mimic_core::mimic_log;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub mod agent_db;
pub mod commands_db;

const SQL_INIT_STATMENTS: [&str; 2] = [
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

